//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

const (
	tlsEpollFixSuiteID     = 0x1301
	tlsEpollFixAlertLen    = 2
	tlsEpollFixTinyRecords = 5000
)

type tlsEpollFixPeer struct {
	conn         *epollConn
	srv          *Server
	suite        *CipherSuiteConfig
	clientSecret []byte
	serverSecret []byte
	clientWriter *TrafficAEAD
	clientReader *TrafficAEAD
}

func tlsEpollFixAEAD(t testing.TB, cs *CipherSuiteConfig, secret []byte) *TrafficAEAD {
	t.Helper()
	a, err := NewTrafficAEAD(cs.HashFn, secret, cs)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func tlsEpollFixNextSecret(cs *CipherSuiteConfig, secret []byte) []byte {
	return TLSExpandLabel(cs.HashFn, secret, "traffic upd", nil, cs.HashLen)
}

func newTLSEpollFixPeer(t testing.TB) *tlsEpollFixPeer {
	t.Helper()
	cs := FindSuiteByID(tlsEpollFixSuiteID)
	p := &tlsEpollFixPeer{
		srv:          New(Config{}),
		suite:        cs,
		clientSecret: bytes.Repeat([]byte{0x11}, cs.HashLen),
		serverSecret: bytes.Repeat([]byte{0x22}, cs.HashLen),
	}
	p.conn = &epollConn{
		tls:        true,
		tlsVersion: TLSVersion13,
		phase:      tlsConnPhaseApplication,
		appReader:  tlsEpollFixAEAD(t, cs, p.clientSecret),
		appWriter:  tlsEpollFixAEAD(t, cs, p.serverSecret),
		appBuf:     make([]byte, 0, 4096),
	}
	p.clientWriter = tlsEpollFixAEAD(t, cs, p.clientSecret)
	p.clientReader = tlsEpollFixAEAD(t, cs, p.serverSecret)
	return p
}

func (p *tlsEpollFixPeer) advanceClientWriter(t testing.TB) {
	t.Helper()
	p.clientSecret = tlsEpollFixNextSecret(p.suite, p.clientSecret)
	p.clientWriter = tlsEpollFixAEAD(t, p.suite, p.clientSecret)
}

func (p *tlsEpollFixPeer) advanceClientReader(t testing.TB) {
	t.Helper()
	p.serverSecret = tlsEpollFixNextSecret(p.suite, p.serverSecret)
	p.clientReader = tlsEpollFixAEAD(t, p.suite, p.serverSecret)
}

func (p *tlsEpollFixPeer) record(content []byte, innerType byte) []byte {
	inner := append(append([]byte(nil), content...), innerType)
	return appendTLSInnerRecord(nil, p.clientWriter, inner)
}

func (p *tlsEpollFixPeer) feed(wire []byte) {
	c := p.conn
	c.readBuf = append(c.readBuf[:c.readN], wire...)
	c.readN = len(c.readBuf)
}

func (p *tlsEpollFixPeer) decrypt() (int, bool) {
	return p.conn.epollTLSDecryptToApp(p.srv)
}

type tlsEpollFixServerRecord struct {
	innerType byte
	content   []byte
}

func (p *tlsEpollFixPeer) serverRecords(t testing.TB) []tlsEpollFixServerRecord {
	t.Helper()
	var out []tlsEpollFixServerRecord
	wire := append([]byte(nil), p.conn.writeBuf...)
	p.conn.writeBuf = p.conn.writeBuf[:0]
	for len(wire) > 0 {
		_, payload, totalLen, ok, err := nextTLSRecord(wire)
		if err != nil || !ok {
			t.Fatalf("server output is not a sequence of whole records (ok=%v err=%v)", ok, err)
		}
		pt, err := p.clientReader.Decrypt(payload)
		if err != nil {
			t.Fatalf("client cannot decrypt server record %d: %v", len(out), err)
		}
		content, innerType, err := StripInnerPlaintext(pt)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, tlsEpollFixServerRecord{innerType: innerType, content: append([]byte(nil), content...)})
		if innerType == tlsRecHandshake && len(content) > 0 && content[0] == 24 {
			p.advanceClientReader(t)
		}
		wire = wire[totalLen:]
	}
	return out
}

func (p *tlsEpollFixPeer) expectFatalAlert(t *testing.T, action int, want tlsAlert) {
	t.Helper()
	if action != epollActionCloseAfterFlush {
		t.Fatalf("action %d, want close after flush", action)
	}
	recs := p.serverRecords(t)
	if len(recs) != 1 || recs[0].innerType != tlsRecAlert || len(recs[0].content) != tlsEpollFixAlertLen || tlsAlert(recs[0].content[1]) != want {
		t.Fatalf("server sent %+v, want one fatal alert %d", recs, want)
	}
}

func tlsEpollFixTLS12Pair(t testing.TB) (client, server *tls12AEAD) {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x33}, 16))
	if err != nil {
		t.Fatal(err)
	}
	newGCM := func() cipher.AEAD {
		g, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	iv := []byte{1, 2, 3, 4}
	return &tls12AEAD{aead: newGCM(), iv: iv}, &tls12AEAD{aead: newGCM(), iv: iv}
}
