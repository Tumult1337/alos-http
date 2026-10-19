//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
)

const (
	tlsEpollFixHelloFragment  = 100
	tlsEpollFixEmptyALPNNames = 16000
	tlsEpollFixHugeClientCert = 70 << 10
	tlsEpollFixExtEMS         = 0x0017
	tlsEpollFixExtALPN        = 0x0010
	tlsEpollFixFloodExtBase   = 0x7000
)

type tlsEpollFixHello struct {
	head        []byte
	compression []byte
	exts        []byte
}

func tlsEpollFixSplitHello(t testing.TB, msg []byte) tlsEpollFixHello {
	t.Helper()
	body := msg[tlsHandshakeHeaderLen:]
	pos := 2 + 32
	pos += 1 + int(body[pos])
	pos += 2 + int(binary.BigEndian.Uint16(body[pos:]))
	compEnd := pos + 1 + int(body[pos])
	extLen := int(binary.BigEndian.Uint16(body[compEnd:]))
	if compEnd+2+extLen != len(body) {
		t.Fatalf("captured ClientHello did not parse: %d+2+%d != %d", compEnd, extLen, len(body))
	}
	return tlsEpollFixHello{
		head:        append([]byte(nil), body[:pos]...),
		compression: append([]byte(nil), body[pos+1:compEnd]...),
		exts:        append([]byte(nil), body[compEnd+2:]...),
	}
}

func (h tlsEpollFixHello) build() []byte {
	body := append([]byte(nil), h.head...)
	body = append(body, byte(len(h.compression)))
	body = append(body, h.compression...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(h.exts)))
	body = append(body, h.exts...)
	return HSWrap(tlsHSClientHello, body)
}

func tlsEpollFixExtension(extType uint16, data []byte) []byte {
	ext := binary.BigEndian.AppendUint16(nil, extType)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(data)))
	return append(ext, data...)
}

func tlsEpollFixCapturedHello(t testing.TB, version uint16) tlsEpollFixHello {
	t.Helper()
	record := captureClientHello(t, &tls.Config{ServerName: harnessDomain, MinVersion: version, MaxVersion: version, NextProtos: []string{"http/1.1"}})
	return tlsEpollFixSplitHello(t, record)
}

func tlsEpollFixParse(msg []byte) (*ParsedClientHello, error) {
	ch := &ParsedClientHello{}
	return ch, ParseClientHello(msg, ch)
}

func TestTLSEpollFixClientHelloStrictExtensions(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		hello := tlsEpollFixCapturedHello(t, version)
		if _, err := tlsEpollFixParse(hello.build()); err != nil {
			t.Fatalf("%s: unmodified ClientHello rejected: %v", tls.VersionName(version), err)
		}
		dup := hello
		dup.exts = append(append(append([]byte(nil), hello.exts...), tlsEpollFixExtension(tlsEpollFixExtEMS, nil)...), tlsEpollFixExtension(tlsEpollFixExtEMS, nil)...)
		if _, err := tlsEpollFixParse(dup.build()); err != ErrDuplicateExtension || clientHelloParseAlert(err) != alertIllegalParameter {
			t.Errorf("%s: duplicate extension: err=%v", tls.VersionName(version), err)
		}
		truncated := hello
		truncated.exts = append(append([]byte(nil), hello.exts...), 0x00, 0x17, 0x00)
		if _, err := tlsEpollFixParse(truncated.build()); err != ErrExtsTruncated {
			t.Errorf("%s: truncated extension header: err=%v", tls.VersionName(version), err)
		}
		overrun := hello
		overrun.exts = append(append([]byte(nil), hello.exts...), 0x00, 0x17, 0x00, 0x09, 0x01)
		if _, err := tlsEpollFixParse(overrun.build()); err != ErrExtsTruncated {
			t.Errorf("%s: extension body overrun: err=%v", tls.VersionName(version), err)
		}
		noNull := hello
		noNull.compression = []byte{1}
		if _, err := tlsEpollFixParse(noNull.build()); err != ErrBadCompression {
			t.Errorf("%s: compression without null: err=%v", tls.VersionName(version), err)
		}
		extra := hello
		extra.compression = []byte{1, 0}
		_, err := tlsEpollFixParse(extra.build())
		if version == tls.VersionTLS13 && err != ErrBadCompression {
			t.Errorf("TLS 1.3 ClientHello with two compression methods: err=%v", err)
		}
		if version == tls.VersionTLS12 && err != nil {
			t.Errorf("TLS 1.2 ClientHello offering null among others rejected: %v", err)
		}
		flood := hello
		flood.exts = append([]byte(nil), hello.exts...)
		for extType := uint16(tlsEpollFixFloodExtBase); extType < tlsEpollFixFloodExtBase+maxClientHelloExtensions; extType++ {
			flood.exts = append(flood.exts, tlsEpollFixExtension(extType, nil)...)
		}
		if _, err := tlsEpollFixParse(flood.build()); err != ErrTooManyExtensions {
			t.Errorf("%s: %d extensions: err=%v", tls.VersionName(version), maxClientHelloExtensions, err)
		}
	}
}

func TestTLSEpollFixALPNValidatedAndBounded(t *testing.T) {
	hello := tlsEpollFixCapturedHello(t, tls.VersionTLS13)
	withALPN := func(list []byte) []byte {
		h := hello
		h.exts = nil
		for rest := hello.exts; len(rest) >= 4; {
			n := 4 + int(binary.BigEndian.Uint16(rest[2:]))
			if binary.BigEndian.Uint16(rest) != tlsEpollFixExtALPN {
				h.exts = append(h.exts, rest[:n]...)
			}
			rest = rest[n:]
		}
		data := binary.BigEndian.AppendUint16(nil, uint16(len(list)))
		h.exts = append(h.exts, tlsEpollFixExtension(tlsEpollFixExtALPN, append(data, list...))...)
		return h.build()
	}
	bad := map[string][]byte{
		"empty names":      make([]byte, tlsEpollFixEmptyALPNNames),
		"empty list":       nil,
		"overrunning name": {5, 'h', '2'},
	}
	for name, list := range bad {
		if _, err := tlsEpollFixParse(withALPN(list)); err != ErrBadALPN {
			t.Errorf("%s: err=%v, want ErrBadALPN", name, err)
		}
	}
	var many []byte
	for i := 0; i < 3*maxALPNProtocols; i++ {
		many = append(many, 1, byte('a'+i%26))
	}
	ch, err := tlsEpollFixParse(withALPN(append(many, 2, 'h', '2')))
	if err != nil || len(ch.ALPNProtos) != maxALPNProtocols {
		t.Fatalf("long ALPN list: err=%v kept %d names, want %d", err, len(ch.ALPNProtos), maxALPNProtocols)
	}
	ch, err = tlsEpollFixParse(withALPN([]byte{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}))
	if err != nil || len(ch.ALPNProtos) != 2 || ch.ALPNProtos[0] != "h2" || ch.ALPNProtos[1] != "http/1.1" {
		t.Fatalf("normal ALPN list: err=%v %q", err, ch.ALPNProtos)
	}
}

type tlsEpollFixFragmentingConn struct {
	net.Conn
	once sync.Once
}

func (c *tlsEpollFixFragmentingConn) Write(b []byte) (int, error) {
	fragmented := false
	c.once.Do(func() { fragmented = true })
	if !fragmented || len(b) < tlsRecordHeaderLen || b[0] != tlsRecHandshake {
		return c.Conn.Write(b)
	}
	payload := b[tlsRecordHeaderLen:]
	var wire []byte
	for len(payload) > 0 {
		n := min(len(payload), tlsEpollFixHelloFragment)
		wire = AppendRecord(wire, tlsRecHandshake, payload[:n])
		payload = payload[n:]
	}
	if _, err := c.Conn.Write(wire); err != nil {
		return 0, err
	}
	return len(b), nil
}

func TestTLSEpollFixFragmentedClientHelloAccepted(t *testing.T) {
	ts := newTestServer(t, testServerOptions{TLS: true, Routes: func(r *Router) {
		r.GET("/hello", func(req *Request, resp *Response) { resp.Status(200).String("fragmented ok") })
	}})
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		raw, err := net.DialTimeout("tcp4", ts.addr, harnessIOTimeout)
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.SetDeadline(wallDeadline(harnessIOTimeout))
		cfg := ts.tlsConfig("http/1.1")
		cfg.MinVersion, cfg.MaxVersion = version, version
		tc := tls.Client(&tlsEpollFixFragmentingConn{Conn: raw}, cfg)
		if err := tc.Handshake(); err != nil {
			t.Fatalf("%s: handshake with a ClientHello split into %d-byte records: %v", tls.VersionName(version), tlsEpollFixHelloFragment, err)
		}
		if _, err := io.WriteString(tc, "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(tc)
		_ = tc.Close()
		if !bytes.HasSuffix(got, []byte("fragmented ok")) {
			t.Fatalf("%s: response %q", tls.VersionName(version), got)
		}
	}
}

func TestTLSEpollFixDuplicateExtensionAlertOnWire(t *testing.T) {
	ts := newTestServer(t, testServerOptions{TLS: true})
	hello := tlsEpollFixCapturedHello(t, tls.VersionTLS13)
	hello.exts = append(hello.exts, tlsEpollFixExtension(0, []byte{0, 7, 0, 0, 4, 'b', '.', 't', 's'})...)
	if got := exchangeRaw(t, ts.addr, handshakeRecord(hello.build())); !bytes.Equal(got, plainAlertRecord(alertIllegalParameter)) {
		t.Fatalf("second server_name extension answered %x, want illegal_parameter", got)
	}
}

func TestTLSEpollFixOversizedSessionTicketNotMisframed(t *testing.T) {
	tc, _ := newTestTicketCodec()
	srv := &Server{tickets: tc}
	cs := FindSuiteByID(tlsEpollFixSuiteID)
	chain := [][]byte{bytes.Repeat([]byte{0xc3}, tlsEpollFixHugeClientCert)}
	if msg := srv.newSessionTicketMessage(newPendingTicket(cs, bytes.Repeat([]byte{9}, cs.HashLen), bytes.Repeat([]byte{8}, cs.HashLen), "big.test", "h2", chain)); msg != nil {
		t.Fatalf("TLS 1.3 NewSessionTicket with a %d-byte ticket emitted (%d bytes); the 16-bit length cannot frame it", tlsEpollFixHugeClientCert, len(msg))
	}
	st := &tls12State{suite: &tls12Suites[0], master: bytes.Repeat([]byte{7}, 48), sni: "big.test", peerChain: chain}
	msg := srv.tls12NewSessionTicket(st, "h2")
	body := msg[tlsHandshakeHeaderLen:]
	if int(msg[1])<<16|int(msg[2])<<8|int(msg[3]) != len(body) || len(body) != 6 || binary.BigEndian.Uint16(body[4:]) != 0 {
		t.Fatalf("TLS 1.2 NewSessionTicket for an oversized ticket: %d-byte body %x, want an empty ticket", len(body), body[:min(len(body), 8)])
	}
}
