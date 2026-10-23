//go:build linux && amd64

package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicFixBigCertSANs     = 160
	quicFixClientStep      = 400 * time.Millisecond
	quicFixRecoverySteps   = 3
	quicFixUnvalidatedStep = 6
	quicFixStormSteps      = 60
	quicFixTicksPerStep    = 8
	quicFixStormStep       = 50 * time.Millisecond
)

func quicFixBigCertConfig(t *testing.T) Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"a.test"}
	for i := 0; i < quicFixBigCertSANs; i++ {
		names = append(names, fmt.Sprintf("san-%03d.padding-for-a-large-certificate.example.test", i))
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "a.test"},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "big.crt"), filepath.Join(dir, "big.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{Certs: []CertConfig{{Domain: "a.test", Source: CertManual, CertFile: certFile, KeyFile: keyFile}}}
}

type quicFixBigFlight struct {
	*quicFixFlightConn
	total    uint64
	covered  map[uint64]bool
	received map[uint64]bool
	seen     int
	clientPN uint64
	in       int
}

func newQUICFixBigFlight(t *testing.T, validated bool) *quicFixBigFlight {
	t.Helper()
	srv := New(quicFixBigCertConfig(t))
	srv.ensureTLSRuntime()
	if err := srv.loadCerts(); err != nil {
		t.Fatal(err)
	}
	pc := &capturePacketConn{}
	dcid := []byte{0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8}
	qc := newQUICConn(srv, pc, &quicFixLoopback, dcid, quicFixClientSCID)
	clientKeys, serverKeys, err := quicDeriveInitialKeys(dcid)
	if err != nil {
		t.Fatal(err)
	}
	qc.keys[quicSpaceInitial] = clientKeys
	qc.sendKeys[quicSpaceInitial] = serverKeys
	qc.tlsState = newQuicTLSState()
	qc.addressValidated.Store(validated)
	qc.bytesReceived.Store(quicMinInitialDatagram)
	t.Cleanup(qc.close)
	hello := quicFixQUICClientHello(t, quicFixTPParam(quicTPInitialSrcCID, quicFixClientSCID))
	qc.processFrames(quicSpaceInitial, 0, quicAppendCryptoFrame(nil, 0, hello))
	if qc.tlsState.stage != quicTLSStageWaitFinished {
		t.Fatalf("ClientHello did not produce the first flight (closed %v)", qc.closed.Load())
	}
	f := &quicFixBigFlight{
		quicFixFlightConn: &quicFixFlightConn{qc: qc, pc: pc, hello: hello, initialSendKeys: qc.sendKeys[quicSpaceInitial], handshakeSendKeys: qc.sendKeys[quicSpaceHandshake]},
		covered:           map[uint64]bool{},
		received:          map[uint64]bool{},
		in:                quicMinInitialDatagram,
	}
	return f
}

func (f *quicFixBigFlight) handshakeCrypto(t *testing.T, raw []byte, each func(quicCryptoFrame)) {
	f.handshakePackets(t, raw, func(uint64) {}, each)
}

func (f *quicFixBigFlight) handshakePackets(t *testing.T, raw []byte, onPacket func(uint64), each func(quicCryptoFrame)) {
	t.Helper()
	pkt := append([]byte(nil), raw...)
	for len(pkt) > 0 && quicIsLongHeader(pkt) {
		hdr, total, err := quicParseLongHeader(pkt)
		if err != nil {
			t.Fatalf("server sent an unparseable long header: %v", err)
		}
		if hdr.pktType == quicPktHandshake {
			plain, err := quicDecryptPacket(pkt[:total], &hdr, f.handshakeSendKeys, -1)
			if err != nil {
				t.Fatalf("server sent an undecryptable Handshake packet: %v", err)
			}
			onPacket(hdr.pn)
			if err := quicParseFrames(plain, &quicFrameVisitor{onCrypto: each}); err != nil {
				t.Fatalf("server sent malformed Handshake frames: %v", err)
			}
		}
		pkt = pkt[total:]
	}
}

func (f *quicFixBigFlight) deliverFirstDatagramOnly(t *testing.T) int {
	t.Helper()
	raws := f.pc.snapshot()
	for i, raw := range raws {
		f.handshakePackets(t, raw, func(pn uint64) {
			if i == 0 {
				f.received[pn] = true
			}
		}, func(c quicCryptoFrame) {
			f.total = max(f.total, c.offset+uint64(len(c.data)))
			if i == 0 {
				f.cover(c)
			}
		})
	}
	f.seen = len(raws)
	return len(raws)
}

func (f *quicFixBigFlight) cover(c quicCryptoFrame) {
	for off := c.offset; off < c.offset+uint64(len(c.data)); off++ {
		f.covered[off] = true
	}
}

func (f *quicFixBigFlight) complete() bool {
	return uint64(len(f.covered)) == f.total
}

func (f *quicFixBigFlight) deliverNew(t *testing.T) (datagrams, cryptoDatagrams int) {
	t.Helper()
	raws := f.pc.snapshot()
	for _, raw := range raws[f.seen:] {
		hadCrypto := false
		f.handshakePackets(t, raw, func(pn uint64) { f.received[pn] = true }, func(c quicCryptoFrame) {
			hadCrypto = true
			f.cover(c)
		})
		if hadCrypto {
			cryptoDatagrams++
		}
	}
	datagrams = len(raws) - f.seen
	f.seen = len(raws)
	return datagrams, cryptoDatagrams
}

func (f *quicFixBigFlight) clientAcksFirstPacket(t *testing.T) {
	t.Helper()
	f.clientSends(t, quicAppendACKFrame(nil, 0, 0, 0))
}

func (f *quicFixBigFlight) clientAcksEverythingReceived(t *testing.T) {
	t.Helper()
	var ranges []pnRange
	for pn := uint64(1 << 16); pn > 0; pn-- {
		if !f.received[pn-1] {
			continue
		}
		if n := len(ranges); n > 0 && ranges[n-1].lo == pn {
			ranges[n-1].lo = pn - 1
			continue
		}
		ranges = append(ranges, pnRange{lo: pn - 1, hi: pn - 1})
	}
	f.clientSends(t, quicAppendACKFrameRanges(nil, 0, ranges))
}

func (f *quicFixBigFlight) clientSends(t *testing.T, ack []byte) {
	t.Helper()
	frames := append(append([]byte(nil), ack...), quicFramePing)
	frames = append(frames, make([]byte, quicMinInitialDatagram)...)
	pkt := quicBuildHandshakePacket(nil, f.qc.srcCID(), quicFixClientSCID, frames, f.clientPN, -1, f.qc.keys[quicSpaceHandshake])
	f.clientPN++
	f.in += len(pkt)
	f.feedDatagram(pkt)
}

func (f *quicFixBigFlight) elapse(d time.Duration) {
	for range quicFixTicksPerStep {
		f.qc.loss.mu.Lock()
		for _, space := range []int{quicSpaceInitial, quicSpaceHandshake} {
			for i := range f.qc.loss.sent[space] {
				f.qc.loss.sent[space][i].sent -= int64(d / quicFixTicksPerStep)
			}
		}
		f.qc.loss.mu.Unlock()
		f.qc.tick(turbo.UnixNano(), false)
	}
}

func (f *quicFixBigFlight) sentBytes() int {
	total := 0
	for _, raw := range f.pc.snapshot() {
		total += len(raw)
	}
	return total
}

func TestQUICFixHandshakeTailLossIsRecoveredByPTO(t *testing.T) {
	f := newQUICFixBigFlight(t, true)
	if flight := f.deliverFirstDatagramOnly(t); flight < 3 || f.complete() {
		t.Fatalf("fixture flight is %d datagrams (complete %v); the test needs a lost multi-datagram tail", flight, f.complete())
	}
	for step := 1; step <= quicFixRecoverySteps; step++ {
		f.clientAcksFirstPacket(t)
		f.elapse(quicFixClientStep)
		f.deliverNew(t)
		if f.complete() {
			return
		}
	}
	t.Fatalf("the lost Handshake tail was not resent within %d client PTOs (%d of %d bytes delivered)", quicFixRecoverySteps, len(f.covered), f.total)
}

func TestQUICFixHandshakePTOBacksOffWhileOnlyOldPacketsAreAcked(t *testing.T) {
	f := newQUICFixBigFlight(t, true)
	f.deliverFirstDatagramOnly(t)
	probes := 0
	for step := 1; step <= quicFixStormSteps; step++ {
		f.clientAcksFirstPacket(t)
		f.elapse(quicFixStormStep)
		_, crypto := f.deliverNew(t)
		probes += crypto
	}
	if probes == 0 {
		t.Fatal("the server never probed the Handshake space")
	}
	elapsed := quicFixStormSteps * quicFixStormStep
	rounds := 1
	for window := 2 * quicTimerGranularity; window <= elapsed; window *= 2 {
		rounds++
	}
	if bound := quicPTOProbePackets * rounds; probes > bound {
		t.Fatalf("%d probe datagrams in %v of repeated old ACKs, want at most %d (%d PTO rounds of %d packets)", probes, elapsed, bound, rounds, quicPTOProbePackets)
	}
}

func TestQUICFixHandshakePTOStaysWithinTheAmplificationLimit(t *testing.T) {
	f := newQUICFixBigFlight(t, false)
	f.deliverFirstDatagramOnly(t)
	for step := 1; step <= quicFixUnvalidatedStep; step++ {
		f.clientAcksFirstPacket(t)
		f.elapse(quicFixClientStep)
		f.deliverNew(t)
		if out := f.sentBytes(); out > quicAmplificationFactor*f.in {
			t.Fatalf("step %d: server sent %d bytes to an unvalidated address that sent %d", step, out, f.in)
		}
	}
	if !f.complete() {
		t.Fatalf("the lost Handshake tail was not resent within %d client PTOs on an unvalidated path (%d of %d bytes)", quicFixUnvalidatedStep, len(f.covered), f.total)
	}
}

func TestQUICFixLostHelloRetryRequestIsResentOnPTO(t *testing.T) {
	h := newQUICFixHandshakeConn(t)
	hello := quicFixQUICClientHello(t, quicFixTPParam(quicTPInitialSrcCID, quicFixClientSCID))
	var ch ParsedClientHello
	if err := ParseClientHello(hello, &ch); err != nil {
		t.Fatal(err)
	}
	h.qc.tlsState.sendHelloRetry(h.qc, negotiateQUICSuite(ch.CipherSuites), groupP256, &ch, hello)
	initialCrypto := func(from int) []byte {
		var data []byte
		for _, raw := range h.pc.snapshot()[from:] {
			pkt := append([]byte(nil), raw...)
			for len(pkt) > 0 && quicIsLongHeader(pkt) {
				hdr, total, err := quicParseLongHeader(pkt)
				if err != nil {
					t.Fatal(err)
				}
				if hdr.pktType == quicPktInitial {
					plain, err := quicDecryptPacket(pkt[:total], &hdr, h.keys, -1)
					if err != nil {
						t.Fatal(err)
					}
					_ = quicParseFrames(plain, &quicFrameVisitor{onCrypto: func(c quicCryptoFrame) { data = append(data, c.data...) }})
				}
				pkt = pkt[total:]
			}
		}
		return data
	}
	sent := len(h.pc.snapshot())
	hrr := initialCrypto(0)
	if sent == 0 || len(hrr) == 0 {
		t.Fatal("fixture did not send a HelloRetryRequest")
	}
	h.qc.loss.mu.Lock()
	pto := h.qc.loss.smoothedRTT + max(4*h.qc.loss.rttVar, quicTimerGranularity)
	for i := range h.qc.loss.sent[quicSpaceInitial] {
		h.qc.loss.sent[quicSpaceInitial][i].sent -= int64(pto + quicTimerGranularity)
	}
	h.qc.loss.mu.Unlock()
	h.qc.tick(turbo.UnixNano(), false)
	if again := initialCrypto(sent); string(again) != string(hrr) {
		t.Fatalf("after one PTO the server resent %d CRYPTO bytes, want the %d-byte HelloRetryRequest", len(again), len(hrr))
	}
}
