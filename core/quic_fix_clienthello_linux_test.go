//go:build linux && amd64

package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

const (
	quicFixCryptoErrorBase     = 0x0100
	quicFixMissingExtension    = 109
	quicFixTransportParamError = 0x08
	quicFixSessionIDOffset     = 4 + 2 + 32
	quicFixSessionIDLen        = 32
	quicFixAmplification       = 3
	quicFixLargeCertificate    = 6000
)

var quicFixClientSCID = []byte{0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8}

type quicFixHandshakeConn struct {
	qc   *QUICConn
	pc   *capturePacketConn
	keys *quicKeys
}

func newQUICFixHandshakeConn(t *testing.T) *quicFixHandshakeConn {
	t.Helper()
	srv := New(Config{})
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
	qc.addressValidated.Store(true)
	t.Cleanup(qc.close)
	return &quicFixHandshakeConn{qc: qc, pc: pc, keys: serverKeys}
}

func (h *quicFixHandshakeConn) closeCodes(t *testing.T) []uint64 {
	t.Helper()
	var codes []uint64
	for _, raw := range h.pc.snapshot() {
		pkt := append([]byte(nil), raw...)
		for len(pkt) > 0 && quicIsLongHeader(pkt) {
			hdr, total, err := quicParseLongHeader(pkt)
			if err != nil {
				break
			}
			if hdr.pktType == quicPktInitial {
				plain, derr := quicDecryptPacket(pkt[:total], &hdr, h.keys, -1)
				if derr == nil {
					_ = quicParseFrames(plain, &quicFrameVisitor{onConnClose: func(f quicConnCloseFrame) { codes = append(codes, f.errorCode) }})
				}
			}
			pkt = pkt[total:]
		}
	}
	return codes
}

func quicFixTP(params ...[]byte) []byte {
	var tp []byte
	for _, p := range params {
		tp = append(tp, p...)
	}
	return tp
}

func quicFixTPParam(id uint64, value []byte) []byte {
	out := quicAppendVarint(nil, id)
	out = quicAppendVarint(out, uint64(len(value)))
	return append(out, value...)
}

func quicFixTPInt(id, v uint64) []byte {
	return quicFixTPParam(id, quicAppendVarint(nil, v))
}

func quicFixQUICClientHello(t *testing.T, transportParams []byte) []byte {
	t.Helper()
	conn := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{ServerName: "a.test", NextProtos: []string{"h3"}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}})
	conn.SetTransportParameters(transportParams)
	if err := conn.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var hello []byte
	for {
		ev := conn.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			break
		}
		if ev.Kind == tls.QUICWriteData && ev.Level == tls.QUICEncryptionLevelInitial {
			hello = append(hello, ev.Data...)
		}
	}
	return hello
}

func quicFixWithSessionID(hello []byte) []byte {
	out := append([]byte(nil), hello[:quicFixSessionIDOffset]...)
	out = append(out, quicFixSessionIDLen)
	out = append(out, make([]byte, quicFixSessionIDLen)...)
	out = append(out, hello[quicFixSessionIDOffset+1:]...)
	n := int(out[1])<<16 | int(out[2])<<8 | int(out[3]) + quicFixSessionIDLen
	out[1], out[2], out[3] = byte(n>>16), byte(n>>8), byte(n)
	return out
}

func quicFixHasCode(codes []uint64, want uint64) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

func TestQUICFixClientHelloTransportParameterRules(t *testing.T) {
	validSCID := quicFixTPParam(quicTPInitialSrcCID, quicFixClientSCID)
	cases := []struct {
		name string
		tp   []byte
		want uint64
	}{
		{"missing initial_source_connection_id", quicFixTPInt(quicTPInitialMaxData, 1<<20), quicFixTransportParamError},
		{"initial_source_connection_id mismatch", quicFixTPParam(quicTPInitialSrcCID, []byte{1, 2, 3, 4}), quicFixTransportParamError},
		{"duplicate parameter", quicFixTP(validSCID, quicFixTPInt(quicTPInitialMaxData, 1), quicFixTPInt(quicTPInitialMaxData, 2)), quicFixTransportParamError},
		{"zero-length integer reads the next parameter", quicFixTP(validSCID, quicFixTPParam(quicTPInitialMaxData, nil), quicFixTPInt(quicTPInitialMaxStreamBidiL, 7)), quicFixTransportParamError},
		{"server-only original_destination_connection_id", quicFixTP(validSCID, quicFixTPParam(0x00, []byte{1})), quicFixTransportParamError},
		{"max_udp_payload_size below 1200", quicFixTP(validSCID, quicFixTPInt(0x03, 1000)), quicFixTransportParamError},
		{"ack_delay_exponent above 20", quicFixTP(validSCID, quicFixTPInt(0x0a, 21)), quicFixTransportParamError},
		{"active_connection_id_limit below 2", quicFixTP(validSCID, quicFixTPInt(quicTPActiveConnIDLimit, 1)), quicFixTransportParamError},
	}
	for _, tc := range cases {
		h := newQUICFixHandshakeConn(t)
		h.qc.tlsState.handleClientHello(h.qc, quicFixQUICClientHello(t, tc.tp))
		if codes := h.closeCodes(t); !quicFixHasCode(codes, tc.want) {
			t.Errorf("%s: CONNECTION_CLOSE codes %#x, want %#x", tc.name, codes, tc.want)
		}
	}
	h := newQUICFixHandshakeConn(t)
	h.qc.tlsState.handleClientHello(h.qc, quicFixQUICClientHello(t, validSCID))
	if codes := h.closeCodes(t); quicFixHasCode(codes, quicFixTransportParamError) || quicFixHasCode(codes, quicFixProtocolViolation) {
		t.Fatalf("valid transport parameters were rejected: %#x", codes)
	}
}

func TestQUICFixClientHelloSessionIDAndMissingExtension(t *testing.T) {
	hello := quicFixQUICClientHello(t, quicFixTPParam(quicTPInitialSrcCID, quicFixClientSCID))
	h := newQUICFixHandshakeConn(t)
	h.qc.tlsState.handleClientHello(h.qc, quicFixWithSessionID(hello))
	if codes := h.closeCodes(t); !quicFixHasCode(codes, quicFixProtocolViolation) {
		t.Errorf("non-empty legacy_session_id: CONNECTION_CLOSE codes %#x, want PROTOCOL_VIOLATION", codes)
	}
	tcpHello := captureClientHello(t, &tls.Config{ServerName: "a.test", NextProtos: []string{"h3"}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	h = newQUICFixHandshakeConn(t)
	h.qc.tlsState.handleClientHello(h.qc, tcpHello)
	if codes := h.closeCodes(t); !quicFixHasCode(codes, quicFixCryptoErrorBase+quicFixMissingExtension) {
		t.Errorf("ClientHello without quic_transport_parameters: CONNECTION_CLOSE codes %#x, want missing_extension", codes)
	}
}

func TestQUICFixFirstFlightRespectsAmplificationLimit(t *testing.T) {
	h := newQUICFixHandshakeConn(t)
	h.qc.addressValidated.Store(false)
	h.qc.bytesReceived.Store(quicMinInitialDatagram)
	h.qc.keys[quicSpaceHandshake] = h.qc.keys[quicSpaceInitial]
	h.qc.sendKeys[quicSpaceHandshake] = h.qc.sendKeys[quicSpaceInitial]
	h.qc.sendFirstFlight(make([]byte, 90), make([]byte, 40), make([]byte, quicFixLargeCertificate), make([]byte, 80), make([]byte, 36))
	sent := 0
	for _, raw := range h.pc.snapshot() {
		sent += len(raw)
	}
	if limit := quicFixAmplification * quicMinInitialDatagram; sent > limit {
		t.Fatalf("server sent %d bytes to an unvalidated address that sent %d (limit %d)", sent, quicMinInitialDatagram, limit)
	}
}

func newQUICFixKeyedConn(t *testing.T) (*quicFixHandshakeConn, *quicKeys, *quicKeys) {
	t.Helper()
	h := newQUICFixHandshakeConn(t)
	initialKeys := h.qc.keys[quicSpaceInitial]
	_, handshakeKeys, err := quicDeriveInitialKeys([]byte{0xee, 1, 2, 3, 4, 5, 6, 7})
	if err != nil {
		t.Fatal(err)
	}
	h.qc.keys[quicSpaceHandshake] = handshakeKeys
	h.qc.sendKeys[quicSpaceHandshake] = handshakeKeys
	return h, initialKeys, handshakeKeys
}

func (h *quicFixHandshakeConn) feed(packet []byte) {
	h.qc.processPacket(packet, quicFixLoopback.AddrPort())
}

func TestQUICFixInitialKeysDiscardedAfterFirstHandshakePacket(t *testing.T) {
	h, initialKeys, handshakeKeys := newQUICFixKeyedConn(t)
	ping := []byte{quicFixPingFrame}
	h.feed(quicBuildHandshakePacket(nil, h.qc.srcCID(), quicFixClientSCID, ping, 0, -1, handshakeKeys))
	if h.qc.keys[quicSpaceInitial] != nil || h.qc.sendKeys[quicSpaceInitial] != nil {
		t.Error("Initial keys survived the first successfully processed Handshake packet")
	}
	forgedClose := quicAppendConnCloseFrame(nil, quicFixProtocolViolation, 0, "")
	h.feed(quicBuildInitialPacket(nil, h.qc.srcCID(), quicFixClientSCID, nil, forgedClose, 1, -1, initialKeys))
	if h.qc.closed.Load() {
		t.Fatal("an Initial-space CONNECTION_CLOSE built from the public Initial keys tore down the connection")
	}
}

func TestQUICFixOneRTTPacketsIgnoredBeforeHandshakeCompletes(t *testing.T) {
	h := newQUICFixHandshakeConn(t)
	appKeys := h.qc.keys[quicSpaceInitial]
	h.qc.keys[quicSpaceAppData] = appKeys
	h.qc.sendKeys[quicSpaceAppData] = appKeys
	frames := quicStreamBytes(0, 0, make([]byte, 64), false)
	packet := quicBuildShortPacket(nil, h.qc.srcCID(), frames, 0, -1, appKeys, 0)
	h.feed(append([]byte(nil), packet...))
	h.qc.streamsMu.Lock()
	opened := len(h.qc.streams)
	h.qc.streamsMu.Unlock()
	if opened != 0 {
		t.Fatalf("a 1-RTT STREAM frame opened %d streams before the client Finished was verified", opened)
	}
	h.qc.handshakeDone.Store(true)
	h.feed(quicBuildShortPacket(nil, h.qc.srcCID(), frames, 1, -1, appKeys, 0))
	h.qc.streamsMu.Lock()
	opened = len(h.qc.streams)
	h.qc.streamsMu.Unlock()
	if opened != 1 {
		t.Fatalf("after the handshake a 1-RTT STREAM frame opened %d streams, want 1", opened)
	}
}

type quicFixLogSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *quicFixLogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *quicFixLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestQUICFixHandshakeDebugLogsCarryNoSecrets(t *testing.T) {
	sink := &quicFixLogSink{}
	prev := logger()
	srv := New(Config{Certs: []CertConfig{{Domain: "a.test", Source: CertSelfSigned}}, Debug: true, Logger: slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	t.Cleanup(func() {
		SetDebugFlag(false)
		useLogger(prev)
	})
	srv.ensureTLSRuntime()
	if err := srv.loadCerts(); err != nil {
		t.Fatal(err)
	}
	if srv.certStore.Lookup("a.test") == nil {
		t.Fatal("self-signed test certificate was not installed")
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
	qc.addressValidated.Store(true)
	t.Cleanup(qc.close)
	qc.tlsState.handleClientHello(qc, quicFixQUICClientHello(t, quicFixTPParam(quicTPInitialSrcCID, quicFixClientSCID)))
	if qc.keys[quicSpaceHandshake] == nil {
		t.Fatalf("handshake did not reach key derivation; log:\n%s", sink.String())
	}
	logs := sink.String()
	for _, leak := range []string{"handshakeSecret", "serverHSSecret", "IV=", "full hex"} {
		if strings.Contains(logs, leak) {
			t.Errorf("debug log contains %q (handshake key material or the full ServerHello)", leak)
		}
	}
}
