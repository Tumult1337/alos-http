//go:build linux && amd64

package core

import (
	"testing"
	"time"
)

const (
	quicFixEmptyCryptoPackets     = 200
	quicFixDuplicateHelloPackets  = 50
	quicFixClientHelloInitialPN   = 0
	quicFixClientRetryFirstPN     = 1
	quicFixBackdatePastPTOPadding = time.Second
)

type quicFixFlightConn struct {
	qc     *QUICConn
	pc     *capturePacketConn
	hello  []byte
	nextPN uint64
}

func newQUICFixFlightConn(t *testing.T) *quicFixFlightConn {
	t.Helper()
	srv := New(Config{Certs: []CertConfig{{Domain: "a.test", Source: CertSelfSigned}}})
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
	qc.addressValidated.Store(true)
	t.Cleanup(qc.close)
	hello := quicFixQUICClientHello(t, quicFixTPParam(quicTPInitialSrcCID, quicFixClientSCID))
	qc.processFrames(quicSpaceInitial, quicFixClientHelloInitialPN, quicAppendCryptoFrame(nil, 0, hello))
	if qc.tlsState.stage != quicTLSStageWaitFinished || !qc.firstFlight.sent {
		t.Fatalf("ClientHello did not produce the first flight (stage %d, closed %v)", qc.tlsState.stage, qc.closed.Load())
	}
	return &quicFixFlightConn{qc: qc, pc: pc, hello: hello, nextPN: quicFixClientRetryFirstPN}
}

func (f *quicFixFlightConn) feedInitial(frames []byte) {
	f.qc.processFrames(quicSpaceInitial, f.nextPN, frames)
	f.nextPN++
}

func (f *quicFixFlightConn) datagrams() int {
	return len(f.pc.snapshot())
}

func (f *quicFixFlightConn) tracked() (initial, handshake int) {
	f.qc.loss.mu.Lock()
	defer f.qc.loss.mu.Unlock()
	return len(f.qc.loss.sent[quicSpaceInitial]), len(f.qc.loss.sent[quicSpaceHandshake])
}

func (f *quicFixFlightConn) backdateFlightPastPTO() {
	f.qc.writeMu.Lock()
	pto := f.qc.loss.ptoTimeout()
	f.qc.writeMu.Unlock()
	f.qc.firstFlight.lastSent -= int64(pto + quicFixBackdatePastPTOPadding)
}

func TestQUICFixEmptyInitialCryptoFramesDoNotResendTheFlight(t *testing.T) {
	f := newQUICFixFlightConn(t)
	flight := f.datagrams()
	initial, handshake := f.tracked()
	f.backdateFlightPastPTO()
	for i := 0; i < quicFixEmptyCryptoPackets; i++ {
		f.feedInitial(quicAppendCryptoFrame(nil, 0, nil))
	}
	if extra := f.datagrams() - flight; extra != 0 {
		t.Fatalf("%d empty Initial CRYPTO frames drew %d datagrams after a %d-datagram flight", quicFixEmptyCryptoPackets, extra, flight)
	}
	if i, h := f.tracked(); i != initial || h != handshake {
		t.Fatalf("tracked sent packets grew from %d/%d to %d/%d", initial, handshake, i, h)
	}
}

func TestQUICFixDuplicateClientHelloWithinPTODoesNotResendTheFlight(t *testing.T) {
	f := newQUICFixFlightConn(t)
	flight := f.datagrams()
	for i := 0; i < quicFixDuplicateHelloPackets; i++ {
		f.feedInitial(quicAppendCryptoFrame(nil, 0, f.hello))
	}
	if extra := f.datagrams() - flight; extra != 0 {
		t.Fatalf("%d duplicate ClientHello packets inside one PTO drew %d datagrams", quicFixDuplicateHelloPackets, extra)
	}
}

func TestQUICFixDuplicateClientHelloAfterPTOResendsTheFlightOnce(t *testing.T) {
	f := newQUICFixFlightConn(t)
	flight := f.datagrams()
	initial, handshake := f.tracked()
	if initial == 0 || handshake == 0 {
		t.Fatalf("first flight tracked %d Initial and %d Handshake packets", initial, handshake)
	}
	f.backdateFlightPastPTO()
	for i := 0; i < quicFixDuplicateHelloPackets; i++ {
		f.feedInitial(quicAppendCryptoFrame(nil, 0, f.hello))
	}
	if resent := f.datagrams() - flight; resent != flight {
		t.Fatalf("%d duplicate ClientHello packets after one PTO drew %d datagrams, want one %d-datagram flight", quicFixDuplicateHelloPackets, resent, flight)
	}
	if i, h := f.tracked(); i > initial || h > handshake {
		t.Fatalf("tracked sent packets grew from %d/%d to %d/%d after one resend", initial, handshake, i, h)
	}
	f.backdateFlightPastPTO()
	f.feedInitial(quicAppendCryptoFrame(nil, 0, f.hello))
	if resent := f.datagrams() - flight; resent != 2*flight {
		t.Fatalf("a duplicate ClientHello one PTO after the resend drew %d datagrams in total, want %d", resent, 2*flight)
	}
	if i, h := f.tracked(); i > initial || h > handshake {
		t.Fatalf("tracked sent packets grew from %d/%d to %d/%d after two resends", initial, handshake, i, h)
	}
}

func TestQUICFixFlightResendBacksOffThePTO(t *testing.T) {
	f := newQUICFixFlightConn(t)
	f.qc.writeMu.Lock()
	before := f.qc.loss.ptoTimeout()
	f.qc.writeMu.Unlock()
	f.backdateFlightPastPTO()
	f.feedInitial(quicAppendCryptoFrame(nil, 0, f.hello))
	f.qc.writeMu.Lock()
	after := f.qc.loss.ptoTimeout()
	f.qc.writeMu.Unlock()
	if after != 2*before {
		t.Fatalf("PTO %v after a client-clocked flight resend, want %v", after, 2*before)
	}
}

func TestQUICFixDuplicateFirstHelloDuringRetryKeepsTheLaterFlight(t *testing.T) {
	srv := New(Config{Certs: []CertConfig{{Domain: "a.test", Source: CertSelfSigned}}})
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
	qc.addressValidated.Store(true)
	t.Cleanup(qc.close)
	hello := quicFixQUICClientHello(t, quicFixTPParam(quicTPInitialSrcCID, quicFixClientSCID))
	qc.tlsState.initialConsumed = len(hello)
	qc.cryptoBuf[quicSpaceInitial] = append([]byte(nil), hello...)
	qc.cryptoRcv[quicSpaceInitial] = make([]bool, len(hello))
	for i := range qc.cryptoRcv[quicSpaceInitial] {
		qc.cryptoRcv[quicSpaceInitial][i] = true
	}
	qc.cryptoContig[quicSpaceInitial] = len(hello)
	qc.writeMu.Lock()
	pto := qc.loss.ptoTimeout()
	qc.writeMu.Unlock()

	qc.processFrames(quicSpaceInitial, 0, quicAppendCryptoFrame(nil, 0, hello))
	if n := len(pc.snapshot()); n != 0 || qc.firstFlight.sent {
		t.Fatalf("a repeated first ClientHello while the server waits for the second drew %d datagrams (flight marked sent %v)", n, qc.firstFlight.sent)
	}
	qc.writeMu.Lock()
	after := qc.loss.ptoTimeout()
	qc.writeMu.Unlock()
	if after != pto {
		t.Fatalf("PTO %v after a repeated first ClientHello, want %v", after, pto)
	}

	qc.processFrames(quicSpaceInitial, 1, quicAppendCryptoFrame(nil, uint64(len(hello)), hello))
	if qc.tlsState.stage != quicTLSStageWaitFinished {
		t.Fatalf("second ClientHello left stage %d (closed %v)", qc.tlsState.stage, qc.closed.Load())
	}
	flight := len(pc.snapshot())
	f := &quicFixFlightConn{qc: qc, pc: pc, nextPN: 2}
	f.backdateFlightPastPTO()
	f.feedInitial(quicAppendCryptoFrame(nil, uint64(len(hello)), hello))
	if resent := len(pc.snapshot()) - flight; resent != flight {
		t.Fatalf("a repeated second ClientHello after one PTO drew %d datagrams, want one %d-datagram flight", resent, flight)
	}
}

const quicFixServerProcessing = 10 * time.Millisecond

func TestQUICFixDuplicateClientHelloAtTheClientsFirstPTOResendsTheFlight(t *testing.T) {
	f := newQUICFixFlightConn(t)
	flight := f.datagrams()
	clientPTO := quicInitialRTT + 4*(quicInitialRTT/2)
	f.qc.firstFlight.lastSent -= int64(clientPTO - quicFixServerProcessing)
	f.feedInitial(quicAppendCryptoFrame(nil, 0, f.hello))
	if resent := f.datagrams() - flight; resent != flight {
		t.Fatalf("a duplicate ClientHello one client PTO (%v) after the ClientHello drew %d datagrams, want one %d-datagram flight", clientPTO, resent, flight)
	}
}

func TestQUICFixResendWindowDoublesAfterEachResend(t *testing.T) {
	f := newQUICFixFlightConn(t)
	flight := f.datagrams()
	f.qc.firstFlight.lastSent -= int64(quicInitialRTT)
	f.feedInitial(quicAppendCryptoFrame(nil, 0, f.hello))
	if resent := f.datagrams() - flight; resent != flight {
		t.Fatalf("a duplicate ClientHello one RTT after the flight drew %d datagrams, want %d", resent, flight)
	}
	f.qc.firstFlight.lastSent -= int64(quicInitialRTT)
	f.feedInitial(quicAppendCryptoFrame(nil, 0, f.hello))
	if resent := f.datagrams() - flight; resent != flight {
		t.Fatalf("a duplicate ClientHello one RTT after the first resend drew %d datagrams in total, want %d", resent, flight)
	}
	f.qc.firstFlight.lastSent -= int64(quicInitialRTT)
	f.feedInitial(quicAppendCryptoFrame(nil, 0, f.hello))
	if resent := f.datagrams() - flight; resent != 2*flight {
		t.Fatalf("a duplicate ClientHello two RTTs after the first resend drew %d datagrams in total, want %d", resent, 2*flight)
	}
}
