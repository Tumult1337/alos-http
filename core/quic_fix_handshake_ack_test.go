//go:build linux && amd64

package core

import (
	"testing"
)

const (
	quicFixFloodDatagrams = 200
	quicFixFloodPNStride  = 100000
)

type quicFixServerDatagram struct {
	size         int
	initialAcks  []quicAckFrame
	ackEliciting bool
}

func (f *quicFixFlightConn) clientInitial(pn uint64, frames []byte, padded bool) []byte {
	build := func(payload []byte) []byte {
		return quicBuildInitialPacket(nil, f.qc.srcCID(), quicFixClientSCID, nil, payload, pn, -1, f.qc.keys[quicSpaceInitial])
	}
	pkt := build(frames)
	if short := quicMinInitialDatagram - len(pkt); padded && short > 0 {
		pkt = build(append(append([]byte(nil), frames...), make([]byte, short+2)...))
	}
	return pkt
}

func (f *quicFixFlightConn) feedDatagram(datagram []byte) {
	f.qc.processPacket(append([]byte(nil), datagram...), quicAddrPort(&quicFixLoopback))
}

func (f *quicFixFlightConn) serverDatagrams(t *testing.T, from int) []quicFixServerDatagram {
	t.Helper()
	var out []quicFixServerDatagram
	for _, raw := range f.pc.snapshot()[from:] {
		d := quicFixServerDatagram{size: len(raw)}
		pkt := append([]byte(nil), raw...)
		for len(pkt) > 0 && quicIsLongHeader(pkt) {
			hdr, total, err := quicParseLongHeader(pkt)
			if err != nil {
				t.Fatalf("server sent an unparseable long header: %v", err)
			}
			if hdr.pktType == quicPktInitial {
				plain, err := quicDecryptPacket(pkt[:total], &hdr, f.qc.sendKeys[quicSpaceInitial], -1)
				if err != nil {
					t.Fatalf("server sent an undecryptable Initial: %v", err)
				}
				visitor := &quicFrameVisitor{
					onACK:    func(a quicAckFrame) { d.initialAcks = append(d.initialAcks, a) },
					onCrypto: func(quicCryptoFrame) { d.ackEliciting = true },
					onPing:   func() { d.ackEliciting = true },
				}
				if err := quicParseFrames(plain, visitor); err != nil {
					t.Fatalf("server sent malformed Initial frames: %v", err)
				}
			}
			pkt = pkt[total:]
		}
		out = append(out, d)
	}
	return out
}

func quicFixAckCovers(a quicAckFrame, pn uint64) bool {
	lo, hi := a.largestAck-a.firstRange, a.largestAck
	if pn >= lo && pn <= hi {
		return true
	}
	for _, r := range a.ranges {
		if lo < r.gap+2 {
			return false
		}
		hi = lo - r.gap - 2
		if hi < r.count {
			return false
		}
		lo = hi - r.count
		if pn >= lo && pn <= hi {
			return true
		}
	}
	return false
}

func TestQUICFixDuplicateInitialInsideTheResendWindowIsAcked(t *testing.T) {
	f := newQUICFixFlightConn(t)
	base := f.datagrams()
	const pn = 1
	f.feedDatagram(f.clientInitial(pn, quicAppendCryptoFrame(nil, 0, f.hello), true))
	sent := f.serverDatagrams(t, base)
	if len(sent) != 1 {
		t.Fatalf("a duplicate ClientHello inside the resend window drew %d datagrams, want one ACK datagram", len(sent))
	}
	d := sent[0]
	if d.ackEliciting {
		t.Fatal("the reply to a duplicate ClientHello inside the resend window resent the flight")
	}
	if len(d.initialAcks) != 1 || !quicFixAckCovers(d.initialAcks[0], pn) {
		t.Fatalf("reply Initial ACK frames %+v do not cover packet %d", d.initialAcks, pn)
	}
	if d.size >= quicMinInitialDatagram {
		t.Fatalf("ACK-only datagram is %d bytes; it carries no ack-eliciting packet and needs no padding", d.size)
	}
}

func TestQUICFixInitialFloodGetsAcksWithinTheAmplificationLimit(t *testing.T) {
	for _, validated := range []bool{true, false} {
		f := newQUICFixFlightConn(t)
		f.qc.addressValidated.Store(validated)
		f.qc.bytesSent.Store(0)
		f.qc.bytesReceived.Store(0)
		base := f.datagrams()
		in := 0
		for i := 1; i <= quicFixFloodDatagrams; i++ {
			datagram := f.clientInitial(uint64(i*quicFixFloodPNStride), []byte{quicFramePing}, false)
			in += len(datagram)
			f.feedDatagram(datagram)
		}
		out, acks := 0, 0
		for _, d := range f.serverDatagrams(t, base) {
			out += d.size
			acks += len(d.initialAcks)
		}
		if acks == 0 {
			t.Fatalf("validated=%v: %d ack-eliciting Initial packets drew no ACK", validated, quicFixFloodDatagrams)
		}
		if out > quicAmplificationFactor*in {
			t.Fatalf("validated=%v: %d small Initial datagrams (%d bytes) drew %d bytes of ACKs", validated, quicFixFloodDatagrams, in, out)
		}
	}
}

func TestQUICFixResentFlightCarriesTheAckWithoutAnExtraDatagram(t *testing.T) {
	f := newQUICFixFlightConn(t)
	flight := f.datagrams()
	f.qc.firstFlight.lastSent -= int64(f.resendWindow())
	const pn = 7
	f.feedDatagram(f.clientInitial(pn, quicAppendCryptoFrame(nil, 0, f.hello), true))
	sent := f.serverDatagrams(t, flight)
	if len(sent) != flight {
		t.Fatalf("a duplicate ClientHello after the window drew %d datagrams, want only the %d-datagram flight", len(sent), flight)
	}
	if len(sent[0].initialAcks) != 1 || !quicFixAckCovers(sent[0].initialAcks[0], pn) || !quicFixAckCovers(sent[0].initialAcks[0], quicFixClientHelloInitialPN) {
		t.Fatalf("resent flight Initial ACK frames %+v do not cover packets %d and %d", sent[0].initialAcks, quicFixClientHelloInitialPN, pn)
	}
}

const quicFixAcksBeforeResend = 10

func TestQUICFixAckBytesCountAgainstTheAmplificationBudgetOfLaterFlights(t *testing.T) {
	f := newQUICFixFlightConn(t)
	f.qc.addressValidated.Store(false)
	f.qc.bytesSent.Store(0)
	f.qc.bytesReceived.Store(0)
	base := f.datagrams()
	in := 0
	for i := 1; i <= quicFixAcksBeforeResend; i++ {
		datagram := f.clientInitial(uint64(i*quicFixFloodPNStride), []byte{quicFramePing}, false)
		in += len(datagram)
		f.feedDatagram(datagram)
	}
	acks := 0
	for _, d := range f.serverDatagrams(t, base) {
		acks += d.size
	}
	if acks == 0 {
		t.Fatal("fixture PING packets drew no ACK")
	}
	f.qc.firstFlight.lastSent -= int64(f.resendWindow())
	fragment := f.clientInitial(uint64((quicFixAcksBeforeResend+1)*quicFixFloodPNStride), quicAppendCryptoFrame(nil, 0, f.hello[:16]), false)
	in += len(fragment)
	f.feedDatagram(fragment)
	out := 0
	for _, d := range f.serverDatagrams(t, base) {
		out += d.size
	}
	if out > quicAmplificationFactor*in {
		t.Fatalf("server sent %d bytes (%d of them ACKs) to an unvalidated address that sent %d", out, acks, in)
	}
}

func TestQUICFixReplayedInitialPacketNumberIsAcked(t *testing.T) {
	f := newQUICFixFlightConn(t)
	const pn = 3
	datagram := f.clientInitial(pn, []byte{quicFramePing}, false)
	f.feedDatagram(datagram)
	base := f.datagrams()
	f.feedDatagram(datagram)
	sent := f.serverDatagrams(t, base)
	if len(sent) != 1 || len(sent[0].initialAcks) != 1 || !quicFixAckCovers(sent[0].initialAcks[0], pn) {
		t.Fatalf("a replayed Initial packet %d drew %+v, want one ACK that covers it", pn, sent)
	}
}
