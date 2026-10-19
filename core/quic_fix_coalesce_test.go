//go:build linux && amd64

package core

import (
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicFixOtherVersion    = 0x6b3343cf
	quicFixFirstRTTSample  = 10 * time.Millisecond
	quicFixSecondRTTSample = 100 * time.Millisecond
	quicFixUnbiasedRTT     = 20 * time.Millisecond
)

var (
	quicFixForeignDCID  = []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7}
	quicFixCoalesceSCID = []byte{0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8}
)

func quicFixReceivedIn(qc *QUICConn, space int, pn uint64) bool {
	for _, r := range qc.ackRanges[space] {
		if pn >= r.lo && pn <= r.hi {
			return true
		}
	}
	return false
}

func newQUICFixCoalescePeer(t *testing.T) (*QUICConn, *quicKeys, *quicKeys) {
	t.Helper()
	startReqStreamWorkers()
	srv := New(Config{})
	srv.Router.Build()
	qc := newQUICTestPeerFor(t, srv).qc
	_, handshakeKeys, err := quicDeriveInitialKeys([]byte{0xee, 1, 2, 3, 4, 5, 6, 7})
	if err != nil {
		t.Fatal(err)
	}
	qc.keys[quicSpaceHandshake] = handshakeKeys
	qc.sendKeys[quicSpaceHandshake] = handshakeKeys
	return qc, handshakeKeys, qc.keys[quicSpaceAppData]
}

func quicFixPingPayload() []byte {
	payload := make([]byte, quicFixKeyUpdatePayload)
	payload[0] = quicFixPingFrame
	return payload
}

func TestQUICFixCoalescedPacketsMustShareDCID(t *testing.T) {
	for _, tc := range []struct {
		name     string
		shortCID func(qc *QUICConn) []byte
		want     bool
	}{
		{"same DCID", func(qc *QUICConn) []byte { return qc.srcCID() }, true},
		{"different DCID", func(*QUICConn) []byte { return quicFixForeignDCID }, false},
	} {
		qc, handshakeKeys, appKeys := newQUICFixCoalescePeer(t)
		datagram := quicBuildHandshakePacket(nil, qc.srcCID(), quicFixCoalesceSCID, quicFixPingPayload(), 0, -1, handshakeKeys)
		datagram = quicBuildShortPacket(datagram, tc.shortCID(qc), quicFixPingPayload(), 4, -1, appKeys, 0)
		qc.processPacket(datagram, quicFixLoopback.AddrPort())
		if !quicFixReceivedIn(qc, quicSpaceHandshake, 0) {
			t.Fatalf("%s: leading Handshake packet not processed", tc.name)
		}
		if got := quicFixReceivedIn(qc, quicSpaceAppData, 4); got != tc.want {
			t.Errorf("%s: coalesced 1-RTT packet processed=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestQUICFixLongHeaderVersionMustMatchConnection(t *testing.T) {
	qc, handshakeKeys, _ := newQUICFixCoalescePeer(t)
	qc.version = quicFixOtherVersion
	qc.processPacket(quicBuildHandshakePacket(nil, qc.srcCID(), quicFixCoalesceSCID, quicFixPingPayload(), 0, -1, handshakeKeys), quicFixLoopback.AddrPort())
	if quicFixReceivedIn(qc, quicSpaceHandshake, 0) {
		t.Error("Handshake packet with a version other than the connection's was processed")
	}
}

func quicFixAckAged(t *testing.T, qc *QUICConn, pn uint64, age time.Duration) {
	t.Helper()
	qc.writeMu.Lock()
	qc.loss.onPacketSent(quicSpaceAppData, pn, quicMaxPacketSize, true, []byte{quicFixPingFrame})
	sent := qc.loss.sent[quicSpaceAppData]
	sent[len(sent)-1].sent = turbo.Now() - int64(age)
	qc.sendPN[quicSpaceAppData] = pn + 1
	qc.writeMu.Unlock()
	qc.processFrames(quicSpaceAppData, pn, quicAppendACKFrameRanges(nil, 0, []pnRange{{lo: pn, hi: pn}}))
}

func TestQUICFixZeroAckDelayDoesNotBiasRTT(t *testing.T) {
	qc, _, _ := newQUICFixCoalescePeer(t)
	quicFixAckAged(t, qc, 0, quicFixFirstRTTSample)
	quicFixAckAged(t, qc, 1, quicFixSecondRTTSample)
	qc.writeMu.Lock()
	srtt := qc.loss.smoothedRTT
	qc.writeMu.Unlock()
	if srtt < quicFixUnbiasedRTT {
		t.Errorf("smoothed RTT %v after samples of %v and %v with ACK Delay 0: an ack delay the peer never reported was subtracted", srtt, quicFixFirstRTTSample, quicFixSecondRTTSample)
	}
}
