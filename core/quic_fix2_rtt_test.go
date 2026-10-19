//go:build linux && amd64

package core

import (
	"testing"
	"time"
)

const (
	quicFix2SendSpacing   = 30 * time.Millisecond
	quicFix2AckOnlyCount  = 3
	quicFix2NoAckDelay    = 0
	quicFix2HistoryFactor = 4
)

func quicFix2BackdateTracked(ls *quicLossState, pn uint64, by time.Duration) {
	for i := range ls.sent[quicSpaceAppData] {
		if ls.sent[quicSpaceAppData][i].pn == pn {
			ls.sent[quicSpaceAppData][i].sent -= int64(by)
		}
	}
}

func TestQUICFix2RTTSampleUsesLargestAckedAckOnlyPacket(t *testing.T) {
	ls := newQuicLossState()
	ls.onPacketSent(quicSpaceAppData, 0, quicMaxPacketSize, true, []byte{quicFixPingFrame})
	quicFix2BackdateTracked(ls, 0, quicFix2SendSpacing)
	for pn := uint64(1); pn <= quicFix2AckOnlyCount; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, quicMaxPacketSize, false, nil)
	}
	ack := quicAckFrame{largestAck: quicFix2AckOnlyCount, firstRange: quicFix2AckOnlyCount}
	if _, err := ls.onAckReceived(quicSpaceAppData, ack, quicFix2NoAckDelay, quicFix2AckOnlyCount+1); err != nil {
		t.Fatal(err)
	}
	if !ls.firstRTTDone {
		t.Fatal("an ACK newly acknowledging an ack-eliciting packet and the largest acknowledged produced no RTT sample")
	}
	if ls.smoothedRTT >= quicFix2SendSpacing/2 {
		t.Fatalf("RTT sample %v was taken from the older ack-eliciting packet, not the largest acknowledged (sent %v later)", ls.smoothedRTT, quicFix2SendSpacing)
	}
}

func TestQUICFix2NoRTTSampleWhenLargestAlreadyAcked(t *testing.T) {
	ls := newQuicLossState()
	ls.onPacketSent(quicSpaceAppData, 0, quicMaxPacketSize, true, []byte{quicFixPingFrame})
	ls.onPacketSent(quicSpaceAppData, 1, quicMaxPacketSize, false, nil)
	if _, err := ls.onAckReceived(quicSpaceAppData, quicAckFrame{largestAck: 1}, quicFix2NoAckDelay, 2); err != nil {
		t.Fatal(err)
	}
	if ls.firstRTTDone {
		t.Fatal("an ACK that newly acknowledged no ack-eliciting packet produced an RTT sample")
	}
	quicFix2BackdateTracked(ls, 0, quicFix2SendSpacing)
	if _, err := ls.onAckReceived(quicSpaceAppData, quicAckFrame{largestAck: 1, firstRange: 1}, quicFix2NoAckDelay, 2); err != nil {
		t.Fatal(err)
	}
	if ls.firstRTTDone {
		t.Fatalf("an ACK whose largest acknowledged was already acknowledged produced an RTT sample of %v", ls.smoothedRTT)
	}
}

func TestQUICFix2NoRTTSampleBeyondSendHistory(t *testing.T) {
	ls := newQuicLossState()
	ls.onPacketSent(quicSpaceAppData, 0, quicMaxPacketSize, true, []byte{quicFixPingFrame})
	quicFix2BackdateTracked(ls, 0, quicFix2SendSpacing)
	last := uint64(quicFix2HistoryFactor * quicSendTimeLogEntries)
	for pn := uint64(1); pn <= last; pn++ {
		ls.appSendTimes.record(pn, int64(pn))
	}
	if _, err := ls.onAckReceived(quicSpaceAppData, quicAckFrame{largestAck: 1, firstRange: 1}, quicFix2NoAckDelay, last+1); err != nil {
		t.Fatal(err)
	}
	if ls.firstRTTDone {
		t.Fatalf("an ACK whose largest acknowledged send time is no longer known produced an RTT sample of %v", ls.smoothedRTT)
	}
}

func TestQUICFix2SendTimeLogFindsTickOfPacket(t *testing.T) {
	var l quicSendTimeLog
	l.record(10, 100)
	l.record(11, 100)
	l.record(12, 105)
	l.record(13, 105)
	l.record(14, 109)
	for _, tc := range []struct {
		pn   uint64
		at   int64
		know bool
	}{{9, 0, false}, {10, 100, true}, {11, 100, true}, {12, 105, true}, {13, 105, true}, {14, 109, true}, {20, 109, true}} {
		at, ok := l.sentAt(tc.pn)
		if ok != tc.know || at != tc.at {
			t.Errorf("sentAt(%d) = %d, %v; want %d, %v", tc.pn, at, ok, tc.at, tc.know)
		}
	}
}

func BenchmarkQUICFix2AckOnlySent(b *testing.B) {
	ls := newQuicLossState()
	b.ReportAllocs()
	pn := uint64(0)
	for b.Loop() {
		ls.onPacketSent(quicSpaceAppData, pn, quicMaxPacketSize, false, nil)
		pn++
	}
}

func BenchmarkQUICFix2AckOnlyPacketSend(b *testing.B) {
	qc := newQUICFixBenchConn(b)
	_, keys, err := quicDeriveInitialKeys([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		b.Fatal(err)
	}
	qc.keys[quicSpaceAppData] = keys
	qc.sendKeys[quicSpaceAppData] = keys
	ack := quicAppendACKFrame(nil, 0, 0, 0)
	b.ReportAllocs()
	for b.Loop() {
		qc.writeMu.Lock()
		qc.sendFramesLocked(quicSpaceAppData, ack, false)
		qc.writeMu.Unlock()
	}
}
