//go:build linux && amd64

package core

import (
	"slices"
	"testing"
	"time"
)

const (
	quicFixAckTracked        = quicMaxTrackedSent
	quicFixAckRanges         = 256
	quicFixAckFrames         = 50
	quicFixSingleAckFrames   = 2000
	quicFixAckTrials         = 3
	quicFixAckFrameBudget    = 2 * time.Millisecond
	quicFixSingleAcksBudget  = 20 * time.Millisecond
	quicFixAckPacketSize     = 1200
	quicFixAckUnsentHeadroom = 4096
)

func quicFixOddPacketsSent(n int) *quicLossState {
	ls := newQuicLossState()
	for i := 0; i < n; i++ {
		ls.onPacketSent(quicSpaceAppData, uint64(2*i+1), quicFixAckPacketSize, true, nil)
	}
	return ls
}

func quicFixFastest(trials int, run func() time.Duration) time.Duration {
	best := time.Duration(1<<63 - 1)
	for i := 0; i < trials; i++ {
		best = min(best, run())
	}
	return best
}

func TestQUICFixAckWithManyEmptyRangesCostsLessThanRangesTimesTracked(t *testing.T) {
	nextPN := uint64(2*quicFixAckTracked + quicFixAckUnsentHeadroom)
	ack := quicAckFrame{largestAck: uint64(2*quicFixAckTracked + 2*quicFixAckRanges + 2)}
	for i := 0; i < quicFixAckRanges; i++ {
		ack.ranges = append(ack.ranges, quicAckRange{gap: 0, count: 0})
	}
	var ls *quicLossState
	perFrame := quicFixFastest(quicFixAckTrials, func() time.Duration {
		ls = quicFixOddPacketsSent(quicFixAckTracked)
		start := time.Now()
		for i := 0; i < quicFixAckFrames; i++ {
			if _, err := ls.onAckReceived(quicSpaceAppData, ack, 0, nextPN); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start) / quicFixAckFrames
	})
	if left := len(ls.sent[quicSpaceAppData]); left != quicFixAckTracked {
		t.Fatalf("ACK of unsent packet numbers removed tracked packets: %d left of %d", left, quicFixAckTracked)
	}
	if perFrame > quicFixAckFrameBudget {
		t.Fatalf("one ACK frame with %d ranges over %d tracked packets took %v, want at most %v", quicFixAckRanges, quicFixAckTracked, perFrame, quicFixAckFrameBudget)
	}
}

func TestQUICFixManySingleAckFramesCostLessThanFramesTimesTracked(t *testing.T) {
	nextPN := uint64(2*quicFixAckTracked + quicFixAckUnsentHeadroom)
	var ls *quicLossState
	total := quicFixFastest(quicFixAckTrials, func() time.Duration {
		ls = quicFixOddPacketsSent(quicFixAckTracked)
		start := time.Now()
		for i := 1; i <= quicFixSingleAckFrames; i++ {
			pn := uint64(2*i + 1)
			if _, err := ls.onAckReceived(quicSpaceAppData, quicAckFrame{largestAck: pn}, 0, nextPN); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start)
	})
	if live := ls.liveSent(quicSpaceAppData); live != quicFixAckTracked-quicFixSingleAckFrames {
		t.Fatalf("%d tracked packets after %d single ACKs of %d, want %d", live, quicFixSingleAckFrames, quicFixAckTracked, quicFixAckTracked-quicFixSingleAckFrames)
	}
	if want := quicFixAckTracked - quicFixSingleAckFrames; ls.bytesInFlight != want*quicFixAckPacketSize {
		t.Fatalf("bytes in flight %d, want %d", ls.bytesInFlight, want*quicFixAckPacketSize)
	}
	if total > quicFixSingleAcksBudget {
		t.Fatalf("%d one-packet ACK frames over %d tracked packets took %v, want at most %v", quicFixSingleAckFrames, quicFixAckTracked, total, quicFixSingleAcksBudget)
	}
}

func quicFixLivePNs(ls *quicLossState, space int) []uint64 {
	var pns []uint64
	for _, sp := range ls.sent[space] {
		if !sp.acked {
			pns = append(pns, sp.pn)
		}
	}
	return pns
}

func TestQUICFixMultiRangeAckRemovesExactlyTheAckedPackets(t *testing.T) {
	ls := newQuicLossState()
	for pn := uint64(0); pn < 40; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, 100, pn%5 != 4, []byte{quicFramePing})
	}
	ack := quicAckFrame{largestAck: 30, firstRange: 2, ranges: []quicAckRange{{gap: 1, count: 3}, {gap: 4, count: 0}, {gap: 0, count: 5}}}
	acked := map[uint64]bool{}
	for _, r := range [][2]uint64{{28, 30}, {22, 25}, {16, 16}, {9, 14}} {
		for pn := r[0]; pn <= r[1]; pn++ {
			acked[pn] = true
		}
	}
	if _, err := ls.onAckReceived(quicSpaceAppData, ack, 0, 40); err != nil {
		t.Fatal(err)
	}
	var want []uint64
	inFlight := 0
	for pn := uint64(0); pn < 40; pn++ {
		if pn%5 != 4 && !acked[pn] {
			want = append(want, pn)
			inFlight += 100
		}
	}
	if got := quicFixLivePNs(ls, quicSpaceAppData); !slices.Equal(got, want) {
		t.Fatalf("tracked packets after the ACK %v, want %v", got, want)
	}
	if ls.bytesInFlight != inFlight {
		t.Fatalf("bytes in flight %d, want %d", ls.bytesInFlight, inFlight)
	}
	if ls.largestAcked[quicSpaceAppData] != 30 {
		t.Fatalf("largest acked %d, want 30", ls.largestAcked[quicSpaceAppData])
	}
	if lost := ls.detectLost(quicSpaceAppData, nil); len(lost) == 0 {
		t.Fatal("packets below the largest acked were not declared lost")
	}
	if got := quicFixLivePNs(ls, quicSpaceAppData); len(got) == 0 || got[0] < 28 {
		t.Fatalf("tracked packets after loss detection %v, want only packets above the packet threshold", got)
	}
}

const (
	quicFixReackFrames  = 5000
	quicFixReackLowPN   = 5
	quicFixReackHighPN  = 16003
	quicFixReackEntries = (quicFixReackHighPN-quicFixReackLowPN)/2 + 1
	quicFixReackBudget  = 20 * time.Millisecond
)

func TestQUICFixRepeatedAckOfAnAckedRangeIsCheap(t *testing.T) {
	if 2*quicFixReackEntries > quicFixAckTracked {
		t.Fatalf("fixture acks %d of %d packets; it must stay below the compaction point", quicFixReackEntries, quicFixAckTracked)
	}
	nextPN := uint64(2*quicFixAckTracked + quicFixAckUnsentHeadroom)
	ack := quicAckFrame{largestAck: quicFixReackHighPN, firstRange: quicFixReackHighPN - quicFixReackLowPN}
	var ls *quicLossState
	total := quicFixFastest(quicFixAckTrials, func() time.Duration {
		ls = quicFixOddPacketsSent(quicFixAckTracked)
		if _, err := ls.onAckReceived(quicSpaceAppData, ack, 0, nextPN); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		for i := 0; i < quicFixReackFrames; i++ {
			if _, err := ls.onAckReceived(quicSpaceAppData, ack, 0, nextPN); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start)
	})
	if got := ls.liveSent(quicSpaceAppData); got != quicFixAckTracked-quicFixReackEntries {
		t.Fatalf("%d live packets, want %d", got, quicFixAckTracked-quicFixReackEntries)
	}
	if dead := len(ls.sent[quicSpaceAppData]) - ls.liveSent(quicSpaceAppData); dead != quicFixReackEntries {
		t.Fatalf("%d acked entries kept for the re-ACK scan, want %d", dead, quicFixReackEntries)
	}
	if total > quicFixReackBudget {
		t.Fatalf("%d repeated ACKs of %d acked packets took %v, want at most %v", quicFixReackFrames, quicFixReackEntries, total, quicFixReackBudget)
	}
}

func TestQUICFixAckedEntriesAreCompactedAwayBeforeTheyOutnumberLivePackets(t *testing.T) {
	nextPN := uint64(2*quicFixAckTracked + quicFixAckUnsentHeadroom)
	ls := quicFixOddPacketsSent(quicFixAckTracked)
	for i := 0; i < quicFixAckTracked-1; i++ {
		pn := uint64(2*i + 1)
		if _, err := ls.onAckReceived(quicSpaceAppData, quicAckFrame{largestAck: pn}, 0, nextPN); err != nil {
			t.Fatal(err)
		}
		if live, kept := ls.liveSent(quicSpaceAppData), len(ls.sent[quicSpaceAppData]); kept > 2*live {
			t.Fatalf("after %d ACKs the list keeps %d entries for %d live packets", i+1, kept, live)
		}
	}
}

func TestQUICFixPTOAfterPartialAckRecoversOnlyLivePackets(t *testing.T) {
	ls := newQuicLossState()
	for pn := uint64(0); pn < 10; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, 100, true, []byte{quicFramePing})
	}
	if _, err := ls.onAckReceived(quicSpaceAppData, quicAckFrame{largestAck: 6, firstRange: 2}, 0, 10); err != nil {
		t.Fatal(err)
	}
	ls.mu.Lock()
	for i := range ls.sent[quicSpaceAppData] {
		ls.sent[quicSpaceAppData][i].sent -= int64(10 * time.Second)
	}
	ls.mu.Unlock()
	frames := ls.ptoExpiredFrames(quicSpaceAppData)
	if len(frames) != 7 {
		t.Fatalf("PTO recovered %d packets, want the 7 that were never acked", len(frames))
	}
	if live, kept := ls.liveSent(quicSpaceAppData), len(ls.sent[quicSpaceAppData]); live != 0 || kept != 0 {
		t.Fatalf("after the PTO the list keeps %d entries, %d live", kept, live)
	}
	if ls.bytesInFlight != 0 {
		t.Fatalf("bytes in flight %d after every packet was acked or recovered", ls.bytesInFlight)
	}
}

func TestQUICFixAckOfTheOldestPacketsReportsNoPossibleLoss(t *testing.T) {
	ls := newQuicLossState()
	for pn := uint64(0); pn < 10; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, 100, true, nil)
	}
	lossPossible, err := ls.onAckReceived(quicSpaceAppData, quicAckFrame{largestAck: 4, firstRange: 4}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if dead := len(ls.sent[quicSpaceAppData]) - ls.liveSent(quicSpaceAppData); dead != 5 {
		t.Fatalf("fixture kept %d acked entries, want 5 so the oldest entry is acked", dead)
	}
	if lossPossible {
		t.Fatal("an ACK of the five oldest packets reported possible loss with no live packet below the largest acked")
	}
}
