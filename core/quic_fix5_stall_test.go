//go:build linux && amd64

package core

import (
	"math"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicFix5OldStalledStreams = 2
	quicFix5FreshStream       = 8
	quicFix5BeforeTimeout     = quicSendStallTimeout / 2
)

func (p *quicTestPeer) backdateStall(id uint64, by time.Duration) {
	p.t.Helper()
	p.qc.streamsMu.Lock()
	s := p.qc.streams[id]
	p.qc.streamsMu.Unlock()
	if s == nil {
		p.t.Fatalf("stream %d is not open", id)
	}
	s.mu.Lock()
	s.stallSince -= int64(by)
	s.mu.Unlock()
}

func (p *quicTestPeer) excessiveLoadResets() map[uint64]bool {
	reset := map[uint64]bool{}
	for _, r := range p.sent().resets {
		if r.errorCode == quicFixH3ExcessiveLoad {
			reset[r.streamID] = true
		}
	}
	return reset
}

func (p *quicTestPeer) tickAt(now int64) {
	p.qc.lastActive.Store(now)
	p.qc.tick(now, true)
}

func quicFix5DataBytes(t *testing.T, stream []byte) int {
	t.Helper()
	reader := h3FrameReader{data: stream}
	total := 0
	for {
		frameType, payload, ok := reader.next()
		if !ok {
			return total
		}
		if frameType == h3FrameData {
			total += len(payload)
		}
	}
}

func newQUICFix5FreshStallPeer(t *testing.T) (*quicTestPeer, int64) {
	t.Helper()
	p := newQUICFixStalledPeer(t)
	for i := 0; i < quicFix5OldStalledStreams; i++ {
		quicFixSendRequest(p, uint64(i*4), h3AppendHeadersFrame(nil, quicFixGET("/big")))
	}
	p.awaitHandlersIdle()
	if held := p.qc.stalledSendBytes.Load(); held <= p.qc.stallSoftCap {
		t.Fatalf("precondition: %d stalled bytes, soft cap %d", held, p.qc.stallSoftCap)
	}
	now := turbo.UnixNano()
	for i := 0; i < quicFix5OldStalledStreams; i++ {
		p.backdateStall(uint64(i*4), quicFixStallTimeoutPlus)
	}
	p.qc.lastSendProgress.Store(now - int64(quicFixStallTimeoutPlus))
	softCap := p.qc.stallSoftCap
	p.qc.stallSoftCap = math.MaxInt64
	quicFixSendRequest(p, quicFix5FreshStream, h3AppendHeadersFrame(nil, quicFixGET("/big")))
	p.awaitHandlersIdle()
	p.qc.stallSoftCap = softCap
	p.tickAt(now)
	reset := p.excessiveLoadResets()
	for i := 0; i < quicFix5OldStalledStreams; i++ {
		if id := uint64(i * 4); !reset[id] {
			t.Fatalf("precondition: long-stalled stream %d was not reset: %v", id, reset)
		}
	}
	return p, now
}

func TestQUICFix5SendStallSparesFreshlyStalledStream(t *testing.T) {
	p, now := newQUICFix5FreshStallPeer(t)
	if p.excessiveLoadResets()[quicFix5FreshStream] {
		t.Fatalf("stream %d began stalling 0s before the tick but was reset with H3_EXCESSIVE_LOAD as if stalled for %v", quicFix5FreshStream, quicSendStallTimeout)
	}
	if !p.hasStream(quicFix5FreshStream) {
		t.Fatalf("freshly stalled stream %d was retired", quicFix5FreshStream)
	}
	if held := p.qc.stalledSendBytes.Load(); held <= p.qc.stallSoftCap {
		t.Fatalf("precondition: fresh stream holds %d stalled bytes, want more than the %d soft cap", held, p.qc.stallSoftCap)
	}
	if p.qc.sendStalledTooLong(now) {
		t.Fatal("the stall timer still fires right after the reset pass; it would rescan every idle check")
	}
	if !p.qc.sendStalledTooLong(now + int64(quicFixStallTimeoutPlus)) {
		t.Fatal("the stall timer is not re-armed for the fresh stream that stays stalled")
	}
}

func TestQUICFix5StallTimerRearmsWhenNoStreamQualifies(t *testing.T) {
	p := newQUICFixStalledPeer(t)
	quicFixSendRequest(p, quicFix5FreshStream, h3AppendHeadersFrame(nil, quicFixGET("/big")))
	p.awaitHandlersIdle()
	if held := p.qc.stalledSendBytes.Load(); held <= p.qc.stallSoftCap {
		t.Fatalf("precondition: %d stalled bytes, soft cap %d", held, p.qc.stallSoftCap)
	}
	now := turbo.UnixNano()
	p.qc.lastSendProgress.Store(now - int64(quicFixStallTimeoutPlus))
	p.tickAt(now)
	if p.excessiveLoadResets()[quicFix5FreshStream] {
		t.Fatalf("stream %d was reset although it had just begun stalling", quicFix5FreshStream)
	}
	if p.qc.sendStalledTooLong(now) {
		t.Fatal("a stall pass that reset nothing left the timer armed; it would rescan every idle check")
	}
	p.tickAt(now + int64(quicFixStallTimeoutPlus))
	if !p.excessiveLoadResets()[quicFix5FreshStream] {
		t.Fatalf("stream %d stalled for %v and was not reset", quicFix5FreshStream, quicFixStallTimeoutPlus)
	}
}

func TestQUICFix5FreshStalledStreamCompletesWithCredit(t *testing.T) {
	p, now := newQUICFix5FreshStallPeer(t)
	p.send(quicAppendMaxStreamDataFrame(nil, quicFix5FreshStream, 2*quicFixBigResponse))
	p.send(quicAppendMaxDataFrame(nil, 8*quicFixBigResponse))
	p.awaitFin(quicFix5FreshStream)
	p.awaitHandlersIdle()
	if status := quicFixResponseStatus(t, p, quicFix5FreshStream); status != 200 {
		t.Fatalf("fresh stream got status %d after credit, want 200", status)
	}
	if got := quicFix5DataBytes(t, quicFixStreamData(p, quicFix5FreshStream)); got != quicFixBigResponse {
		t.Fatalf("fresh stream delivered %d body bytes after credit, want %d", got, quicFixBigResponse)
	}
	if held := p.qc.stalledSendBytes.Load(); held != 0 {
		t.Fatalf("%d stalled bytes still held after every stalled stream drained or was reset", held)
	}
	p.tickAt(now + int64(quicFixStallTimeoutPlus))
	if p.excessiveLoadResets()[quicFix5FreshStream] {
		t.Fatalf("stream %d was reset after it completed", quicFix5FreshStream)
	}
	if p.qc.closed.Load() {
		t.Fatal("the connection closed")
	}
}

func TestQUICFix5StillStalledStreamResetAfterTimeout(t *testing.T) {
	p, now := newQUICFix5FreshStallPeer(t)
	p.tickAt(now + int64(quicFix5BeforeTimeout))
	if p.excessiveLoadResets()[quicFix5FreshStream] {
		t.Fatalf("stream %d was reset after stalling only %v", quicFix5FreshStream, quicFix5BeforeTimeout)
	}
	p.tickAt(now + int64(quicFixStallTimeoutPlus))
	if !p.excessiveLoadResets()[quicFix5FreshStream] {
		t.Fatalf("stream %d stalled for %v and was not reset", quicFix5FreshStream, quicFixStallTimeoutPlus)
	}
	if held := p.qc.stalledSendBytes.Load(); held != 0 {
		t.Fatalf("%d stalled bytes still held after the last stalled stream was reset", held)
	}
	if p.hasStream(quicFix5FreshStream) {
		t.Fatalf("stream %d was not retired after its reset", quicFix5FreshStream)
	}
	if p.qc.closed.Load() {
		t.Fatal("a send stall closed the whole connection")
	}
}
