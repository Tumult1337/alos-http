//go:build linux && amd64

package core

import (
	"testing"
)

const (
	quicFixCwndResponse       = 1 << 20
	quicFixCwndRequests       = 16
	quicFixCwndPendingCap     = 1 << 20
	quicFixCwndLiveResponse   = 256 << 10
	quicFixCwndLiveRequests   = 3
	quicFixUnlimitedFlowLimit = 1 << 40
)

func newQUICFixCwndPeer(t *testing.T, responseLen int) *quicTestPeer {
	t.Helper()
	startReqStreamWorkers()
	srv := New(Config{MaxPendingWriteBytes: quicFixCwndPendingCap})
	body := make([]byte, responseLen)
	srv.Router.GET("/big", func(req *Request, resp *Response) { resp.Status(200).BytesNoCopy(body) })
	srv.Router.Build()
	p := newQUICTestPeerFor(t, srv)
	p.qc.writeMu.Lock()
	p.qc.maxDataRemote = quicFixUnlimitedFlowLimit
	p.qc.peerStreamWindow = quicFixUnlimitedFlowLimit
	p.qc.writeMu.Unlock()
	return p
}

func (p *quicTestPeer) congestionState() (queued, inFlight int, cwnd uint64) {
	p.qc.writeMu.Lock()
	queued = len(p.qc.coalesceBuf) - p.qc.coalesceStart
	p.qc.loss.mu.Lock()
	inFlight, cwnd = p.qc.loss.bytesInFlight, p.qc.loss.cwnd
	p.qc.loss.mu.Unlock()
	p.qc.writeMu.Unlock()
	return queued, inFlight, cwnd
}

func TestQUICFixUnackedResponsesStayWithinTheCongestionWindow(t *testing.T) {
	p := newQUICFixCwndPeer(t, quicFixCwndResponse)
	for i := 0; i < quicFixCwndRequests; i++ {
		quicFixSendRequest(p, uint64(i*4), h3AppendHeadersFrame(nil, quicFixGET("/big")))
	}
	p.awaitHandlersIdle()
	queued, inFlight, cwnd := p.congestionState()
	if inFlight == 0 {
		t.Fatal("fixture sent nothing; the congestion window was never filled")
	}
	if limit := int(cwnd) + 2*(p.qc.pktBudget+quicShortHeaderMaxOverhead); queued+inFlight > limit {
		t.Fatalf("a peer that sends no ACK has %d bytes queued and %d in flight, want at most %d (cwnd %d)", queued, inFlight, limit, cwnd)
	}
	pending, _ := p.pendingResponseBytes()
	if held := p.qc.stalledSendBytes.Load(); pending == 0 || held == 0 {
		t.Fatalf("held-back response bytes %d, stalled accounting %d; both must be non-zero", pending, held)
	}
}

func TestQUICFixCongestionStalledResponsesHitTheHardCap(t *testing.T) {
	p := newQUICFixCwndPeer(t, quicFixCwndResponse)
	for i := 0; i < quicFixCwndRequests; i++ {
		quicFixSendRequest(p, uint64(i*4), h3AppendHeadersFrame(nil, quicFixGET("/big")))
	}
	p.awaitHandlersIdle()
	pending, _ := p.pendingResponseBytes()
	if limit := quicFixCwndPendingCap*quicStalledSendHardFactor + quicFixCwndResponse + 4096; pending > limit {
		t.Fatalf("a peer that sends no ACK pinned %d response bytes on one conn, want <= %d", pending, limit)
	}
	p.awaitSent("RESET_STREAM with H3_EXCESSIVE_LOAD", func(f quicSentFrames) bool {
		for _, r := range f.resets {
			if r.errorCode == quicFixH3ExcessiveLoad {
				return true
			}
		}
		return false
	})
}

func TestQUICFixCongestionStalledResponsesFinishWhenAcked(t *testing.T) {
	p := newQUICFixCwndPeer(t, quicFixCwndLiveResponse)
	for i := 0; i < quicFixCwndLiveRequests; i++ {
		quicFixSendRequest(p, uint64(i*4), h3AppendHeadersFrame(nil, quicFixGET("/big")))
	}
	p.awaitHandlersIdle()
	if pending, _ := p.pendingResponseBytes(); pending == 0 {
		t.Fatal("fixture responses fit in the first congestion window; the test needs held-back bytes")
	}
	for i := 0; i < quicFixCwndLiveRequests; i++ {
		p.awaitFin(uint64(i * 4))
	}
	if held := p.qc.stalledSendBytes.Load(); held != 0 {
		t.Fatalf("stalled accounting holds %d bytes after every response finished", held)
	}
}

func TestQUICFixAmplificationBlockedResponseStaysWithinTheCongestionWindow(t *testing.T) {
	p := newQUICFixCwndPeer(t, quicFixCwndResponse)
	p.qc.writeMu.Lock()
	p.qc.addressValidated.Store(false)
	p.qc.bytesSent.Store(0)
	p.qc.bytesReceived.Store(quicMinInitialDatagram)
	p.qc.writeMu.Unlock()
	quicFixSendRequest(p, 0, h3AppendHeadersFrame(nil, quicFixGET("/big")))
	p.awaitHandlersIdle()
	queued, inFlight, cwnd := p.congestionState()
	if limit := int(cwnd) + 2*(p.qc.pktBudget+quicShortHeaderMaxOverhead); queued+inFlight > limit {
		t.Fatalf("an unvalidated path has %d bytes queued and %d in flight, want at most %d (cwnd %d)", queued, inFlight, limit, cwnd)
	}
	if inFlight >= int(cwnd) {
		t.Fatalf("fixture filled the congestion window (%d of %d); the amplification limit must be the blocker", inFlight, cwnd)
	}
}

func TestQUICFixCongestionBlockedStreamsResumeOnTick(t *testing.T) {
	p := newQUICFixCwndPeer(t, quicFixCwndLiveResponse)
	quicFixSendRequest(p, 0, h3AppendHeadersFrame(nil, quicFixGET("/big")))
	p.awaitHandlersIdle()
	before, _ := p.pendingResponseBytes()
	if before == 0 {
		t.Fatal("fixture response fit in the first congestion window")
	}
	p.qc.loss.mu.Lock()
	p.qc.loss.cwnd += quicFixCwndLiveResponse
	p.qc.loss.mu.Unlock()
	p.qc.timerWork.Store(true)
	p.qc.tick(p.qc.lastActive.Load(), false)
	if after, _ := p.pendingResponseBytes(); after >= before {
		t.Fatalf("a timer tick after the congestion window opened left %d of %d held-back bytes", after, before)
	}
}

func TestQUICFixSendRoomHonoursTheWindowAndTheTrackedPacketCap(t *testing.T) {
	ls := newQuicLossState()
	if room := ls.sendRoom(); room != quicInitialWindow {
		t.Fatalf("empty connection send room %d, want %d", room, quicInitialWindow)
	}
	ls.onPacketSent(quicSpaceAppData, 0, quicInitialWindow+quicMaxPacketSize, true, nil)
	if room := ls.sendRoom(); room != 0 {
		t.Fatalf("send room %d with more bytes in flight than the window", room)
	}
	ls = newQuicLossState()
	ls.mu.Lock()
	ls.cwnd = 1 << 40
	ls.mu.Unlock()
	for pn := uint64(0); pn < quicMaxTrackedSent; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, 1, true, nil)
	}
	if room := ls.sendRoom(); room != 0 {
		t.Fatalf("send room %d with %d tracked packets", room, quicMaxTrackedSent)
	}
}

func (p *quicTestPeer) ackEverySent() {
	p.qc.writeMu.Lock()
	next := p.qc.sendPN[quicSpaceAppData]
	p.qc.writeMu.Unlock()
	if next == 0 || p.qc.closed.Load() {
		return
	}
	p.send(quicAppendACKFrame(nil, next-1, 0, next-1))
}
