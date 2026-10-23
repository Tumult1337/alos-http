//go:build linux && amd64

package core

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicFixAdmitCap        = 2
	quicFixAdmitRequests   = 6
	quicFixAdmitBurst      = 32
	quicFixAdmitSettle     = 50 * time.Millisecond
	quicFixAdmitBody       = 4096
	quicFixAdmitPendingCap = 64 << 10
	quicFixAdmitBigBody    = 256 << 10
)

type quicFixBlockingRoutes struct {
	running atomic.Int32
	peak    atomic.Int32
	started atomic.Int32
	release chan struct{}
	once    sync.Once
}

func newQUICFixBlockingRoutes() *quicFixBlockingRoutes {
	return &quicFixBlockingRoutes{release: make(chan struct{})}
}

func (r *quicFixBlockingRoutes) open() {
	r.once.Do(func() { close(r.release) })
}

func (r *quicFixBlockingRoutes) handler(req *Request, resp *Response) {
	r.started.Add(1)
	now := r.running.Add(1)
	for {
		peak := r.peak.Load()
		if now <= peak || r.peak.CompareAndSwap(peak, now) {
			break
		}
	}
	<-r.release
	r.running.Add(-1)
	resp.Status(200).String("ok")
}

func newQUICFixAdmissionPeer(t *testing.T, cfg Config, routes func(*Router)) *quicTestPeer {
	t.Helper()
	srv := New(cfg)
	routes(srv.Router)
	srv.Router.Build()
	return newQUICTestPeerFor(t, srv)
}

func awaitQUICFix(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := turbo.Deadline(quicPeerWait)
	for !cond() {
		if turbo.Until(deadline) <= 0 {
			t.Fatalf("timed out waiting for %s", what)
		}
		turbo.Sleep(quicPeerPoll)
	}
}

func (p *quicTestPeer) awaitFinsAcking(ids []uint64) {
	p.t.Helper()
	for _, id := range ids {
		p.awaitFin(id)
	}
}

func TestQUICFixH3BurstOfRequestsCompletesUnderTheHandlerCap(t *testing.T) {
	var hits atomic.Int32
	p := newQUICFixAdmissionPeer(t, Config{H2MaxRunningHandlers: quicFixAdmitCap}, func(r *Router) {
		r.GET("/fast", func(req *Request, resp *Response) { hits.Add(1); resp.Status(200).String("ok") })
	})
	var ids []uint64
	for i := 0; i < quicFixAdmitBurst; i++ {
		id := uint64(i * 4)
		ids = append(ids, id)
		quicFixSendRequest(p, id, h3AppendHeadersFrame(nil, quicFixGET("/fast")))
	}
	p.awaitFinsAcking(ids)
	if got := hits.Load(); got != quicFixAdmitBurst {
		t.Fatalf("%d of %d requests ran", got, quicFixAdmitBurst)
	}
	p.awaitHandlersIdle()
}

func TestQUICFixH3RunningHandlersStayAtTheCap(t *testing.T) {
	routes := newQUICFixBlockingRoutes()
	t.Cleanup(routes.open)
	p := newQUICFixAdmissionPeer(t, Config{H2MaxRunningHandlers: quicFixAdmitCap}, func(r *Router) { r.GET("/block", routes.handler) })
	var ids []uint64
	for i := 0; i < quicFixAdmitRequests; i++ {
		id := uint64(i * 4)
		ids = append(ids, id)
		quicFixSendRequest(p, id, h3AppendHeadersFrame(nil, quicFixGET("/block")))
	}
	awaitQUICFix(t, "the first handlers to start", func() bool { return routes.running.Load() >= quicFixAdmitCap })
	turbo.Sleep(quicFixAdmitSettle)
	if peak := routes.peak.Load(); peak != quicFixAdmitCap {
		t.Fatalf("%d handlers ran at once on one connection, want %d", peak, quicFixAdmitCap)
	}
	if active := p.qc.activeReqStreams.Load(); active != quicFixAdmitRequests {
		t.Fatalf("%d request slots held, want %d running or waiting", active, quicFixAdmitRequests)
	}
	routes.open()
	awaitQUICFix(t, "every waiting handler to start without an ACK", func() bool { return routes.started.Load() == quicFixAdmitRequests })
	p.awaitFinsAcking(ids)
	if started := routes.started.Load(); started != quicFixAdmitRequests {
		t.Fatalf("%d of %d waiting requests ran", started, quicFixAdmitRequests)
	}
	if peak := routes.peak.Load(); peak > quicFixAdmitCap {
		t.Fatalf("%d handlers ran at once after the release, want at most %d", peak, quicFixAdmitCap)
	}
}

func TestQUICFixH3ResetOfAWaitingStreamReleasesIt(t *testing.T) {
	routes := newQUICFixBlockingRoutes()
	t.Cleanup(routes.open)
	p := newQUICFixAdmissionPeer(t, Config{H2MaxRunningHandlers: 1}, func(r *Router) { r.POST("/block", routes.handler) })
	body := h3AppendDataFrame(nil, make([]byte, quicFixAdmitBody))
	quicFixSendRequest(p, 0, h3AppendHeadersFrame(nil, quicFixPOST("/block", quicFixAdmitBody)), body)
	awaitQUICFix(t, "the first handler to start", func() bool { return routes.running.Load() == 1 })
	reserved := p.qc.bodyReserved.Load()
	waiting := h3AppendHeadersFrame(nil, quicFixPOST("/block", quicFixAdmitBody))
	waiting = append(waiting, body...)
	quicFixSendRequest(p, 4, waiting)
	turbo.Sleep(quicFixAdmitSettle)
	if p.qc.bodyReserved.Load() <= reserved || !p.hasStream(4) || p.qc.activeReqStreams.Load() != 2 {
		t.Fatalf("fixture stream 4 is not waiting with a body: reserved %d (was %d), tracked %v, slots %d", p.qc.bodyReserved.Load(), reserved, p.hasStream(4), p.qc.activeReqStreams.Load())
	}
	p.send(quicAppendResetStreamFrame(nil, 4, h3ErrRequestRejected, uint64(len(waiting))))
	awaitQUICFix(t, "the reset waiting stream to be released", func() bool {
		return !p.hasStream(4) && p.qc.activeReqStreams.Load() == 1 && p.qc.bodyReserved.Load() == reserved
	})
	routes.open()
	p.awaitFin(0)
	p.awaitHandlersIdle()
	if started := routes.started.Load(); started != 1 {
		t.Fatalf("%d handlers ran; the reset waiting request must not run", started)
	}
}

func TestQUICFixH3CloseReleasesWaitingStreams(t *testing.T) {
	routes := newQUICFixBlockingRoutes()
	t.Cleanup(routes.open)
	p := newQUICFixAdmissionPeer(t, Config{H2MaxRunningHandlers: 1}, func(r *Router) { r.POST("/block", routes.handler) })
	body := h3AppendDataFrame(nil, make([]byte, quicFixAdmitBody))
	for i := 0; i < 4; i++ {
		quicFixSendRequest(p, uint64(i*4), h3AppendHeadersFrame(nil, quicFixPOST("/block", quicFixAdmitBody)), body)
	}
	awaitQUICFix(t, "the first handler to start", func() bool { return routes.running.Load() >= 1 })
	turbo.Sleep(quicFixAdmitSettle)
	if p.qc.activeReqStreams.Load() != 4 {
		t.Fatalf("fixture holds %d request slots, want 4", p.qc.activeReqStreams.Load())
	}
	p.qc.close()
	routes.open()
	awaitQUICFix(t, "every request slot and body byte to be released", func() bool {
		return p.qc.activeReqStreams.Load() == 0 && p.qc.bodyReserved.Load() == 0
	})
	if started := routes.started.Load(); started != 1 {
		t.Fatalf("%d handlers ran after close, want only the one that was running", started)
	}
}

func TestQUICFixH3PendingWriteGateHoldsNewHandlers(t *testing.T) {
	big := make([]byte, quicFixAdmitBigBody)
	var fast atomic.Int32
	p := newQUICFixAdmissionPeer(t, Config{MaxPendingWriteBytes: quicFixAdmitPendingCap}, func(r *Router) {
		r.GET("/big", func(req *Request, resp *Response) { resp.Status(200).BytesNoCopy(big) })
		r.GET("/fast", func(req *Request, resp *Response) { fast.Add(1); resp.Status(200).String("ok") })
	})
	p.qc.writeMu.Lock()
	p.qc.maxDataRemote = quicFixUnlimitedFlowLimit
	p.qc.peerStreamWindow = quicFixUnlimitedFlowLimit
	p.qc.writeMu.Unlock()
	quicFixSendRequest(p, 0, h3AppendHeadersFrame(nil, quicFixGET("/big")))
	awaitQUICFix(t, "the big response to be held back", func() bool { return p.qc.stalledSendBytes.Load() >= quicFixAdmitPendingCap })
	quicFixSendRequest(p, 4, h3AppendHeadersFrame(nil, quicFixGET("/fast")))
	turbo.Sleep(quicFixAdmitSettle)
	if got := fast.Load(); got != 0 {
		t.Fatalf("a handler started while the connection held %d unsent bytes (cap %d)", p.qc.stalledSendBytes.Load(), quicFixAdmitPendingCap)
	}
	p.awaitFinsAcking([]uint64{0, 4})
	if got := fast.Load(); got != 1 {
		t.Fatalf("the held request ran %d times after the bytes drained, want 1", got)
	}
}

func newQUICFixGatedWritePeer(t *testing.T) (*quicTestPeer, *atomic.Int32) {
	t.Helper()
	big := make([]byte, quicFixAdmitBigBody)
	fast := &atomic.Int32{}
	p := newQUICFixAdmissionPeer(t, Config{MaxPendingWriteBytes: quicFixAdmitPendingCap}, func(r *Router) {
		r.GET("/big", func(req *Request, resp *Response) { resp.Status(200).BytesNoCopy(big) })
		r.GET("/fast", func(req *Request, resp *Response) { fast.Add(1); resp.Status(200).String("ok") })
	})
	p.qc.writeMu.Lock()
	p.qc.maxDataRemote = quicFixUnlimitedFlowLimit
	p.qc.peerStreamWindow = quicFixUnlimitedFlowLimit
	p.qc.writeMu.Unlock()
	quicFixSendRequest(p, 0, h3AppendHeadersFrame(nil, quicFixGET("/big")))
	awaitQUICFix(t, "the big response to be held back", func() bool { return p.qc.stalledSendBytes.Load() >= quicFixAdmitPendingCap })
	quicFixSendRequest(p, 4, h3AppendHeadersFrame(nil, quicFixGET("/fast")))
	turbo.Sleep(quicFixAdmitSettle)
	if got := fast.Load(); got != 0 {
		t.Fatalf("fixture: a handler started while %d bytes were held back", p.qc.stalledSendBytes.Load())
	}
	return p, fast
}

func TestQUICFixH3StopSendingOfAHeldResponseAdmitsTheWaitingRequest(t *testing.T) {
	p, fast := newQUICFixGatedWritePeer(t)
	p.send(quicAppendStopSendingFrame(nil, 0, h3ErrRequestRejected))
	awaitQUICFix(t, "the waiting request to start after the held response was reset", func() bool { return fast.Load() == 1 })
}

func TestQUICFixH3StallResetOnTheTimerAdmitsTheWaitingRequest(t *testing.T) {
	p, fast := newQUICFixGatedWritePeer(t)
	p.qc.stallSoftCap = quicFixAdmitPendingCap / 2
	now := turbo.UnixNano()
	p.backdateStall(0, quicFixStallTimeoutPlus)
	p.qc.lastSendProgress.Store(now - int64(quicFixStallTimeoutPlus))
	p.tickAt(now)
	awaitQUICFix(t, "the waiting request to start after the stall reset", func() bool { return fast.Load() == 1 })
}
