//go:build linux && amd64

package core

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

type gatedRoutes struct {
	entered atomic.Int32
	release chan struct{}
}

func newGatedRoutes() *gatedRoutes {
	return &gatedRoutes{release: make(chan struct{}, quicMaxBidiStreams*2)}
}

func (g *gatedRoutes) route(r *Router) {
	r.GET("/gate", func(req *Request, resp *Response) {
		g.entered.Add(1)
		<-g.release
		resp.Status(200).String("gated")
	})
}

func (g *gatedRoutes) awaitEntered(t *testing.T, n int32) {
	t.Helper()
	deadline := turbo.Deadline(quicPeerWait)
	for g.entered.Load() < n {
		if turbo.Until(deadline) <= 0 {
			t.Fatalf("%d of %d handlers started", g.entered.Load(), n)
		}
		turbo.Sleep(quicPeerPoll)
	}
}

func (p *quicTestPeer) finCount() int {
	n := 0
	for _, s := range p.pump().streams {
		if s.fin && quicStreamIsBidi(s.streamID) {
			n++
		}
	}
	return n
}

func (p *quicTestPeer) awaitFinCount(n int) {
	p.t.Helper()
	deadline := turbo.Deadline(quicPeerWait)
	for p.finCount() < n {
		if turbo.Until(deadline) <= 0 {
			p.t.Fatalf("%d of %d responses finished", p.finCount(), n)
		}
		turbo.Sleep(quicPeerPoll)
	}
}

func openGatedStreams(p *quicTestPeer, from, count uint64) {
	req := h3TestRequest("/gate")
	for i := from; i < from+count; i++ {
		p.send(quicStreamBytes(i<<2, 0, req, true))
	}
}

func TestQUICStreamLimitAdvertisement(t *testing.T) {
	qc := newTestQUIC(New(Config{}))
	tp := quicBuildTransportParams(qc)
	if got, ok := decodeQUICTP(tp, quicTPInitialMaxStreamsBidi); !ok || got != quicMaxConcurrentReqStreams {
		t.Fatalf("initial_max_streams_bidi = %d (ok=%v), want %d", got, ok, quicMaxConcurrentReqStreams)
	}
	if got, ok := decodeQUICTP(tp, quicTPInitialMaxStreamsUni); !ok || got != 16 {
		t.Fatalf("initial_max_streams_uni = %d (ok=%v), want 16", got, ok)
	}
	if quicMaxTrackedStreams != quicMaxBidiStreams+quicMaxUniStreams+32 {
		t.Fatalf("tracked stream cap %d does not follow the advertised limits", quicMaxTrackedStreams)
	}
}

func TestQUICStreamLimitFullWindowThenCreditReturns(t *testing.T) {
	g := newGatedRoutes()
	p := newQUICTestPeer(t, g.route)
	openGatedStreams(p, 0, quicMaxBidiStreams)
	g.awaitEntered(t, quicMaxBidiStreams)

	for i := 0; i < quicMaxStreamsCreditBatch; i++ {
		g.release <- struct{}{}
	}
	p.awaitFinCount(quicMaxStreamsCreditBatch)
	got := p.awaitSent("MAX_STREAMS", func(f quicSentFrames) bool { return len(f.maxStreams) > 0 })
	want := uint64(quicMaxBidiStreams + quicMaxStreamsCreditBatch)
	if m := got.maxStreams[len(got.maxStreams)-1]; !m.bidi || m.maxStreams != want {
		t.Fatalf("MAX_STREAMS = %+v, want bidi %d", m, want)
	}

	openGatedStreams(p, quicMaxBidiStreams, quicMaxStreamsCreditBatch)
	g.awaitEntered(t, quicMaxBidiStreams+quicMaxStreamsCreditBatch)
	for i := 0; i < quicMaxBidiStreams; i++ {
		g.release <- struct{}{}
	}
	p.awaitFinCount(quicMaxBidiStreams + quicMaxStreamsCreditBatch)
	p.awaitStreamCount(0)
	if got := p.sent(); len(got.closes) != 0 || len(got.resets) != 0 {
		t.Fatalf("closes %+v resets %+v", got.closes, got.resets)
	}
}

func TestQUICStreamLimitBeyondCreditIsAnError(t *testing.T) {
	g := newGatedRoutes()
	p := newQUICTestPeer(t, g.route)
	openGatedStreams(p, 0, quicMaxBidiStreams)
	g.awaitEntered(t, quicMaxBidiStreams)
	openGatedStreams(p, quicMaxBidiStreams, 1)
	p.awaitClose(quicErrStreamLimit)
	for i := 0; i < quicMaxBidiStreams; i++ {
		g.release <- struct{}{}
	}
}

func TestQUICManySequentialRequestsOnOneConnection(t *testing.T) {
	c := &countingRoutes{}
	p := newQUICTestPeer(t, c.route)
	const total = 640
	req := h3TestRequest("/count")
	deadline := turbo.Deadline(10 * time.Second)
	for i := uint64(0); i < total; i++ {
		p.send(quicStreamBytes(i<<2, 0, req, true))
		for c.hits.Load() < int32(i+1) {
			if turbo.Until(deadline) <= 0 {
				t.Fatalf("request %d never ran", i)
			}
			turbo.Sleep(time.Millisecond)
		}
		for p.streamCount() > quicMaxStreamsCreditBatch {
			if turbo.Until(deadline) <= 0 {
				t.Fatalf("streams are not being retired (%d tracked)", p.streamCount())
			}
			turbo.Sleep(time.Millisecond)
		}
	}
	p.awaitStreamCount(0)
	if got := p.sent(); len(got.closes) != 0 {
		t.Fatalf("sequential requests hit %+v", got.closes)
	}
	if p.qc.maxBidiRemote < total {
		t.Fatalf("credit only reached %d streams after %d requests", p.qc.maxBidiRemote, total)
	}
}

func TestQUICFinBeforeGapDispatchesOnceWhenComplete(t *testing.T) {
	c := &countingRoutes{}
	p := newQUICTestPeer(t, c.route)
	req := h3TestRequest("/count")
	mid := len(req) / 2
	p.send(quicStreamBytes(0, uint64(mid), req[mid:], true))
	s := p.qc.acquireStream(0)
	if s == nil {
		t.Fatal("tail frame did not open stream 0")
	}
	dispatched := s.dispatched.Load()
	p.qc.releaseStream(s)
	if dispatched {
		t.Fatal("request dispatched before the gap was filled")
	}
	p.send(quicStreamBytes(0, 0, req[:mid], false))
	p.awaitFin(0)
	p.send(quicStreamBytes(0, 0, req[:mid], false))
	p.send(quicStreamBytes(0, uint64(mid), req[mid:], true))
	if got := c.hits.Load(); got != 1 {
		t.Fatalf("handler ran %d times, want 1", got)
	}
}
