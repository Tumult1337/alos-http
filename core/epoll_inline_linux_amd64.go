//go:build linux && amd64

package core

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/turbo"
)

const (
	inlineWatchTick      = time.Millisecond
	inlineWatchIdleTicks = 100
	inlineBatchBudget    = 2 * time.Millisecond
	inlineHandedOff      = ^uint64(0)
)

var errEpollLoopHandedOff = errors.New("epoll: event loop handed to a successor")

var inlineHandoffs atomic.Uint64

type inlineTask struct {
	conn   *epollConn
	stream *H2Stream
	ws     *wsLoopConn
	route  uintptr
}

type inlineWatchdog struct {
	mu      sync.Mutex
	workers []*epollWorker
	active  bool
	_       [CacheLineSize]byte
	parked  atomic.Bool
	_       [CacheLineSize]byte
	wake    chan struct{}
	ticks   atomic.Uint64
	wakeups atomic.Uint64
}

func (s *Server) inlineDispatchEnabled() bool {
	return s.config.InlineHandlers || !s.config.DisableInlineHandlers
}

func (iw *inlineWatchdog) add(w *epollWorker) {
	iw.mu.Lock()
	if iw.wake == nil {
		iw.wake = make(chan struct{}, 1)
	}
	iw.workers = append(iw.workers, w)
	start := !iw.active
	iw.active = true
	iw.mu.Unlock()
	if start {
		go iw.run()
	}
}

func (iw *inlineWatchdog) remove(w *epollWorker) {
	iw.mu.Lock()
	for i, cur := range iw.workers {
		if cur == w {
			last := len(iw.workers) - 1
			iw.workers[i] = iw.workers[last]
			iw.workers[last] = nil
			iw.workers = iw.workers[:last]
			break
		}
	}
	iw.signal()
	iw.mu.Unlock()
}

func (iw *inlineWatchdog) signal() {
	select {
	case iw.wake <- struct{}{}:
	default:
	}
}

func (iw *inlineWatchdog) run() {
	idle := 0
	for {
		turbo.Sleep(inlineWatchTick)
		iw.ticks.Add(1)
		busy, live := iw.scan()
		if !live {
			return
		}
		if busy {
			idle = 0
			continue
		}
		if idle++; idle < inlineWatchIdleTicks {
			continue
		}
		idle = 0
		if !iw.park() {
			return
		}
	}
}

func (iw *inlineWatchdog) park() bool {
	select {
	case <-iw.wake:
	default:
	}
	iw.parked.Store(true)
	busy, live := iw.scan()
	if !live {
		return false
	}
	if !busy {
		<-iw.wake
		iw.wakeups.Add(1)
	}
	iw.parked.Store(false)
	_, live = iw.scan()
	return live
}

func (iw *inlineWatchdog) scan() (busy, live bool) {
	iw.mu.Lock()
	defer iw.mu.Unlock()
	if len(iw.workers) == 0 {
		iw.parked.Store(false)
		iw.active = false
		return false, false
	}
	for _, w := range iw.workers {
		if w.checkInlineStall() {
			busy = true
		}
	}
	return busy, true
}

func (w *epollWorker) checkInlineStall() bool {
	run := w.inlineRun.Load()
	if run == 0 || run == inlineHandedOff {
		w.inlineSeen = 0
		return false
	}
	if run != w.inlineSeen {
		w.inlineSeen = run
		return true
	}
	w.inlineSeen = 0
	w.handOff(run, false)
	return false
}

func (w *epollWorker) handOff(seq uint64, structural bool) {
	if !w.inlineRun.CompareAndSwap(seq, inlineHandedOff) {
		return
	}
	if ev := w.inlineWS.Load(); ev != nil {
		ev.revokeLoop()
	}
	w.server.Router.demoteInline(w.inlineRoute, structural)
	inlineHandoffs.Add(1)
	w.resumed = true
	go w.runSuccessor()
}

func (w *epollWorker) runSuccessor() {
	if err := w.run(); err != errEpollLoopHandedOff {
		w.loopErr <- err
	}
}

func (w *epollWorker) leaveInline(seq *uint64) {
	if s := *seq; s != 0 {
		*seq = 0
		w.handOff(s, true)
	}
}

func (w *epollWorker) endInlineHandler(seq *uint64, exiting bool) {
	s := *seq
	*seq = 0
	if exiting && s != 0 {
		w.handOff(s, false)
	}
}

func (w *epollWorker) inlinePending() bool {
	return w.inlineHead < len(w.inlineQ)
}

func (w *epollWorker) inlineCandidate() bool {
	srv := w.server
	if !w.inlineAll && !srv.Router.hasInlineRoutes() {
		return false
	}
	return srv.proxy.Load() == nil && srv.httpRouter.Load() == nil
}

func (w *epollWorker) pickInline(req *Request) (HandlerFunc, *inlineRoute, bool) {
	r := w.server.Router
	handler := r.Lookup(req.Method, req.Path, req)
	if !w.inlineAll && !r.isInlineRoute(handler) {
		return handler, nil, false
	}
	if route, demoted := r.demotedInline(handlerIdentity(handler)); demoted {
		return handler, route, false
	}
	return handler, nil, true
}

func (w *epollWorker) queueH1Inline(c *epollConn) bool {
	handler, route, inline := w.pickInline(&c.req)
	if c.h1DispatchFast {
		c.h1Handler = handler
	}
	c.h1Route = route
	if !inline {
		return false
	}
	w.inlineQ = append(w.inlineQ, inlineTask{conn: c, route: handlerIdentity(handler)})
	return true
}

func (w *epollWorker) queueH2Inline(s *H2Stream) bool {
	handler, route, inline := w.pickInline(&s.req)
	s.handler = handler
	s.route = route
	if !inline {
		return false
	}
	w.inlineQ = append(w.inlineQ, inlineTask{stream: s, route: handlerIdentity(handler)})
	return true
}

func (w *epollWorker) runInlineQueue() bool {
	for w.inlineHead < len(w.inlineQ) {
		t := w.inlineQ[w.inlineHead]
		w.inlineQ[w.inlineHead] = inlineTask{}
		w.inlineHead++
		if turbo.Now() > w.inlineDeadline {
			w.spillInline(t)
			continue
		}
		w.inlineSeq++
		seq := w.inlineSeq
		w.inlineRoute = t.route
		w.markInlineWS(t.ws)
		w.inlineRun.Store(seq)
		if w.server.inlineWatch.parked.Load() {
			w.server.inlineWatch.signal()
		}
		switch {
		case t.ws != nil:
			t.ws.inlineSeq = seq
			t.ws.lendLoop()
			t.ws.runCallback(true)
		case t.stream != nil:
			w.inlineRan = true
			t.stream.inlineSeq = seq
			t.stream.run(true)
		default:
			w.inlineRan = true
			t.conn.h1InlineSeq = seq
			t.conn.runH1(true)
		}
		if !w.inlineRun.CompareAndSwap(seq, 0) {
			if t.ws != nil {
				w.pushWSDone(t.ws)
			}
			return false
		}
		if t.ws != nil {
			w.finishWSCallback(t.ws)
		}
	}
	w.inlineQ = w.inlineQ[:0]
	w.inlineHead = 0
	return true
}

func (w *epollWorker) markInlineWS(ev *wsLoopConn) {
	if ev == nil && !w.inlineWSSet {
		return
	}
	w.inlineWS.Store(ev)
	w.inlineWSSet = ev != nil
}

func (w *epollWorker) spillInline(t inlineTask) {
	w.spawned++
	if t.ws != nil {
		w.handlers.run(t.ws.callbackRunner())
		return
	}
	if t.stream != nil {
		w.handlers.run(t.stream.asyncRunner())
		return
	}
	w.handlers.run(t.conn.h1AsyncRunner())
}
