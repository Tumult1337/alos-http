//go:build linux && amd64

package core

import (
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/guno1928/alosmap"
)

const (
	inlineSlowRun           = 2 * time.Millisecond
	inlineRepromoteRuns     = 256
	inlineRepromoteMaxShift = 12
)

type inlineRoute struct {
	demoted    atomic.Bool
	structural atomic.Bool
	demotions  atomic.Int32
	fastRuns   atomic.Int64
}

func (rt *Route) Inline() *Route {
	if rt.node != nil && rt.node.handler != nil {
		rt.node.inline = true
	}
	return rt
}

func handlerIdentity(h HandlerFunc) uintptr {
	return *(*uintptr)(unsafe.Pointer(&h))
}

func (r *Router) registerInline(h HandlerFunc) HandlerFunc {
	unique := func(req *Request, resp *Response) { h(req, resp) }
	if r.inlineHandlers == nil {
		r.inlineHandlers = alosmap.NewTyped[uintptr, bool]()
	}
	r.inlineHandlers.Store(handlerIdentity(unique), true)
	return unique
}

func (r *Router) hasInlineRoutes() bool {
	return r.built.Load() && r.inlineHandlers != nil
}

func (r *Router) isInlineRoute(handler HandlerFunc) bool {
	if !r.hasInlineRoutes() {
		return false
	}
	_, inline := r.inlineHandlers.Load(handlerIdentity(handler))
	return inline
}

func (r *Router) lookupInline(method, path string, req *Request) (HandlerFunc, bool) {
	handler := r.Lookup(method, path, req)
	return handler, r.isInlineRoute(handler)
}

func (r *Router) demotedInline(id uintptr) (*inlineRoute, bool) {
	if r.inlineDemotedLive.Load() == 0 {
		return nil, false
	}
	st, ok := r.inlineDemoted.Load().Load(id)
	if !ok || !st.demoted.Load() {
		return nil, false
	}
	if st.structural.Load() {
		return nil, true
	}
	return st, true
}

func (r *Router) inlineRouteState(id uintptr) *inlineRoute {
	routes := r.inlineDemoted.Load()
	if routes == nil {
		r.inlineDemoted.CompareAndSwap(nil, alosmap.NewTyped[uintptr, *inlineRoute]())
		routes = r.inlineDemoted.Load()
	}
	if st, ok := routes.Load(id); ok {
		return st
	}
	st, _ := routes.LoadOrStore(id, &inlineRoute{})
	return st
}

func (r *Router) demoteInline(id uintptr, structural bool) {
	st := r.inlineRouteState(id)
	if structural {
		st.structural.Store(true)
	}
	st.fastRuns.Store(0)
	if st.demoted.CompareAndSwap(false, true) {
		st.demotions.Add(1)
		r.inlineDemotedLive.Add(1)
	}
}

func (r *Router) observeDemoted(st *inlineRoute, elapsed time.Duration) {
	if elapsed >= inlineSlowRun {
		st.fastRuns.Store(0)
		return
	}
	shift := min(st.demotions.Load()-1, inlineRepromoteMaxShift)
	if st.fastRuns.Add(1) < int64(inlineRepromoteRuns)<<max(shift, 0) {
		return
	}
	st.fastRuns.Store(0)
	if !st.structural.Load() && st.demoted.CompareAndSwap(true, false) {
		r.inlineDemotedLive.Add(-1)
	}
}
