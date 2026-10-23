//go:build linux && amd64

package core

import "net/http"

type timeoutAdmission struct {
	srv    *Server
	ipSlot *ipReqCounter
}

func (s *Server) admitTimeoutHandler(req *Request) (*timeoutAdmission, int) {
	if s == nil {
		return nil, 0
	}
	limits := s.limits.Load()
	if running := s.timeoutHandlers.Add(1); limits.MaxConns > 0 && running > limits.MaxConns {
		s.timeoutHandlers.Add(-1)
		return nil, http.StatusServiceUnavailable
	}
	admission := &timeoutAdmission{srv: s}
	if perIP := s.timeoutPerIPLimit(limits); perIP > 0 {
		slot, ok := s.timeoutIPLimiter().hold(extractIP(req.RemoteAddr), perIP)
		if !ok {
			s.timeoutHandlers.Add(-1)
			return nil, http.StatusTooManyRequests
		}
		admission.ipSlot = slot
	}
	return admission, 0
}

func (s *Server) timeoutPerIPLimit(limits *Limits) int64 {
	if s.trustedProxies.active {
		return s.perIPRequestLimit()
	}
	return limits.MaxConnsPerIP
}

func (a *timeoutAdmission) release() {
	if a == nil {
		return
	}
	if a.ipSlot != nil {
		a.ipSlot.release()
	}
	a.srv.timeoutHandlers.Add(-1)
}

func (s *Server) timeoutIPLimiter() *perIPLimiter {
	if l := s.timeoutPerIP.Load(); l != nil {
		return l
	}
	fresh := newPerIPRequestLimiter()
	if !s.timeoutPerIP.CompareAndSwap(nil, fresh) {
		fresh.Stop()
	}
	return s.timeoutPerIP.Load()
}

type detachedWorkHold struct {
	srv     *Server
	reqSlot bool
	ipSlot  *ipReqCounter
}

func (s *Server) holdDetachedWork(req *Request) *detachedWorkHold {
	if s == nil {
		return nil
	}
	hold := &detachedWorkHold{srv: s}
	if s.config.MaxConcurrentReqs > 0 {
		s.activeReqs.Add(1)
		hold.reqSlot = true
	}
	hold.ipSlot = s.perIPLimiter.holdAlive(extractIP(req.RemoteAddr))
	return hold
}

func (h *detachedWorkHold) release() {
	if h == nil {
		return
	}
	if h.ipSlot != nil {
		h.ipSlot.release()
	}
	if h.reqSlot {
		h.srv.releaseRequestSlot()
	}
}

func (l *perIPLimiter) count(ip string) int64 {
	if l == nil || ip == "" {
		return 0
	}
	c, ok := l.m.Load(ip)
	if !ok {
		return 0
	}
	return max(c.n.Load(), 0)
}

func (l *perIPLimiter) holdAlive(ip string) *ipReqCounter {
	if l == nil || ip == "" {
		return nil
	}
	c, ok := l.m.Load(ip)
	if !ok {
		return nil
	}
	for {
		cur := c.n.Load()
		if cur <= 0 {
			return nil
		}
		if c.n.CompareAndSwap(cur, cur+1) {
			return c
		}
	}
}
