//go:build linux && amd64

package core

import "net/http"

type detachedWorkHold struct {
	srv        *Server
	reqSlot    bool
	ipSlot     *ipReqCounter
	connIPSlot *ipReqCounter
}

func (s *Server) detachedWorkRefusal(req *Request) int {
	if s == nil {
		return 0
	}
	limits := s.limits.Load()
	if limits.MaxConns > 0 && s.detachedWork.Load() >= limits.MaxConns {
		return http.StatusServiceUnavailable
	}
	if limiter := s.perIPConnLimiter.Load(); limiter != nil && limits.MaxConnsPerIP > 0 && !s.trustedProxies.active {
		if limiter.count(extractIP(req.RemoteAddr)) > limits.MaxConnsPerIP {
			return http.StatusTooManyRequests
		}
	}
	return 0
}

func (s *Server) holdDetachedWork(req *Request) *detachedWorkHold {
	if s == nil {
		return nil
	}
	hold := &detachedWorkHold{srv: s}
	s.detachedWork.Add(1)
	if s.config.MaxConcurrentReqs > 0 {
		s.activeReqs.Add(1)
		hold.reqSlot = true
	}
	ip := extractIP(req.RemoteAddr)
	hold.ipSlot = s.perIPLimiter.holdAlive(ip)
	if !s.trustedProxies.active {
		hold.connIPSlot = s.perIPConnLimiter.Load().holdAlive(ip)
	}
	return hold
}

func (h *detachedWorkHold) release() {
	if h == nil {
		return
	}
	if h.connIPSlot != nil {
		h.connIPSlot.release()
	}
	if h.ipSlot != nil {
		h.ipSlot.release()
	}
	if h.reqSlot {
		h.srv.releaseRequestSlot()
	}
	h.srv.detachedWork.Add(-1)
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
