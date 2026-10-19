//go:build linux && amd64

package core

import (
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

const proxyFix2OnLimitPanic = "proxy fix2: OnLimit hook panicked"

func proxyFix2StartPanickingOnLimit(t *testing.T) (*Server, string, *atomic.Bool) {
	t.Helper()
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	armed := &atomic.Bool{}
	srv, addr := proxyFixStart(t, Config{MaxRequestsPerIP: 1, MaxConcurrentReqs: 1}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.RateLimit = NewRateLimitEngine()
		s.RateLimit.SetRules([]RateLimitRule{{Path: "/*", MaxReqs: 1, Window: time.Minute, OnLimit: func(RateLimitEvent, *Request, *Response) bool {
			if armed.Load() {
				panic(proxyFix2OnLimitPanic)
			}
			return false
		}}})
	})
	return srv, addr, armed
}

func proxyFix2AssertAdmissionReleased(t *testing.T, srv *Server) {
	t.Helper()
	released := func() bool {
		if srv.activeReqs.Load() != 0 {
			return false
		}
		held := false
		srv.perIPLimiter.m.Range(func(_ string, c *ipReqCounter) bool {
			held = c.n.Load() > 0
			return !held
		})
		return !held
	}
	if !proxyFixWaitFor(released) {
		t.Fatalf("admission slots leaked: activeReqs=%d after every request finished", srv.activeReqs.Load())
	}
}

func TestProxyFix2PanickingOnLimitReleasesAdmissionH1(t *testing.T) {
	srv, addr, armed := proxyFix2StartPanickingOnLimit(t)
	if got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/first")); got != http.StatusOK {
		t.Fatalf("first request: status %d, want 200", got)
	}
	armed.Store(true)
	c := proxyFixDial(t, addr)
	_, _ = io.WriteString(c, proxyFixGet(proxyFixDomain, "/limited"))
	out, _ := io.ReadAll(c)
	c.Close()
	if want := "HTTP/1.1 " + strconv.Itoa(http.StatusInternalServerError); len(out) < len(want) || string(out[:len(want)]) != want {
		t.Errorf("rate-limited request with a panicking OnLimit: response %q, want a 500", firstLine(string(out)))
	}
	armed.Store(false)
	if got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/after")); got != http.StatusTooManyRequests {
		t.Fatalf("request after the OnLimit panic: status %d, want 429 (503 means the request slot leaked)", got)
	}
	proxyFix2AssertAdmissionReleased(t, srv)
}

func TestProxyFix2PanickingOnLimitReleasesAdmissionH2(t *testing.T) {
	srv, addr, armed := proxyFix2StartPanickingOnLimit(t)
	if got := proxyFixH2Status(t, addr, "/first"); got != "200" {
		t.Fatalf("first h2 request: status %q, want 200", got)
	}
	armed.Store(true)
	if got := proxyFixH2Status(t, addr, "/limited"); got != strconv.Itoa(http.StatusInternalServerError) {
		t.Fatalf("rate-limited h2 request with a panicking OnLimit: status %q, want 500", got)
	}
	armed.Store(false)
	if got := proxyFixH2Status(t, addr, "/after"); got != strconv.Itoa(http.StatusTooManyRequests) {
		t.Fatalf("h2 request after the OnLimit panic: status %q, want 429 (503 means the request slot leaked)", got)
	}
	proxyFix2AssertAdmissionReleased(t, srv)
}

func proxyFix2BenchRateLimitRefused(b *testing.B, rl *RateLimitEngine) {
	s := New(Config{Addr: "127.0.0.1:0", PlainHTTP: true})
	if rl != nil {
		defer rl.Stop()
		s.rateLimitEngine.Store(rl)
	}
	req := &Request{Method: "GET", Path: "/x", RemoteAddr: "192.0.2.7:51234"}
	resp := &Response{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if s.rateLimitRefused("192.0.2.7", req, resp) {
			b.Fatal("refused")
		}
	}
}

func BenchmarkProxyFix2RateLimitRefusedNoEngine(b *testing.B) {
	proxyFix2BenchRateLimitRefused(b, nil)
}

func BenchmarkProxyFix2RateLimitRefusedAllowed(b *testing.B) {
	rl := NewRateLimitEngine()
	rl.SetRules([]RateLimitRule{{Path: "/*", MaxReqs: 1 << 62, Window: time.Hour}})
	proxyFix2BenchRateLimitRefused(b, rl)
}

func BenchmarkProxyFix2ProxiedRateLimitRefusedAllowed(b *testing.B) {
	rl := NewRateLimitEngine()
	defer rl.Stop()
	rl.SetRules([]RateLimitRule{{Path: "/*", MaxReqs: 1 << 62, Window: time.Hour}})
	s := New(Config{Addr: "127.0.0.1:0", PlainHTTP: true})
	s.rateLimitEngine.Store(rl)
	w := &epollWorker{server: s}
	req := &Request{Method: "GET", Path: "/x", RemoteAddr: "192.0.2.7:51234"}
	resp := &Response{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if w.proxiedRateLimitOutcome("192.0.2.7", req, resp) != proxyAdmitted {
			b.Fatal("refused")
		}
	}
}
