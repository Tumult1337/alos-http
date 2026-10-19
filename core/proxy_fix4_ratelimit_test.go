//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	proxyFix4HugeLimit     = 1 << 40
	proxyFix4AdmittedCount = 3
	proxyFix4RefusedCount  = 3
	proxyFix4DefaultBody   = "Too Many Requests"
)

type proxyFix4LimitHookSetup struct {
	name    string
	install func(s *Server, rule func(RateLimitFunc) RateLimitRule, hook RateLimitFunc)
}

var proxyFix4LimitHookSetups = []proxyFix4LimitHookSetup{
	{"rule OnLimit", func(s *Server, rule func(RateLimitFunc) RateLimitRule, hook RateLimitFunc) {
		s.SetRateLimitRules([]RateLimitRule{rule(hook)})
	}},
	{"server OnRateLimit", func(s *Server, rule func(RateLimitFunc) RateLimitRule, hook RateLimitFunc) {
		s.SetRateLimitRules([]RateLimitRule{rule(nil)})
		s.OnRateLimit(hook)
	}},
}

func proxyFix4AdmitAllRule(onLimit RateLimitFunc) RateLimitRule {
	return RateLimitRule{Path: "/*", MaxReqs: proxyFix4HugeLimit, Window: time.Minute, OnLimit: onLimit}
}

func (p *proxyFix3HookProbe) assertOnLoop(t *testing.T, minCalls int64) {
	t.Helper()
	if n := p.calls.Load(); n < minCalls {
		t.Fatalf("in-loop probe ran %d times, want at least %d", n, minCalls)
	}
	if on, n := p.onLoop.Load(), p.calls.Load(); on != n {
		t.Fatalf("in-loop probe ran on the epoll event loop %d of %d times, want every time", on, n)
	}
}

func proxyFix4ProbeProxyRequests(s *Server, probe *proxyFix3HookProbe) {
	s.OnProxyRequest(func(pr *ProxyRequest) bool {
		probe.observe()
		return true
	})
}

func proxyFix4H2Get(t *testing.T, c *proxyFixH2Conn, streamID uint32, path string) *proxyFixH2Response {
	t.Helper()
	if _, err := c.Write(proxyFixH2Request(streamID, "GET", proxyFixDomain, path)); err != nil {
		t.Fatalf("write h2 stream %d: %v", streamID, err)
	}
	return c.collect(t, 1)[streamID]
}

func TestProxyFix4RefusedProxiedRequestRunsLimitHookOffLoop(t *testing.T) {
	for _, setup := range proxyFix4LimitHookSetups {
		t.Run(setup.name+"/h1", func(t *testing.T) {
			o := newProxyFix3UpgradeOrigin(t)
			hookProbe := &proxyFix3HookProbe{}
			_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
				setup.install(s, proxyFix3LimitRule, proxyFix3CustomLimit(hookProbe))
			})
			if resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/first")); resp.StatusCode != http.StatusOK || body != proxyFix3PlainBody {
				t.Fatalf("admitted request: status %d body %q", resp.StatusCode, body)
			}
			resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/limited"))
			if resp.StatusCode != http.StatusTooManyRequests || body != proxyFix3LimitedBody {
				t.Fatalf("refused request: status %d body %q, want the hook's 429", resp.StatusCode, body)
			}
			hookProbe.assertOffLoop(t, 1)
		})
		t.Run(setup.name+"/h2", func(t *testing.T) {
			o := newProxyFix3UpgradeOrigin(t)
			hookProbe := &proxyFix3HookProbe{}
			_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
				setup.install(s, proxyFix3LimitRule, proxyFix3CustomLimit(hookProbe))
			})
			c := proxyFixH2cDial(t, addr)
			defer c.Close()
			if r := proxyFix4H2Get(t, c, 1, "/first"); r.status != "200" || string(r.body) != proxyFix3PlainBody {
				t.Fatalf("admitted h2 request: status %q body %q", r.status, r.body)
			}
			if r := proxyFix4H2Get(t, c, 3, "/limited"); r.status != "429" || string(r.body) != proxyFix3LimitedBody {
				t.Fatalf("refused h2 request: status %q body %q, want the hook's 429", r.status, r.body)
			}
			hookProbe.assertOffLoop(t, 1)
		})
	}
}

func TestProxyFix4AdmittedProxiedRequestsStayInLoopWithLimitHooks(t *testing.T) {
	for _, setup := range proxyFix4LimitHookSetups {
		t.Run(setup.name, func(t *testing.T) {
			o := newProxyFix3UpgradeOrigin(t)
			loopProbe := &proxyFix3HookProbe{}
			hookProbe := &proxyFix3HookProbe{}
			srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
				setup.install(s, proxyFix4AdmitAllRule, proxyFix3CustomLimit(hookProbe))
				proxyFix4ProbeProxyRequests(s, loopProbe)
			})
			for i := 0; i < proxyFix4AdmittedCount; i++ {
				if resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/plain")); resp.StatusCode != http.StatusOK || body != proxyFix3PlainBody {
					t.Fatalf("h1 request %d: status %d body %q", i, resp.StatusCode, body)
				}
			}
			c := proxyFixH2cDial(t, addr)
			if r := proxyFix4H2Get(t, c, 1, "/plain"); r.status != "200" || string(r.body) != proxyFix3PlainBody {
				t.Fatalf("h2 request: status %q body %q", r.status, r.body)
			}
			_ = c.Close()
			tunnel := proxyFixDial(t, addr)
			if _, err := io.WriteString(tunnel, proxyFix3Upgrade("/ws", "websocket")+proxyFix3TunnelProbe); err != nil {
				t.Fatalf("write upgrade: %v", err)
			}
			proxyFix3ExpectTunnel(t, tunnel, bufio.NewReader(tunnel))
			proxyFix3CloseTunnel(t, srv, tunnel)
			loopProbe.assertOnLoop(t, proxyFix4AdmittedCount+2)
			if n := hookProbe.calls.Load(); n != 0 {
				t.Fatalf("limit hook ran %d times for admitted requests", n)
			}
		})
	}
}

func TestProxyFix4AdmittedRouteRequestStaysInLoopWithLimitHooks(t *testing.T) {
	for _, setup := range proxyFix4LimitHookSetups {
		t.Run(setup.name, func(t *testing.T) {
			dispatchOnly := &proxyFix3HookProbe{}
			hookProbe := &proxyFix3HookProbe{}
			_, addr, _ := proxyFix3StartRouteProxy(t, func(s *Server) {
				setup.install(s, proxyFix4AdmitAllRule, proxyFix3CustomLimit(hookProbe))
				s.OnResponse(func(req *Request, resp *Response) { dispatchOnly.observe() })
			})
			for i := 0; i < proxyFix4AdmittedCount; i++ {
				if resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFix3ClientHost, proxyFix3RoutePath)); resp.StatusCode != http.StatusOK || body != proxyFix3RouteBody {
					t.Fatalf("route request %d: status %d body %q", i, resp.StatusCode, body)
				}
			}
			if n := dispatchOnly.calls.Load(); n != 0 {
				t.Fatalf("server OnResponse, which only handler dispatch runs for a route, ran %d times: admitted route requests left the loop", n)
			}
			if n := hookProbe.calls.Load(); n != 0 {
				t.Fatalf("limit hook ran %d times for admitted requests", n)
			}
		})
	}
}

func TestProxyFix4PlainUpgradeStaysInLoop(t *testing.T) {
	loopProbe := &proxyFix3HookProbe{}
	srv, addr, _ := proxyFix3StartUpgradeProxy(t, Config{}, proxyFix3Mode{name: "in-loop"})
	proxyFix4ProbeProxyRequests(srv, loopProbe)
	c := proxyFixDial(t, addr)
	if _, err := io.WriteString(c, proxyFix3Upgrade("/ws", "websocket")+proxyFix3TunnelProbe); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	proxyFix3ExpectTunnel(t, c, bufio.NewReader(c))
	proxyFix3CloseTunnel(t, srv, c)
	loopProbe.assertOnLoop(t, 1)
}

type proxyFix4HookTrace struct {
	mu    sync.Mutex
	calls []string
	probe proxyFix3HookProbe
}

func (tr *proxyFix4HookTrace) hook(name string, handled bool) RateLimitFunc {
	return func(event RateLimitEvent, req *Request, resp *Response) bool {
		tr.probe.observe()
		tr.mu.Lock()
		tr.calls = append(tr.calls, name)
		tr.mu.Unlock()
		if handled {
			resp.Status(http.StatusTooManyRequests).String(proxyFix3LimitedBody)
		}
		return handled
	}
}

func (tr *proxyFix4HookTrace) order() string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return strings.Join(tr.calls, ",")
}

func TestProxyFix4RefusalHookOrderAndFallthroughUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ruleHandles bool
		wantOrder   string
		wantBody    string
		wantRetry   bool
	}{
		{"rule declines then global declines", false, "rule,global", proxyFix4DefaultBody, true},
		{"rule handles", true, "rule", proxyFix3LimitedBody, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newProxyFix3UpgradeOrigin(t)
			trace := &proxyFix4HookTrace{}
			_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
				s.SetRateLimitRules([]RateLimitRule{proxyFix3LimitRule(trace.hook("rule", tc.ruleHandles))})
				s.OnRateLimit(trace.hook("global", false))
			})
			if resp, _ := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/first")); resp.StatusCode != http.StatusOK {
				t.Fatalf("admitted request: status %d", resp.StatusCode)
			}
			resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/limited"))
			if resp.StatusCode != http.StatusTooManyRequests || body != tc.wantBody {
				t.Fatalf("refused request: status %d body %q, want 429 %q", resp.StatusCode, body, tc.wantBody)
			}
			if got := resp.Header.Get("Retry-After") != ""; got != tc.wantRetry {
				t.Fatalf("Retry-After present=%v, want %v (header %q)", got, tc.wantRetry, resp.Header.Get("Retry-After"))
			}
			if got := trace.order(); got != tc.wantOrder {
				t.Fatalf("hook order %q, want %q", got, tc.wantOrder)
			}
			trace.probe.assertOffLoop(t, 1)
		})
	}
}

func TestProxyFix4EachRefusalRunsHooksAndCountsOnce(t *testing.T) {
	o := newProxyFix3UpgradeOrigin(t)
	hookProbe := &proxyFix3HookProbe{}
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.SetRateLimitRules([]RateLimitRule{proxyFix3LimitRule(proxyFix3CustomLimit(hookProbe))})
	})
	if resp, _ := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/first")); resp.StatusCode != http.StatusOK {
		t.Fatalf("admitted request: status %d", resp.StatusCode)
	}
	blockedBefore := Stats.BlockedReqs.Load()
	for i := 0; i < proxyFix4RefusedCount; i++ {
		if resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/limited")); resp.StatusCode != http.StatusTooManyRequests || body != proxyFix3LimitedBody {
			t.Fatalf("refused request %d: status %d body %q", i, resp.StatusCode, body)
		}
	}
	if n := hookProbe.calls.Load(); n != proxyFix4RefusedCount {
		t.Fatalf("limit hook ran %d times for %d refused requests", n, proxyFix4RefusedCount)
	}
	if n := Stats.BlockedReqs.Load() - blockedBefore; n != proxyFix4RefusedCount {
		t.Fatalf("blocked counter rose by %d for %d refused requests", n, proxyFix4RefusedCount)
	}
	hookProbe.assertOffLoop(t, proxyFix4RefusedCount)
}
