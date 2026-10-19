//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func proxyFixH1Status(t *testing.T, addr, raw string) int {
	t.Helper()
	resp, _ := proxyFixRoundTrip(t, addr, raw)
	return resp.StatusCode
}

func proxyFixH2Status(t *testing.T, addr, path string) string {
	t.Helper()
	c := proxyFixH2cDial(t, addr)
	defer c.Close()
	if _, err := c.Write(proxyFixH2Request(1, "GET", proxyFixDomain, path)); err != nil {
		t.Fatalf("write h2 request: %v", err)
	}
	return c.collect(t, 1)[1].status
}

func TestProxyFixServerOnRequestHookGuardsProxiedDomain(t *testing.T) {
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.OnRequest(func(req *Request, resp *Response) bool {
			resp.Status(http.StatusForbidden).String("denied")
			return false
		})
	})
	if got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/admin")); got != http.StatusForbidden {
		t.Fatalf("h1 proxied request with a denying OnRequest hook: status %d, want 403", got)
	}
	if got := proxyFixH2Status(t, addr, "/admin"); got != "403" {
		t.Fatalf("h2 proxied request with a denying OnRequest hook: status %q, want 403", got)
	}
	if n := o.hits.Load(); n != 0 {
		t.Fatalf("origin served %d requests the server hook denied", n)
	}
}

func TestProxyFixRateLimitGuardsProxiedDomain(t *testing.T) {
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.RateLimit = NewRateLimitEngine()
		s.RateLimit.SetRules([]RateLimitRule{{Path: "/*", MaxReqs: 1, Window: time.Minute}})
	})
	statuses := []int{
		proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/a")),
		proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/b")),
		proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/c")),
	}
	if statuses[len(statuses)-1] != http.StatusTooManyRequests {
		t.Fatalf("proxied statuses under a 1-request rate limit: %v, want the last to be 429", statuses)
	}
}

func proxyFixHoldOne(t *testing.T, addr, xff string) func() {
	t.Helper()
	c := proxyFixDial(t, addr)
	_ = c.SetDeadline(time.Time{})
	req := "GET /held HTTP/1.1\r\nHost: " + proxyFixDomain + "\r\n"
	if xff != "" {
		req += "X-Forwarded-For: " + xff + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		t.Fatalf("write held request: %v", err)
	}
	return func() {
		_ = c.SetReadDeadline(wallDeadline(proxyFixIOTimeout))
		_, _ = http.ReadResponse(bufio.NewReader(c), nil)
		_ = c.Close()
	}
}

func TestProxyFixPerIPRequestLimitGuardsProxiedDomain(t *testing.T) {
	o := newProxyFixHeldOrigin(t, false)
	_, addr := proxyFixStart(t, Config{ProxyMode: true, MaxRequestsPerIP: 1}, proxyFixSingleBackend(o.addr()), nil)
	const client = "203.0.113.50"
	finish := proxyFixHoldOne(t, addr, client)
	proxyFixEventually(t, "first request in flight", func() bool { return o.received.Load() == 1 })
	got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/second", "X-Forwarded-For: "+client))
	o.releaseOnce()
	finish()
	if got != http.StatusTooManyRequests {
		t.Fatalf("second concurrent proxied request from %s with MaxRequestsPerIP=1: status %d, want 429", client, got)
	}
	if got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/third", "X-Forwarded-For: "+client)); got != http.StatusOK {
		t.Fatalf("request after the first completed: status %d, want 200 (slot not released)", got)
	}
}

func TestProxyFixMaxConcurrentReqsGuardsProxiedDomain(t *testing.T) {
	o := newProxyFixHeldOrigin(t, false)
	_, addr := proxyFixStart(t, Config{MaxConcurrentReqs: 1}, proxyFixSingleBackend(o.addr()), nil)
	finish := proxyFixHoldOne(t, addr, "")
	proxyFixEventually(t, "first request in flight", func() bool { return o.received.Load() == 1 })
	got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/second"))
	o.releaseOnce()
	finish()
	if got != http.StatusServiceUnavailable {
		t.Fatalf("second concurrent proxied request with MaxConcurrentReqs=1: status %d, want 503", got)
	}
	if got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/third")); got != http.StatusOK {
		t.Fatalf("request after the first completed: status %d, want 200 (slot not released)", got)
	}
}

type proxyFixHookPanicCase struct {
	name       string
	tune       func(pe *ProxyEngine)
	path       string
	deadOrigin bool
}

const (
	proxyFixBufferedPath = "/cl/16"
	proxyFixStreamedPath = "/cl/1048576"
)

var proxyFixUnallocatedHookCounters map[string]int

func proxyFixHookFault() { proxyFixUnallocatedHookCounters["boom"]++ }

func proxyFixHookPanicCases() []proxyFixHookPanicCase {
	boom := proxyFixHookFault
	onResponse := func(pe *ProxyEngine) { pe.OnResponse = func(pr *ProxyResponse) { boom() } }
	return []proxyFixHookPanicCase{
		{name: "on_request", path: proxyFixBufferedPath, tune: func(pe *ProxyEngine) {
			pe.OnRequest = func(pr *ProxyRequest) bool { boom(); return true }
		}},
		{name: "on_response", path: proxyFixBufferedPath, tune: onResponse},
		{name: "on_response_streamed", path: proxyFixStreamedPath, tune: onResponse},
		{name: "on_error", path: proxyFixBufferedPath, deadOrigin: true, tune: func(pe *ProxyEngine) {
			pe.OnError = func(e ProxyError) { boom() }
		}},
	}
}

func proxyFixAssertBackendsIdle(t *testing.T, srv *Server, what string) {
	t.Helper()
	ds := srv.proxy.Load().Lookup(proxyFixDomain)
	idle := func() bool {
		for _, b := range ds.backends {
			if b.ActiveConns.Load() != 0 {
				return false
			}
		}
		return true
	}
	if !proxyFixWaitFor(idle) {
		for _, b := range ds.backends {
			t.Errorf("%s: backend %s ActiveConns=%d, want 0", what, b.Addr, b.ActiveConns.Load())
		}
		t.FailNow()
	}
}

func TestProxyFixPanickingProxyHookFailsOnlyThatRequest(t *testing.T) {
	for _, tc := range proxyFixHookPanicCases() {
		t.Run(tc.name, func(t *testing.T) {
			backend := proxyFixShapedOrigin(t, nil).addr()
			if tc.deadOrigin {
				backend = proxyFixRefusedAddr(t)
			}
			srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(backend), func(s *Server) { tc.tune(s.proxy.Load()) })
			for i := 0; i < 2; i++ {
				target := tc.path + "?i=" + strconv.Itoa(i)
				got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, target))
				if got < http.StatusInternalServerError {
					t.Fatalf("request %d with a panicking %s hook: status %d, want a 5xx", i, tc.name, got)
				}
				if h2 := proxyFixH2Status(t, addr, target); h2 == "" || h2[0] != '5' {
					t.Fatalf("h2 request %d with a panicking %s hook: status %q, want a 5xx", i, tc.name, h2)
				}
			}
			proxyFixAssertBackendsIdle(t, srv, tc.name)
			proxyFixAssertConnsDrain(t, srv, tc.name)
		})
	}
}

func TestProxyFixPanickingCacheHitHookFailsOnlyThatRequest(t *testing.T) {
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	var armed atomic.Bool
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.SetProxyCache(DefaultProxyCacheConfig())
		s.proxy.Load().OnResponse = func(pr *ProxyResponse) {
			if armed.Load() && pr.Backend == "cache" {
				proxyFixHookFault()
			}
		}
	})
	if got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/cached")); got != http.StatusOK {
		t.Fatalf("priming request: %d", got)
	}
	armed.Store(true)
	if got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/cached")); got < http.StatusInternalServerError {
		t.Fatalf("cache hit with a panicking OnResponse hook: status %d, want a 5xx", got)
	}
	if h2 := proxyFixH2Status(t, addr, "/cached"); h2 == "" || h2[0] != '5' {
		t.Fatalf("h2 cache hit with a panicking OnResponse hook: status %q, want a 5xx", h2)
	}
}

const proxyFixCORSOrigin = "https://app.example"

func TestProxyFixServerResponseControlsApplyToProxiedDomain(t *testing.T) {
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	var calls atomic.Int64
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.SetCORS(CORSConfig{AllowOrigins: []string{proxyFixCORSOrigin}})
		s.OnResponse(func(req *Request, resp *Response) {
			calls.Add(1)
			resp.SetHeader("X-Server-Hook", "seen")
		})
	})
	resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/page", "Origin: "+proxyFixCORSOrigin))
	if resp.StatusCode != http.StatusOK || body != "ORIGIN:/page" {
		t.Fatalf("h1 proxied response: status %d body %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Server-Hook"); got != "seen" {
		t.Fatalf("h1 proxied response skipped the server OnResponse hook: X-Server-Hook=%q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != proxyFixCORSOrigin {
		t.Fatalf("h1 proxied response skipped CORS: Access-Control-Allow-Origin=%q", got)
	}
	c := proxyFixH2cDial(t, addr)
	defer c.Close()
	if _, err := c.Write(proxyFixH2Request(1, "GET", proxyFixDomain, "/page2")); err != nil {
		t.Fatalf("write h2 request: %v", err)
	}
	if r := c.collect(t, 1)[1]; r.status != "200" || string(r.body) != "ORIGIN:/page2" {
		t.Fatalf("h2 proxied response: status %q body %q", r.status, r.body)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("server OnResponse hook ran %d times for 2 proxied requests", n)
	}
}

func proxyFixUpgradeRequest(path string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: " + proxyFixDomain + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
}

func TestProxyFixServerOnRequestHookGuardsProxiedUpgrade(t *testing.T) {
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.OnRequest(func(req *Request, resp *Response) bool {
			resp.Status(http.StatusForbidden).String("denied")
			return false
		})
	})
	resp, _ := proxyFixRoundTrip(t, addr, proxyFixUpgradeRequest("/ws"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("upgrade with a denying OnRequest hook: status %d, want 403", resp.StatusCode)
	}
	if n := o.hits.Load(); n != 0 {
		t.Fatalf("origin served %d upgrade requests the server hook denied", n)
	}
}

const proxyFixTunnelProbe = "ping-through-tunnel"

func TestProxyFixUpgradeStillTunnelsWithServerHooks(t *testing.T) {
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf := make([]byte, len(proxyFixTunnelProbe))
		if _, err := io.ReadFull(br, buf); err == nil {
			_, _ = conn.Write(buf)
		}
	})
	var requestHooks atomic.Int64
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.OnRequest(func(req *Request, resp *Response) bool { requestHooks.Add(1); return true })
		s.OnResponse(func(req *Request, resp *Response) {})
	})
	c := proxyFixDial(t, addr)
	defer c.Close()
	if _, err := io.WriteString(c, proxyFixUpgradeRequest("/ws")); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade with server hooks set: status %d, want 101", resp.StatusCode)
	}
	if _, err := io.WriteString(c, proxyFixTunnelProbe); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	echo := make([]byte, len(proxyFixTunnelProbe))
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != proxyFixTunnelProbe {
		t.Fatalf("tunnel echo %q err %v", echo, err)
	}
	if n := requestHooks.Load(); n != 1 {
		t.Fatalf("server OnRequest hook ran %d times for one upgrade", n)
	}
}
