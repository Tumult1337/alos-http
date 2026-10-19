//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	proxyFix3StackBufSize  = 64 << 10
	proxyFix3TunnelProbe   = "probe-through-tunnel"
	proxyFix3PlainBody     = "plain-backend"
	proxyFix3DeclinedBody  = "declined"
	proxyFix3ChunkedBody   = "declined-in-chunks"
	proxyFix3LimitedBody   = "custom-limit"
	proxyFix3RouteBody     = "route-backend"
	proxyFix3HookDeniedMsg = "denied"
)

var proxyFix3LoopFrame = []byte(".(*epollWorker).run(")

func proxyFix3OnEventLoop() bool {
	buf := make([]byte, proxyFix3StackBufSize)
	return bytes.Contains(buf[:runtime.Stack(buf, false)], proxyFix3LoopFrame)
}

type proxyFix3HookProbe struct {
	calls  atomic.Int64
	onLoop atomic.Int64
}

func (p *proxyFix3HookProbe) observe() {
	p.calls.Add(1)
	if proxyFix3OnEventLoop() {
		p.onLoop.Add(1)
	}
}

func (p *proxyFix3HookProbe) assertOffLoop(t *testing.T, minCalls int64) {
	t.Helper()
	if n := p.calls.Load(); n < minCalls {
		t.Fatalf("hook ran %d times, want at least %d", n, minCalls)
	}
	if n := p.onLoop.Load(); n != 0 {
		t.Fatalf("hook ran on the epoll event loop %d of %d times, want it on a handler goroutine", n, p.calls.Load())
	}
}

func (p *proxyFix3HookProbe) onRequest(s *Server) {
	s.OnRequest(func(req *Request, resp *Response) bool {
		p.observe()
		return true
	})
}

var proxyFix3UpgradeAnswers = map[string]string{
	"/ws":                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
	"/layered":           "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket, foo/2\r\nConnection: Upgrade\r\n\r\n",
	"/h2c":               "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n",
	"/other":             "HTTP/1.1 101 Switching Protocols\r\nUpgrade: other\r\nConnection: Upgrade\r\n\r\n",
	"/no-upgrade-header": "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n",
	"/unrequested-extra": "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket, h2c\r\nConnection: Upgrade\r\n\r\n",
}

func newProxyFix3UpgradeOrigin(t *testing.T) *inloopOrigin {
	t.Helper()
	return newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		if answer, ok := proxyFix3UpgradeAnswers[req.URL.Path]; ok {
			_, _ = io.WriteString(conn, answer)
			_, _ = io.Copy(conn, br)
			return
		}
		switch req.URL.Path {
		case "/declined":
			fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\n%s", len(proxyFix3DeclinedBody), proxyFix3DeclinedBody)
		case "/declined-chunked":
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(proxyFix3ChunkedBody), proxyFix3ChunkedBody)
		default:
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(proxyFix3PlainBody), proxyFix3PlainBody)
		}
	})
}

func proxyFix3Upgrade(path, protocols string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: " + proxyFixDomain + "\r\nUpgrade: " + protocols + "\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
}

type proxyFix3Mode struct {
	name  string
	hooks bool
}

var proxyFix3Modes = []proxyFix3Mode{{name: "in-loop"}, {name: "dispatch", hooks: true}}

func proxyFix3StartUpgradeProxy(t *testing.T, cfg Config, mode proxyFix3Mode) (*Server, string, *proxyFix3HookProbe) {
	t.Helper()
	o := newProxyFix3UpgradeOrigin(t)
	probe := &proxyFix3HookProbe{}
	srv, addr := proxyFixStart(t, cfg, proxyFixSingleBackend(o.addr()), func(s *Server) {
		if mode.hooks {
			probe.onRequest(s)
		}
	})
	return srv, addr, probe
}

func proxyFix3CloseTunnel(t *testing.T, srv *Server, c net.Conn) {
	t.Helper()
	_ = c.Close()
	proxyFixEventually(t, "tunnel torn down after the client closed", func() bool { return srv.activeConns.Load() == 0 })
}

func proxyFix3ExpectTunnel(t *testing.T, c net.Conn, br *bufio.Reader) {
	t.Helper()
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d, want 101", resp.StatusCode)
	}
	echo := make([]byte, len(proxyFix3TunnelProbe))
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != proxyFix3TunnelProbe {
		t.Fatalf("tunnel echo %q, err %v", echo, err)
	}
}

func TestProxyFix3UpgradeTunnelsInBothModes(t *testing.T) {
	for _, mode := range proxyFix3Modes {
		t.Run(mode.name, func(t *testing.T) {
			srv, addr, probe := proxyFix3StartUpgradeProxy(t, Config{}, mode)
			for _, tc := range []struct{ path, protocols string }{{"/ws", "websocket"}, {"/layered", "websocket, foo/2"}} {
				c := proxyFixDial(t, addr)
				if _, err := io.WriteString(c, proxyFix3Upgrade(tc.path, tc.protocols)+proxyFix3TunnelProbe); err != nil {
					t.Fatalf("write upgrade with early tunnel bytes: %v", err)
				}
				proxyFix3ExpectTunnel(t, c, bufio.NewReader(c))
				proxyFix3CloseTunnel(t, srv, c)
			}
			if mode.hooks {
				probe.assertOffLoop(t, 2)
			}
		})
	}
}

func TestProxyFix3UpgradeRefusesUnrequestedSwitchInBothModes(t *testing.T) {
	for _, mode := range proxyFix3Modes {
		t.Run(mode.name, func(t *testing.T) {
			_, addr, probe := proxyFix3StartUpgradeProxy(t, Config{}, mode)
			for _, tc := range []struct{ path, protocols string }{
				{"/h2c", "h2c"},
				{"/other", "websocket"},
				{"/no-upgrade-header", "websocket"},
				{"/unrequested-extra", "websocket"},
			} {
				resp, _ := proxyFixRoundTrip(t, addr, proxyFix3Upgrade(tc.path, tc.protocols))
				if resp.StatusCode != http.StatusBadGateway {
					t.Errorf("%s: status %d, want 502", tc.path, resp.StatusCode)
				}
			}
			if mode.hooks {
				probe.assertOffLoop(t, 4)
			}
		})
	}
}

func TestProxyFix3DeclinedUpgradeIsAnOrdinaryResponseInBothModes(t *testing.T) {
	for _, mode := range proxyFix3Modes {
		t.Run(mode.name, func(t *testing.T) {
			_, addr, probe := proxyFix3StartUpgradeProxy(t, Config{}, mode)
			c := proxyFixDial(t, addr)
			defer c.Close()
			br := bufio.NewReader(c)
			for _, tc := range []struct {
				path   string
				status int
				body   string
			}{
				{"/declined", http.StatusForbidden, proxyFix3DeclinedBody},
				{"/declined-chunked", http.StatusOK, proxyFix3ChunkedBody},
			} {
				if _, err := io.WriteString(c, proxyFix3Upgrade(tc.path, "websocket")); err != nil {
					t.Fatalf("write: %v", err)
				}
				resp, body := proxyFixReadResponse(t, br)
				if resp.StatusCode != tc.status || body != tc.body {
					t.Fatalf("%s: status %d body %q, want %d %q", tc.path, resp.StatusCode, body, tc.status, tc.body)
				}
			}
			if _, err := io.WriteString(c, "GET /after HTTP/1.1\r\nHost: "+proxyFixDomain+"\r\n\r\n"); err != nil {
				t.Fatalf("write follow-up: %v", err)
			}
			resp, body := proxyFixReadResponse(t, br)
			if resp.StatusCode != http.StatusOK || body != proxyFix3PlainBody {
				t.Fatalf("request after declined upgrades: status %d body %q", resp.StatusCode, body)
			}
			if mode.hooks {
				probe.assertOffLoop(t, 3)
			}
		})
	}
}

func TestProxyFix3ServerOnRequestHookCanDenyDispatchedUpgrade(t *testing.T) {
	o := newProxyFix3UpgradeOrigin(t)
	probe := &proxyFix3HookProbe{}
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.OnRequest(func(req *Request, resp *Response) bool {
			probe.observe()
			resp.Status(http.StatusForbidden).String(proxyFix3HookDeniedMsg)
			return false
		})
	})
	resp, body := proxyFixRoundTrip(t, addr, proxyFix3Upgrade("/ws", "websocket"))
	if resp.StatusCode != http.StatusForbidden || body != proxyFix3HookDeniedMsg {
		t.Fatalf("denied upgrade: status %d body %q", resp.StatusCode, body)
	}
	if n := o.accepted.Load(); n != 0 {
		t.Fatalf("origin accepted %d connections for an upgrade the hook denied", n)
	}
	probe.assertOffLoop(t, 1)
}

func proxyFix3LimitRule(onLimit RateLimitFunc) RateLimitRule {
	return RateLimitRule{Path: "/*", MaxReqs: 1, Window: time.Minute, OnLimit: onLimit}
}

func proxyFix3CustomLimit(probe *proxyFix3HookProbe) RateLimitFunc {
	return func(event RateLimitEvent, req *Request, resp *Response) bool {
		probe.observe()
		resp.Status(http.StatusTooManyRequests).String(proxyFix3LimitedBody)
		return true
	}
}

func TestProxyFix3RateLimitHooksRunOffLoopForProxiedUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name    string
		install func(s *Server, probe *proxyFix3HookProbe)
	}{
		{"rule OnLimit", func(s *Server, probe *proxyFix3HookProbe) {
			s.SetRateLimitRules([]RateLimitRule{proxyFix3LimitRule(proxyFix3CustomLimit(probe))})
		}},
		{"server OnRateLimit", func(s *Server, probe *proxyFix3HookProbe) {
			s.SetRateLimitRules([]RateLimitRule{proxyFix3LimitRule(nil)})
			s.OnRateLimit(proxyFix3CustomLimit(probe))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newProxyFix3UpgradeOrigin(t)
			probe := &proxyFix3HookProbe{}
			srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) { tc.install(s, probe) })
			c := proxyFixDial(t, addr)
			if _, err := io.WriteString(c, proxyFix3Upgrade("/ws", "websocket")+proxyFix3TunnelProbe); err != nil {
				t.Fatalf("write: %v", err)
			}
			proxyFix3ExpectTunnel(t, c, bufio.NewReader(c))
			proxyFix3CloseTunnel(t, srv, c)
			resp, body := proxyFixRoundTrip(t, addr, proxyFix3Upgrade("/ws", "websocket"))
			if resp.StatusCode != http.StatusTooManyRequests || body != proxyFix3LimitedBody {
				t.Fatalf("rate-limited upgrade: status %d body %q", resp.StatusCode, body)
			}
			probe.assertOffLoop(t, 1)
		})
	}
}

func proxyFix3StartRouteProxy(t *testing.T, tune func(*Server)) (*Server, string, *inloopOrigin) {
	t.Helper()
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		if answer, ok := proxyFix3UpgradeAnswers[strings.TrimPrefix(req.URL.Path, strings.TrimSuffix(proxyFixRoutePrefix, "/"))]; ok {
			_, _ = io.WriteString(conn, answer)
			_, _ = io.Copy(conn, br)
			return
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(proxyFix3RouteBody), proxyFix3RouteBody)
	})
	srv, addr := proxyFixStart(t, Config{}, nil, func(s *Server) {
		s.SetHTTPRoutes([]HTTPRoute{{PathPrefix: proxyFixRoutePrefix, Backend: o.addr()}})
		tune(s)
	})
	return srv, addr, o
}

func TestProxyFix3ServerHooksRunOffLoopForPlainListenerRoute(t *testing.T) {
	probe := &proxyFix3HookProbe{}
	_, addr, _ := proxyFix3StartRouteProxy(t, probe.onRequest)
	resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFix3ClientHost, proxyFix3RoutePath))
	if resp.StatusCode != http.StatusOK || body != proxyFix3RouteBody {
		t.Fatalf("h1 route with an OnRequest hook: status %d body %q", resp.StatusCode, body)
	}
	c := proxyFixH2cDial(t, addr)
	defer c.Close()
	if _, err := c.Write(proxyFixH2Request(1, "GET", proxyFix3ClientHost, proxyFix3RoutePath)); err != nil {
		t.Fatalf("write h2 request: %v", err)
	}
	if r := c.collect(t, 1)[1]; r.status != "200" || string(r.body) != proxyFix3RouteBody {
		t.Fatalf("h2 route with an OnRequest hook: status %q body %q", r.status, r.body)
	}
	probe.assertOffLoop(t, 2)
}

func TestProxyFix3ServerHookCanDenyPlainListenerRoute(t *testing.T) {
	_, addr, o := proxyFix3StartRouteProxy(t, func(s *Server) {
		s.OnRequest(func(req *Request, resp *Response) bool {
			resp.Status(http.StatusForbidden).String(proxyFix3HookDeniedMsg)
			return false
		})
	})
	resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFix3ClientHost, proxyFix3RoutePath))
	if resp.StatusCode != http.StatusForbidden || body != proxyFix3HookDeniedMsg {
		t.Fatalf("denied route: status %d body %q", resp.StatusCode, body)
	}
	if n := o.accepted.Load(); n != 0 {
		t.Fatalf("route backend accepted %d connections for a request the hook denied", n)
	}
}

func TestProxyFix3RateLimitHookRunsOffLoopForPlainListenerRoute(t *testing.T) {
	probe := &proxyFix3HookProbe{}
	_, addr, _ := proxyFix3StartRouteProxy(t, func(s *Server) {
		s.SetRateLimitRules([]RateLimitRule{proxyFix3LimitRule(proxyFix3CustomLimit(probe))})
	})
	if resp, _ := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFix3ClientHost, proxyFix3RoutePath)); resp.StatusCode != http.StatusOK {
		t.Fatalf("first route request: status %d", resp.StatusCode)
	}
	resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFix3ClientHost, proxyFix3RoutePath))
	if resp.StatusCode != http.StatusTooManyRequests || body != proxyFix3LimitedBody {
		t.Fatalf("rate-limited route request: status %d body %q", resp.StatusCode, body)
	}
	probe.assertOffLoop(t, 1)
}

func TestProxyFix3PlainListenerRouteUpgradeTunnelsThroughDispatch(t *testing.T) {
	probe := &proxyFix3HookProbe{}
	srv, addr, _ := proxyFix3StartRouteProxy(t, probe.onRequest)
	c := proxyFixDial(t, addr)
	if _, err := io.WriteString(c, proxyFix3Upgrade(proxyFixRoutePrefix+"ws", "websocket")+proxyFix3TunnelProbe); err != nil {
		t.Fatalf("write: %v", err)
	}
	proxyFix3ExpectTunnel(t, c, bufio.NewReader(c))
	proxyFix3CloseTunnel(t, srv, c)
	probe.assertOffLoop(t, 1)
}

func TestProxyFix3TLSUpgradeTunnelsThroughDispatch(t *testing.T) {
	for _, tc := range []struct {
		name       string
		maxVersion uint16
	}{{"tls1.3", tls.VersionTLS13}, {"tls1.2", tls.VersionTLS12}} {
		t.Run(tc.name, func(t *testing.T) {
			o := newProxyFix3UpgradeOrigin(t)
			probe := &proxyFix3HookProbe{}
			srv, httpsAddr, _ := proxyFixStartTLS(t, Config{MaxConnsPerIP: -1}, func(s *Server) {
				s.AddProxyDomain(DomainConfig{Domain: proxyFixTLSDomain, Backends: []BackendConfig{{Addr: o.addr()}}})
				probe.onRequest(s)
			})
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: proxyFixIOTimeout}, "tcp", httpsAddr, &tls.Config{
				InsecureSkipVerify: true, ServerName: proxyFixTLSDomain, NextProtos: []string{"http/1.1"}, MaxVersion: tc.maxVersion,
			})
			if err != nil {
				t.Fatalf("tls dial: %v", err)
			}
			_ = c.SetDeadline(wallDeadline(proxyFixIOTimeout))
			upgrade := strings.Replace(proxyFix3Upgrade("/ws", "websocket"), "Host: "+proxyFixDomain, "Host: "+proxyFixTLSDomain, 1)
			if _, err := io.WriteString(c, upgrade+proxyFix3TunnelProbe); err != nil {
				t.Fatalf("write: %v", err)
			}
			proxyFix3ExpectTunnel(t, c, bufio.NewReader(c))
			proxyFix3CloseTunnel(t, srv, c)
			probe.assertOffLoop(t, 1)
		})
	}
}

func TestProxyFix3OpenTunnelDoesNotHoldRequestSlotInBothModes(t *testing.T) {
	for _, mode := range proxyFix3Modes {
		t.Run(mode.name, func(t *testing.T) {
			srv, addr, probe := proxyFix3StartUpgradeProxy(t, Config{MaxConcurrentReqs: 1}, mode)
			c := proxyFixDial(t, addr)
			if _, err := io.WriteString(c, proxyFix3Upgrade("/ws", "websocket")+proxyFix3TunnelProbe); err != nil {
				t.Fatalf("write: %v", err)
			}
			proxyFix3ExpectTunnel(t, c, bufio.NewReader(c))
			resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/plain"))
			if resp.StatusCode != http.StatusOK || body != proxyFix3PlainBody {
				t.Fatalf("request while a tunnel is open under MaxConcurrentReqs=1: status %d body %q", resp.StatusCode, body)
			}
			proxyFix3CloseTunnel(t, srv, c)
			if mode.hooks {
				probe.assertOffLoop(t, 2)
			}
		})
	}
}
