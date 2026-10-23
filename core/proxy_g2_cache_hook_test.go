//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type proxyG2CachePath struct {
	name    string
	handler bool
	h2      bool
}

var proxyG2CachePaths = []proxyG2CachePath{
	{name: "h1 loop"},
	{name: "h1 handler", handler: true},
	{name: "h2 loop", h2: true},
}

func proxyG2CacheOrigin(t *testing.T, served *atomic.Int64) string {
	t.Helper()
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, _ *bufio.Reader) {
		served.Add(1)
		body := "origin:" + req.URL.Path
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nCache-Control: max-age=600\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	})
	return o.addr()
}

func proxyG2CacheStart(t *testing.T, p proxyG2CachePath, originAddr string, hook ProxyInterceptFunc) string {
	t.Helper()
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(originAddr), func(s *Server) {
		s.SetProxyCache(DefaultProxyCacheConfig())
		s.OnProxyRequest(hook)
		if p.handler {
			s.OnRequest(func(*Request, *Response) bool { return true })
		}
	})
	return addr
}

type proxyG2Reply struct {
	status int
	body   string
	cache  string
}

func proxyG2Get(t *testing.T, p proxyG2CachePath, addr, path string) proxyG2Reply {
	t.Helper()
	if p.h2 {
		c := proxyFixH2cDial(t, addr)
		defer c.Close()
		proxyFixSendH2(t, c, path)
		r := c.collect(t, 1)[1]
		status := 0
		fmt.Sscan(r.status, &status)
		return proxyG2Reply{status: status, body: string(r.body)}
	}
	resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, path))
	return proxyG2Reply{status: resp.StatusCode, body: body, cache: resp.Header.Get("X-Cache")}
}

func TestProxyCacheHitRunsRequestHook(t *testing.T) {
	for _, p := range proxyG2CachePaths {
		t.Run(p.name, func(t *testing.T) {
			var served atomic.Int64
			var block atomic.Bool
			var calls atomic.Int64
			addr := proxyG2CacheStart(t, p, proxyG2CacheOrigin(t, &served), func(pr *ProxyRequest) bool {
				calls.Add(1)
				return !block.Load()
			})
			if r := proxyG2Get(t, p, addr, "/c"); r.status != http.StatusOK {
				t.Fatalf("first request: %+v", r)
			}
			if r := proxyG2Get(t, p, addr, "/c"); r.status != http.StatusOK || served.Load() != 1 {
				t.Fatalf("second request was not a cache hit: %+v, origin served %d", r, served.Load())
			}
			if calls.Load() != 2 {
				t.Fatalf("request hook ran %d times for a miss and a hit, want 2", calls.Load())
			}
			block.Store(true)
			if r := proxyG2Get(t, p, addr, "/c"); r.status != http.StatusBadGateway {
				t.Fatalf("a request the hook refuses was answered from the cache: %+v", r)
			}
		})
	}
}

func TestProxyCacheDoesNotStoreHookRewrittenRequests(t *testing.T) {
	for _, p := range proxyG2CachePaths {
		t.Run(p.name, func(t *testing.T) {
			var served atomic.Int64
			addr := proxyG2CacheStart(t, p, proxyG2CacheOrigin(t, &served), func(pr *ProxyRequest) bool {
				if pr.Path == "/public" {
					pr.Path = "/internal"
				}
				return true
			})
			if r := proxyG2Get(t, p, addr, "/public"); r.body != "origin:/internal" {
				t.Fatalf("rewrite did not reach the origin: %+v", r)
			}
			if r := proxyG2Get(t, p, addr, "/internal"); r.body != "origin:/internal" || served.Load() != 2 {
				t.Fatalf("a direct request was served from the entry of a rewritten request: %+v, origin served %d", r, served.Load())
			}
			if r := proxyG2Get(t, p, addr, "/public"); r.body != "origin:/internal" || served.Load() != 3 {
				t.Fatalf("a rewritten request was answered from the cache: %+v, origin served %d", r, served.Load())
			}
		})
	}
}

func proxyG2TenantOrigin(t *testing.T) string {
	t.Helper()
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, _ *bufio.Reader) {
		body := "path=" + req.URL.Path + " user=" + req.Header.Get("X-User") + " tenant=" + req.Header.Get("X-Tenant") + " host=" + req.Host
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nCache-Control: max-age=600\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	})
	return o.addr()
}

func proxyG2TenantOf(pr *ProxyRequest) string {
	for _, h := range pr.Headers {
		if strings.EqualFold(h[0], "x-tenant") {
			return h[1]
		}
	}
	return ""
}

func proxyG2GetAs(t *testing.T, p proxyG2CachePath, addr, path, tenant string) proxyG2Reply {
	t.Helper()
	if p.h2 {
		c := proxyFixH2cDial(t, addr)
		defer c.Close()
		block := proxyFixAppendHPACKLiteral(nil, proxyFixHpackStaticMethod, "GET")
		block = append(block, proxyFixHpackStaticSchemeHTTP)
		block = proxyFixAppendHPACKLiteral(block, proxyFixHpackStaticPath, path)
		block = proxyFixAppendHPACKLiteral(block, proxyFixHpackStaticAuthority, proxyFixDomain)
		block = append(block, 0x00, byte(len("x-tenant")))
		block = append(block, "x-tenant"...)
		block = append(block, byte(len(tenant)))
		block = append(block, tenant...)
		if _, err := c.Write(proxyFixAppendH2Frame(nil, h2FrameHeaders, h2FlagEndStream|h2FlagEndHeaders, 1, block)); err != nil {
			t.Fatalf("write: %v", err)
		}
		r := c.collect(t, 1)[1]
		status := 0
		fmt.Sscan(r.status, &status)
		return proxyG2Reply{status: status, body: string(r.body)}
	}
	resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, path, "X-Tenant: "+tenant))
	return proxyG2Reply{status: resp.StatusCode, body: body, cache: resp.Header.Get("X-Cache")}
}

func TestProxyCacheNeverCrossesTenantsRewrittenByHook(t *testing.T) {
	rewrites := map[string]func(pr *ProxyRequest, tenant string){
		"path":    func(pr *ProxyRequest, tenant string) { pr.Path = "/t/" + tenant },
		"header":  func(pr *ProxyRequest, tenant string) { pr.Headers = append(pr.Headers, [2]string{"X-User", tenant}) },
		"removal": func(pr *ProxyRequest, tenant string) { pr.Headers = pr.Headers[:0] },
		"host":    func(pr *ProxyRequest, tenant string) { pr.Host = tenant + ".internal" },
	}
	for _, p := range proxyG2CachePaths {
		for name, rewrite := range rewrites {
			t.Run(p.name+"/"+name, func(t *testing.T) {
				addr := proxyG2CacheStart(t, p, proxyG2TenantOrigin(t), func(pr *ProxyRequest) bool {
					tenant := proxyG2TenantOf(pr)
					if tenant == "" || name == "removal" && tenant == "a" {
						return true
					}
					rewrite(pr, tenant)
					return true
				})
				first := proxyG2GetAs(t, p, addr, "/data", "a")
				second := proxyG2GetAs(t, p, addr, "/data", "b")
				if first.status != http.StatusOK || second.status != http.StatusOK {
					t.Fatalf("statuses %d and %d", first.status, second.status)
				}
				if second.body == first.body {
					t.Fatalf("tenant b received tenant a's cached body %q", second.body)
				}
				if name == "removal" {
					return
				}
				if anonymous := proxyG2GetAs(t, p, addr, "/data", ""); anonymous.body == first.body || anonymous.body == second.body {
					t.Fatalf("a request the hook left unchanged received a rewritten tenant body %q", anonymous.body)
				}
			})
		}
	}
}

func TestProxyCacheBypassRunsRequestHookForLookupAndForward(t *testing.T) {
	for _, p := range proxyG2CachePaths {
		t.Run(p.name, func(t *testing.T) {
			var mu sync.Mutex
			var backends []string
			addr := proxyG2CacheStart(t, p, proxyG2TenantOrigin(t), func(pr *ProxyRequest) bool {
				mu.Lock()
				backends = append(backends, pr.Backend)
				mu.Unlock()
				if tenant := proxyG2TenantOf(pr); tenant != "" {
					pr.Path = "/t/" + tenant
				}
				return true
			})
			seen := func() []string {
				mu.Lock()
				defer mu.Unlock()
				return append([]string(nil), backends...)
			}
			if r := proxyG2GetAs(t, p, addr, "/data", ""); r.status != http.StatusOK || len(seen()) != 1 || seen()[0] == proxyCacheBackend {
				t.Fatalf("a miss must run the hook once with the real backend: %+v, backends %q", r, seen())
			}
			if r := proxyG2GetAs(t, p, addr, "/data", "b"); !strings.HasPrefix(r.body, "path=/t/b ") {
				t.Fatalf("bypassed request: %+v", r)
			}
			got := seen()
			if len(got) != 3 || got[1] != proxyCacheBackend || got[2] == proxyCacheBackend {
				t.Fatalf("a bypassed hit ran the hook with backends %q, want one cache lookup and one forward to the real backend", got)
			}
		})
	}
}

func TestProxyCacheBypassForwardHonorsBackendDecision(t *testing.T) {
	for _, p := range proxyG2CachePaths {
		t.Run(p.name, func(t *testing.T) {
			var served atomic.Int64
			var denyReal atomic.Bool
			addr := proxyG2CacheStart(t, p, proxyG2CacheOrigin(t, &served), func(pr *ProxyRequest) bool {
				if !denyReal.Load() {
					return true
				}
				if pr.Backend == proxyCacheBackend {
					pr.Path = "/elsewhere"
					return true
				}
				return false
			})
			if r := proxyG2Get(t, p, addr, "/c"); r.status != http.StatusOK || served.Load() != 1 {
				t.Fatalf("seed request: %+v, origin served %d", r, served.Load())
			}
			denyReal.Store(true)
			if r := proxyG2Get(t, p, addr, "/c"); r.status != http.StatusBadGateway {
				t.Fatalf("a hook that denies the real backend did not stop the forward: %+v", r)
			}
			if got := served.Load(); got != 1 {
				t.Fatalf("the backend the hook denied received %d requests", got-1)
			}
		})
	}
}
