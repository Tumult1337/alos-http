//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
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

func TestProxyCacheKeysByOriginalPath(t *testing.T) {
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
			if r := proxyG2Get(t, p, addr, "/internal"); r.status != http.StatusOK || served.Load() != 2 {
				t.Fatalf("a direct request for the rewritten path was served from the entry of /public: %+v, origin served %d", r, served.Load())
			}
			if r := proxyG2Get(t, p, addr, "/public"); r.body != "origin:/internal" || served.Load() != 2 {
				t.Fatalf("a repeat of the original path missed the cache: %+v, origin served %d", r, served.Load())
			}
		})
	}
}
