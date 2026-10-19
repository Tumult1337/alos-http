//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"
)

const (
	proxyFix3BenchDomain           = "bench.test"
	proxyFix3BenchPath             = "/cached"
	proxyFix3FewBackendFields      = 2
	proxyFix3BenchBackendFields    = 6
	proxyFix3OverflowBackendFields = 10
	proxyFix3AllocRuns             = 200
)

func TestProxyFix3RetainedDispatchCacheHitHeadersAreStable(t *testing.T) {
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	var kept proxyFixRetained
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.SetProxyCache(DefaultProxyCacheConfig())
		s.OnResponse(func(req *Request, resp *Response) {})
		s.proxy.Load().OnResponse = func(pr *ProxyResponse) {
			if pr.Backend == proxyCacheBackend {
				kept.keepResponse(pr)
			}
		}
	})
	c := proxyFixDial(t, addr)
	defer c.Close()
	br := bufio.NewReader(c)
	for _, p := range []string{"/a", "/a", "/bb", "/bb", "/a"} {
		if _, err := io.WriteString(c, "GET "+p+" HTTP/1.1\r\nHost: "+proxyFixDomain+"\r\n\r\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		if resp, _ := proxyFixReadResponse(t, br); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", p, resp.StatusCode)
		}
	}
	kept.mu.Lock()
	defer kept.mu.Unlock()
	if len(kept.responses) < 2 {
		t.Fatalf("only %d dispatched cache hits observed", len(kept.responses))
	}
	for i, pr := range kept.responses {
		if !reflect.DeepEqual(pr.Headers, kept.snapshots[i]) {
			t.Fatalf("retained dispatch cache-hit %d headers changed after later requests: %v, at hook time %v", i, pr.Headers, kept.snapshots[i])
		}
	}
}

func TestProxyFix3HandleCacheHitHookEditsReachResponse(t *testing.T) {
	pe := proxyFix3CachedEngine(t, 0)
	pe.OnResponse = func(pr *ProxyResponse) {
		pr.StatusCode = http.StatusAccepted
		pr.Headers = append(pr.Headers, [2]string{"x-hooked", "yes"})
	}
	req, resp := proxyFix3CachedRequest()
	if !pe.Handle(req, resp) {
		t.Fatal("Handle did not serve the cached domain")
	}
	if resp.StatusCode != http.StatusAccepted || proxyFixHeaderValue(resp.Headers, "x-hooked") != "yes" || proxyFixHeaderValue(resp.Headers, "x-cache") != "HIT" {
		t.Fatalf("hook edits lost on the Handle cache hit: status %d headers %v", resp.StatusCode, resp.Headers)
	}
}

func proxyFix3CachedEngine(tb testing.TB, backendFields int) *ProxyEngine {
	tb.Helper()
	pe := NewProxyEngine()
	pe.AddDomain(DomainConfig{Domain: proxyFix3BenchDomain, Backends: []BackendConfig{{Addr: "127.0.0.1:1"}}})
	pe.Cache = NewProxyCache(DefaultProxyCacheConfig())
	tb.Cleanup(pe.Stop)
	headers := make([][2]string, 0, backendFields)
	for i := 0; i < backendFields; i++ {
		headers = append(headers, [2]string{"x-backend-" + strconv.Itoa(i), "value-" + strconv.Itoa(i)})
	}
	pe.Cache.put("GET", proxyFix3BenchDomain, proxyFix3BenchPath, http.StatusOK, headers, "text/plain", []byte("cached body"), cachePutOptions{generation: pe.Cache.purgeGeneration()})
	if _, hit := pe.Cache.Get("GET", proxyFix3BenchDomain, proxyFix3BenchPath, &Request{}); !hit {
		tb.Fatal("benchmark entry was not cached")
	}
	return pe
}

func proxyFix3CachedRequest() (*Request, *Response) {
	req := &Request{Method: "GET", Host: proxyFix3BenchDomain, Path: proxyFix3BenchPath, RemoteAddr: "127.0.0.1:40000"}
	resp := &Response{}
	resp.Reset()
	return req, resp
}

func proxyFix3BenchHandleCacheHit(b *testing.B, backendFields int, hook func(*ProxyResponse)) {
	pe := proxyFix3CachedEngine(b, backendFields)
	pe.OnResponse = hook
	req, resp := proxyFix3CachedRequest()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Reset()
		if !pe.Handle(req, resp) {
			b.Fatal("Handle did not serve the cached domain")
		}
	}
}

func BenchmarkProxyFix3HandleCacheHit(b *testing.B) {
	proxyFix3BenchHandleCacheHit(b, 0, nil)
}

func BenchmarkProxyFix3HandleCacheHitHooked(b *testing.B) {
	proxyFix3BenchHandleCacheHit(b, 0, func(*ProxyResponse) {})
}

func BenchmarkProxyFix3HandleCacheHitHookedFourHeaders(b *testing.B) {
	proxyFix3BenchHandleCacheHit(b, proxyFix3FewBackendFields, func(*ProxyResponse) {})
}

func BenchmarkProxyFix3HandleCacheHitHookedManyHeaders(b *testing.B) {
	proxyFix3BenchHandleCacheHit(b, proxyFix3BenchBackendFields, func(*ProxyResponse) {})
}

func BenchmarkProxyFix3HandleCacheHitHookedOverflowHeaders(b *testing.B) {
	proxyFix3BenchHandleCacheHit(b, proxyFix3OverflowBackendFields, func(*ProxyResponse) {})
}

func proxyFix3HandleCacheHitAllocs(t *testing.T, backendFields int, hook func(*ProxyResponse)) float64 {
	pe := proxyFix3CachedEngine(t, backendFields)
	pe.OnResponse = hook
	req, resp := proxyFix3CachedRequest()
	return testing.AllocsPerRun(proxyFix3AllocRuns, func() {
		resp.Reset()
		pe.Handle(req, resp)
	})
}

func TestProxyFix3HandleCacheHitHookCopyAddsNoAllocation(t *testing.T) {
	for _, fields := range []int{0, proxyFix3FewBackendFields, proxyFix3BenchBackendFields} {
		plain := proxyFix3HandleCacheHitAllocs(t, fields, nil)
		hooked := proxyFix3HandleCacheHitAllocs(t, fields, func(*ProxyResponse) {})
		if hooked > plain+1 {
			t.Errorf("%d backend fields: hooked cache hit %.2f allocs, unhooked %.2f; the hook may cost only its ProxyResponse", fields, hooked, plain)
		}
	}
}

func BenchmarkProxyFix3InLoopCacheHitHooked(b *testing.B) {
	proxyFixBenchRoundTrip(b, "/bench?q=1", func(s *Server) {
		s.SetProxyCache(ProxyCacheConfig{
			Rules:         []CacheRule{{PathPrefix: "/", MaxAge: time.Minute}},
			MaxEntrySize:  1 << 20,
			DefaultMaxAge: time.Minute,
		})
		s.proxy.Load().OnResponse = func(*ProxyResponse) {}
	})
}
