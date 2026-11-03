//go:build linux && amd64

package core

import (
	"strings"
	"testing"
	"time"
)

const (
	perfCoreRateLimitMax    = 1_000_000_000
	perfCoreRateLimitWindow = time.Second
	perfCoreChainDepth      = 8
)

func perfCoreMWReq() *Request {
	req := &Request{Method: "GET", Path: "/mw", Proto: "HTTP/1.1", Host: "bench.local", RemoteAddr: "192.0.2.7:51234", Headers: make([][2]string, 0, 8)}
	req.Headers = append(req.Headers, [2]string{"Host", "bench.local"}, [2]string{"Origin", "https://app.test"})
	return req
}

func perfCoreW9Handler(stop <-chan struct{}) HandlerFunc {
	return Chain(func(req *Request, resp *Response) { resp.String("ok") },
		CORS(CORSConfig{AllowOrigins: []string{"*"}}),
		RateLimitMiddleware(RateLimitMiddlewareConfig{MaxRequests: perfCoreRateLimitMax, Window: perfCoreRateLimitWindow, StopCh: stop}),
	)
}

func TestPerfCoreW9Chain(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	h := perfCoreW9Handler(stop)
	req := perfCoreMWReq()
	resp := perfCoreResp()
	h(req, resp)
	if resp.StatusCode != 200 || resp.bodyString != "ok" {
		t.Fatalf("status %d body %q", resp.StatusCode, resp.bodyString)
	}
	found := false
	for _, hv := range resp.Headers {
		if hv[0] == "access-control-allow-origin" && hv[1] == "*" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no wildcard ACAO in %v", resp.Headers)
	}
}

func BenchmarkPerfCoreW9Middleware(b *testing.B) {
	b.Run("cors_ratelimit_chain", func(b *testing.B) {
		stop := make(chan struct{})
		defer close(stop)
		h := perfCoreW9Handler(stop)
		req := perfCoreMWReq()
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			h(req, resp)
		}
	})
	b.Run("cors_wildcard_only", func(b *testing.B) {
		h := Chain(func(req *Request, resp *Response) { resp.String("ok") }, CORS(CORSConfig{AllowOrigins: []string{"*"}}))
		req := perfCoreMWReq()
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			h(req, resp)
		}
	})
	b.Run("cors_allowlist_full", func(b *testing.B) {
		h := Chain(func(req *Request, resp *Response) { resp.String("ok") }, CORS(CORSConfig{
			AllowOrigins:     []string{"https://app.test", "https://admin.test"},
			AllowMethods:     []string{"GET", "POST"},
			AllowHeaders:     []string{"Content-Type", "Authorization"},
			ExposeHeaders:    []string{"X-Request-ID"},
			AllowCredentials: true,
			MaxAge:           600,
		}))
		req := perfCoreMWReq()
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			req.headerCacheMask = 0
			resp.resetFastH1()
			h(req, resp)
		}
	})
	b.Run("ratelimit_only", func(b *testing.B) {
		stop := make(chan struct{})
		defer close(stop)
		h := Chain(func(req *Request, resp *Response) { resp.String("ok") },
			RateLimitMiddleware(RateLimitMiddlewareConfig{MaxRequests: perfCoreRateLimitMax, Window: perfCoreRateLimitWindow, StopCh: stop}))
		req := perfCoreMWReq()
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			h(req, resp)
		}
	})
	b.Run("ratelimit_engine_check", func(b *testing.B) {
		rle := NewRateLimitEngine()
		defer rle.Stop()
		rle.SetRules([]RateLimitRule{{Path: "/mw", MaxReqs: perfCoreRateLimitMax, Window: time.Hour}})
		b.ReportAllocs()
		for b.Loop() {
			rle.Check("192.0.2.7", "/mw")
		}
	})
	b.Run("noop_chain_depth8", func(b *testing.B) {
		noop := func(next HandlerFunc) HandlerFunc {
			return func(req *Request, resp *Response) { next(req, resp) }
		}
		mws := make([]MiddlewareFunc, perfCoreChainDepth)
		for i := range mws {
			mws[i] = noop
		}
		h := Chain(func(req *Request, resp *Response) { resp.String("ok") }, mws...)
		req := perfCoreMWReq()
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			h(req, resp)
		}
	})
	b.Run("security_headers_default", func(b *testing.B) {
		h := Chain(func(req *Request, resp *Response) { resp.String("ok") }, SecurityHeaders(DefaultSecurityHeaders()))
		req := perfCoreMWReq()
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			h(req, resp)
		}
	})
	b.Run("request_id", func(b *testing.B) {
		h := Chain(func(req *Request, resp *Response) { resp.String("ok") }, RequestID())
		req := perfCoreMWReq()
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			h(req, resp)
		}
	})
}

func TestPerfCoreW9ZeroAlloc(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	cases := map[string]HandlerFunc{
		"cors_ratelimit_chain": perfCoreW9Handler(stop),
		"cors_allowlist": Chain(func(req *Request, resp *Response) { resp.String("ok") }, CORS(CORSConfig{
			AllowOrigins:     []string{"https://app.test"},
			AllowMethods:     []string{"GET", "POST"},
			AllowCredentials: true,
			MaxAge:           600,
		})),
		"security_headers": Chain(func(req *Request, resp *Response) { resp.String("ok") }, SecurityHeaders(DefaultSecurityHeaders())),
	}
	for name, h := range cases {
		req := perfCoreMWReq()
		resp := perfCoreResp()
		h(req, resp)
		allocs := testing.AllocsPerRun(200, func() {
			req.headerCacheMask = 0
			resp.resetFastH1()
			h(req, resp)
		})
		if allocs != 0 {
			t.Fatalf("%s allocates %.1f/op, want 0", name, allocs)
		}
	}
}

func perfCoreCacheReq(accept string) *Request {
	req := &Request{Method: "GET", Path: "/cached", Host: "bench.local", Proto: "HTTP/1.1", Headers: make([][2]string, 0, 8)}
	req.Headers = append(req.Headers, [2]string{"Host", "bench.local"})
	if accept != "" {
		req.Headers = append(req.Headers, [2]string{"Accept-Encoding", accept})
	}
	return req
}

func BenchmarkPerfCoreCacheHit(b *testing.B) {
	for _, tc := range []struct {
		name   string
		size   int
		accept string
		cfg    CacheConfig
	}{
		{"plain_2K", 2 << 10, "", CacheConfig{TTL: time.Hour}},
		{"plain_64K", 64 << 10, "", CacheConfig{TTL: time.Hour}},
		{"gzip_16K", 16 << 10, "gzip", CacheConfig{TTL: time.Hour, Gzip: true}},
		{"br_16K", 16 << 10, "br", CacheConfig{TTL: time.Hour, Brotli: true}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			rc := NewResponseCache(tc.cfg)
			defer rc.Stop()
			body := strings.Repeat(perfCorePangram, tc.size/len(perfCorePangram)+1)[:tc.size]
			next := func(req *Request, resp *Response) { resp.Status(200).String(body) }
			req := perfCoreCacheReq(tc.accept)
			resp := perfCoreResp()
			rc.handle(next, req, resp)
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			for b.Loop() {
				req.headerCacheMask = 0
				resp.resetFastH1()
				rc.handle(next, req, resp)
			}
		})
	}
	b.Run("proxycache_ServeCached_2K", func(b *testing.B) {
		pc := NewProxyCache(DefaultProxyCacheConfig())
		defer pc.Stop()
		body := []byte(strings.Repeat("c", 2<<10))
		pc.PutManual("GET", "bench.local", "/cached", 200, [][2]string{{"Cache-Control", "max-age=60"}}, "text/plain", body, time.Hour, 0, false, 0)
		entry, ok := pc.Get("GET", "bench.local", "/cached", nil)
		if !ok {
			b.Fatal("proxy cache miss")
		}
		req := perfCoreCacheReq("")
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			pc.ServeCached(entry, req, resp)
		}
	})
}

func TestPerfCoreCacheHitServesStoredBody(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Hour})
	defer rc.Stop()
	calls := 0
	next := func(req *Request, resp *Response) {
		calls++
		resp.Status(200).String("cached-body")
	}
	req := perfCoreCacheReq("")
	for i := 0; i < 3; i++ {
		resp := perfCoreResp()
		rc.handle(next, req, resp)
		if string(resp.GetBody()) != "cached-body" || resp.StatusCode != 200 {
			t.Fatalf("round %d: status %d body %q", i, resp.StatusCode, resp.GetBody())
		}
	}
	if calls != 1 {
		t.Fatalf("handler ran %d times, want 1", calls)
	}
}

func TestPerfCoreCacheHitZeroAlloc(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Hour})
	defer rc.Stop()
	body := strings.Repeat("c", 2<<10)
	next := func(req *Request, resp *Response) { resp.Status(200).String(body) }
	req := perfCoreCacheReq("")
	resp := perfCoreResp()
	rc.handle(next, req, resp)
	allocs := testing.AllocsPerRun(200, func() {
		resp.resetFastH1()
		rc.handle(next, req, resp)
	})
	if allocs != 0 {
		t.Fatalf("ResponseCache hit allocates %.1f/op, want 0", allocs)
	}
}
