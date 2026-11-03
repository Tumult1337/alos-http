//go:build linux && amd64

package core

import "testing"

func perfCoreFillH2Request(req *Request, headers [][2]string, srv *Server) {
	req.Method = "GET"
	req.Path = "/plaintext"
	req.Proto = "HTTP/2"
	req.Headers = append(req.Headers[:0], headers...)
	req.StreamID = 7
	req.IsH2 = true
	req.Host = "bench.local"
	req.cachedHost = "bench.local"
	req.headerCacheMask = headerCacheHost
	req.RemoteAddr = "10.0.0.1:5555"
	req.server = srv
}

func BenchmarkPerfCoreReset(b *testing.B) {
	headers := [][2]string{{"user-agent", "h2load"}, {"accept", "*/*"}, {"accept-encoding", "gzip"}}
	srv := &Server{}
	b.Run("request_h2", func(b *testing.B) {
		req := &Request{Headers: make([][2]string, 0, 16)}
		b.ReportAllocs()
		for b.Loop() {
			perfCoreFillH2Request(req, headers, srv)
			req.Reset()
		}
	})
	b.Run("request_h1_fast", func(b *testing.B) {
		req := &Request{Headers: make([][2]string, 0, 16)}
		b.ReportAllocs()
		for b.Loop() {
			perfCoreFillH2Request(req, headers, srv)
			req.resetFastH1()
		}
	})
	b.Run("response", func(b *testing.B) {
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.SetHeaderUnsafe("x-a", "1")
			resp.String("Hello, World!")
			resp.Reset()
		}
	})
	b.Run("response_h1_fast", func(b *testing.B) {
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.SetHeaderUnsafe("x-a", "1")
			resp.String("Hello, World!")
			resp.resetFastH1()
		}
	})
}

func TestPerfCoreRequestResetKeepsOnlyReusableState(t *testing.T) {
	srv := &Server{}
	req := &Request{Headers: make([][2]string, 0, 16), Body: make([]byte, 0, 1024)}
	perfCoreFillH2Request(req, [][2]string{{"a", "b"}, {"cookie", "x=1"}}, srv)
	req.Body = append(req.Body, "body"...)
	req.Params[0] = Param{Key: "id", Value: "7"}
	req.ParamCount = 1
	req.Query = "q=1"
	req.IsTLS = true
	req.TLSVersion = TLSVersion13
	req.hijacked = true
	req.expect = h1ExpectContinue
	req.trailers = [][2]string{{"t", "v"}}
	req.Set("k", "v")
	_ = req.Cookie("x")
	_ = req.QueryParam("q")
	cors := streamCORSPolicy{engine: &CORSEngine{}}
	refusal := rateLimitRefusal{rule: &compiledRule{}, retryAfter: 5}
	req.streamCORS = cors
	req.loopRateLimitRefusal = refusal
	headersCap, store := cap(req.Headers), req.store
	req.Reset()
	_, stored := req.Get("k")
	if req.Method != "" || req.Path != "" || req.Query != "" || req.Host != "" || req.RemoteAddr != "" || req.Proto != "" ||
		len(req.Headers) != 0 || len(req.Body) != 0 || req.ParamCount != 0 || req.Params[0] != (Param{}) ||
		req.StreamID != 0 || req.IsH2 || req.IsTLS || req.TLSVersion != 0 || req.hijacked || req.expect != h1ExpectNone ||
		req.trailers != nil || req.server != nil || req.cachedHost != "" || req.headerCacheMask != 0 ||
		req.cookiesParsed || len(req.cookiesCache) != 0 || req.queryParsed || stored {
		t.Fatalf("Reset left request state behind: %+v", req)
	}
	if cap(req.Headers) != headersCap || req.store == nil || len(store) != 0 {
		t.Fatal("Reset dropped reusable buffers")
	}
	if req.streamCORS != cors || req.loopRateLimitRefusal != refusal {
		t.Fatal("Reset changed fields it never owned")
	}
}
