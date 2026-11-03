//go:build linux && amd64

package core

import "testing"

const perfCoreBrowserCookie = "sid=8f14e45fceea167a5a36dedd4bea2543; theme=dark; _ga=GA1.2.1234567890.1700000000"

func perfCoreBrowserReq() *Request {
	req := &Request{Method: "GET", Path: "/browser", Proto: "HTTP/1.1", Host: "bench.local", Headers: make([][2]string, 0, 32)}
	req.Headers = append(req.Headers,
		[2]string{"Host", "bench.local"},
		[2]string{"Connection", "keep-alive"},
		[2]string{"sec-ch-ua", `"Chromium";v="141", "Google Chrome";v="141", "Not?A_Brand";v="99"`},
		[2]string{"sec-ch-ua-mobile", "?0"},
		[2]string{"sec-ch-ua-platform", `"Windows"`},
		[2]string{"Upgrade-Insecure-Requests", "1"},
		[2]string{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"},
		[2]string{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
		[2]string{"Sec-Fetch-Site", "same-origin"},
		[2]string{"Sec-Fetch-Mode", "navigate"},
		[2]string{"Sec-Fetch-User", "?1"},
		[2]string{"Sec-Fetch-Dest", "document"},
		[2]string{"Referer", "https://bench.local/dashboard"},
		[2]string{"Accept-Encoding", "gzip, deflate, br, zstd"},
		[2]string{"Accept-Language", "en-US,en;q=0.9"},
		[2]string{"Cookie", perfCoreBrowserCookie},
	)
	return req
}

func perfCoreBrowserHandler(req *Request, resp *Response) {
	resp.String(req.Header("User-Agent") + "|" + req.Header("Accept-Language") + "|" + req.Cookie("sid"))
}

func perfCoreBrowserNextRequest(req *Request) {
	req.headerCacheMask = 0
	req.cookiesParsed = false
	clear(req.cookiesCache)
	req.cookiesCache = req.cookiesCache[:0]
}

func TestPerfCoreW8BrowserLookups(t *testing.T) {
	req := perfCoreBrowserReq()
	if got := req.Cookie("sid"); got != "8f14e45fceea167a5a36dedd4bea2543" {
		t.Fatalf("sid %q", got)
	}
	if got := req.Cookie("_ga"); got != "GA1.2.1234567890.1700000000" {
		t.Fatalf("_ga %q", got)
	}
	if got := req.Header("accept-language"); got != "en-US,en;q=0.9" {
		t.Fatalf("accept-language %q", got)
	}
	resp := perfCoreResp()
	perfCoreBrowserHandler(req, resp)
	want := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36|en-US,en;q=0.9|8f14e45fceea167a5a36dedd4bea2543"
	if resp.bodyString != want {
		t.Fatalf("body %q", resp.bodyString)
	}
}

func BenchmarkPerfCoreW8Browser(b *testing.B) {
	b.Run("header_user_agent", func(b *testing.B) {
		req := perfCoreBrowserReq()
		b.ReportAllocs()
		for b.Loop() {
			perfCoreSinkString = req.Header("User-Agent")
		}
	})
	b.Run("header_accept_language", func(b *testing.B) {
		req := perfCoreBrowserReq()
		b.ReportAllocs()
		for b.Loop() {
			perfCoreSinkString = req.Header("Accept-Language")
		}
	})
	b.Run("header_cached_accept_encoding_cold", func(b *testing.B) {
		req := perfCoreBrowserReq()
		b.ReportAllocs()
		for b.Loop() {
			req.headerCacheMask = 0
			perfCoreSinkString = req.Header("Accept-Encoding")
		}
	})
	b.Run("header_absent", func(b *testing.B) {
		req := perfCoreBrowserReq()
		b.ReportAllocs()
		for b.Loop() {
			perfCoreSinkString = req.Header("X-Not-Present")
		}
	})
	b.Run("cookie_sid_parse", func(b *testing.B) {
		req := perfCoreBrowserReq()
		b.ReportAllocs()
		for b.Loop() {
			perfCoreBrowserNextRequest(req)
			perfCoreSinkString = req.Cookie("sid")
		}
	})
	b.Run("cookie_sid_cached", func(b *testing.B) {
		req := perfCoreBrowserReq()
		req.Cookie("sid")
		b.ReportAllocs()
		for b.Loop() {
			perfCoreSinkString = req.Cookie("sid")
		}
	})
	b.Run("parseCookieHeader", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			perfCoreSinkCookies = parseCookieHeader(perfCoreBrowserCookie)
		}
	})
	b.Run("handler_W8", func(b *testing.B) {
		req := perfCoreBrowserReq()
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			perfCoreBrowserNextRequest(req)
			resp.resetFastH1()
			perfCoreBrowserHandler(req, resp)
		}
	})
}

var perfCoreSinkCookies []Cookie

func TestPerfCoreHeaderLookupZeroAlloc(t *testing.T) {
	req := perfCoreBrowserReq()
	for _, name := range []string{"User-Agent", "Accept-Language", "accept-encoding", "Host", "Origin", "X-Not-Present"} {
		allocs := testing.AllocsPerRun(200, func() {
			req.headerCacheMask = 0
			perfCoreSinkString = req.Header(name)
		})
		if allocs != 0 {
			t.Fatalf("Header(%q) allocates %.1f/op, want 0", name, allocs)
		}
	}
}

func TestPerfCoreCookieCachedZeroAlloc(t *testing.T) {
	req := perfCoreBrowserReq()
	req.Cookie("sid")
	allocs := testing.AllocsPerRun(200, func() {
		perfCoreSinkString = req.Cookie("sid")
		perfCoreSinkString = req.Cookie("missing")
	})
	if allocs != 0 {
		t.Fatalf("Cookie on an already-parsed request allocates %.1f/op, want 0", allocs)
	}
}
