//go:build linux && amd64

package core

import (
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

const perfBrowserHead = "GET /browser?x=1 HTTP/1.1\r\n" +
	"Host: bench.example.com\r\n" +
	"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36\r\n" +
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
	"Accept-Language: en-US,en;q=0.9\r\n" +
	"Accept-Encoding: gzip, deflate, br\r\n" +
	"Connection: keep-alive\r\n" +
	"Cookie: sid=abc123; theme=dark; lang=en\r\n" +
	"Upgrade-Insecure-Requests: 1\r\n" +
	"Sec-Fetch-Dest: document\r\n" +
	"Sec-Fetch-Mode: navigate\r\n" +
	"Sec-Fetch-Site: none\r\n" +
	"Sec-Fetch-User: ?1\r\n" +
	"Cache-Control: max-age=0\r\n" +
	"DNT: 1\r\n" +
	"Referer: https://bench.example.com/\r\n\r\n"

var perfBackendHeaders = [][2]string{
	{"Content-Type", "text/plain; charset=utf-8"},
	{"Content-Length", "13"},
	{"Date", "Mon, 19 Oct 2026 10:00:00 GMT"},
	{"Server", "origin"},
	{"Cache-Control", "no-cache"},
	{"X-Request-Id", "0123456789abcdef"},
	{"Vary", "Accept-Encoding"},
	{"X-Origin-Trace", "edge-7"},
}

func perfFillH1Parser(p *h1Parser) {
	p.reset()
	p.hdrBuf = p.hdrBuf[:0]
	for _, h := range perfBackendHeaders {
		p.hdrBuf = append(p.hdrBuf, h[0]...)
		p.hdrBuf = append(p.hdrBuf, h[1]...)
	}
	off := 0
	for _, h := range perfBackendHeaders {
		name := p.hdrBuf[off : off+len(h[0])]
		off += len(h[0])
		value := p.hdrBuf[off : off+len(h[1])]
		off += len(h[1])
		p.hdr = append(p.hdr, [2][]byte{name, value})
	}
}

func perfStringHeadersArena(p *h1Parser) [][2]string {
	p.strs = p.strs[:0]
	total := 0
	for _, h := range p.hdr {
		total += len(h[1])
	}
	arena := make([]byte, 0, total)
	for _, h := range p.hdr {
		start := len(arena)
		arena = append(arena, h[1]...)
		value := ""
		if len(h[1]) > 0 {
			value = unsafe.String(&arena[start], len(h[1]))
		}
		p.strs = append(p.strs, [2]string{lowerHeaderName(h[0]), value})
	}
	return p.strs
}

func BenchmarkPerfZeroCopyConversions(b *testing.B) {
	src := []byte(strings.Repeat("abcdefgh", 16))
	for _, n := range []int{8, 32, 128} {
		b.Run("string_copy_escaping/"+strconv.Itoa(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				perfSinkStr = string(src[:n])
			}
		})
		b.Run("unsafe_String_view/"+strconv.Itoa(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				perfSinkStr = unsafe.String(&src[0], n)
			}
		})
		s := string(src[:n])
		b.Run("bytes_copy_escaping/"+strconv.Itoa(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				perfSinkBytes = []byte(s)
			}
		})
		b.Run("unsafe_Slice_view/"+strconv.Itoa(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				perfSinkBytes = unsafe.Slice(unsafe.StringData(s), n)
			}
		})
	}
}

func BenchmarkPerfZeroCopyProxyStringHeaders(b *testing.B) {
	b.Run("current_string_per_value", func(b *testing.B) {
		b.ReportAllocs()
		var p h1Parser
		perfFillH1Parser(&p)
		for i := 0; i < b.N; i++ {
			if len(p.stringHeaders()) != len(perfBackendHeaders) {
				b.Fatal("header count")
			}
		}
	})
	b.Run("alt_one_arena_per_response", func(b *testing.B) {
		b.ReportAllocs()
		var p h1Parser
		perfFillH1Parser(&p)
		for i := 0; i < b.N; i++ {
			if len(perfStringHeadersArena(&p)) != len(perfBackendHeaders) {
				b.Fatal("header count")
			}
		}
	})
}

func BenchmarkPerfZeroCopyLowerHeaderName(b *testing.B) {
	for _, name := range []string{"Content-Type", "X-Origin-Trace"} {
		raw := []byte(name)
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				perfSinkStr = lowerHeaderName(raw)
			}
		})
	}
}

func perfParseBrowserHead(tb testing.TB, buf []byte, req *Request) []byte {
	tb.Helper()
	n := copy(buf, perfBrowserHead)
	req.resetFastH1()
	end, _, _, _, reject, _, _, ok := ParseH1RequestHead(buf[:n], req, 0, 0)
	if !ok || reject || end == 0 {
		tb.Fatal("browser head did not parse")
	}
	req.Host = req.cachedHost
	return buf[:end]
}

func BenchmarkPerfZeroCopyPromoteRequestHead(b *testing.B) {
	b.Run("h1_keepalive_bump_arena_current", func(b *testing.B) {
		b.ReportAllocs()
		buf := make([]byte, 4096)
		var req Request
		for i := 0; i < b.N; i++ {
			head := perfParseBrowserHead(b, buf, &req)
			promoteRequestHead(&req, head)
		}
	})
	b.Run("fresh_arena_per_request", func(b *testing.B) {
		b.ReportAllocs()
		buf := make([]byte, 4096)
		var req Request
		for i := 0; i < b.N; i++ {
			head := perfParseBrowserHead(b, buf, &req)
			req.promoteBuf = nil
			req.promoteOff = 0
			promoteRequestHead(&req, head)
		}
	})
}

func perfPoison(buf []byte) {
	for i := range buf {
		buf[i] = '#'
	}
}

func TestPerfZeroCopyAliasedHeaderIsUnsafeUntilPromoted(t *testing.T) {
	buf := make([]byte, 4096)
	var req Request
	perfParseBrowserHead(t, buf, &req)
	aliased := req.Header("User-Agent")
	want := strings.Clone(aliased)
	perfPoison(buf)
	if aliased == want {
		t.Fatal("parsed header did not alias the read buffer; the zero-copy premise changed")
	}

	head := perfParseBrowserHead(t, buf, &req)
	promoteRequestHead(&req, head)
	promoted := req.Header("User-Agent")
	perfPoison(buf)
	if promoted != want {
		t.Fatalf("promoted header changed after read-buffer reuse: %q", promoted)
	}
}

func TestPerfZeroCopyPromoteArenaKeepsPriorRequestStrings(t *testing.T) {
	buf := make([]byte, 4096)
	var req Request
	head := perfParseBrowserHead(t, buf, &req)
	promoteRequestHead(&req, head)
	firstUA := req.Header("User-Agent")
	firstPath := req.Path
	firstCookie := req.Header("Cookie")

	for i := 0; i < 64; i++ {
		perfPoison(buf)
		alt := strings.Replace(perfBrowserHead, "sid=abc123", "sid=zz"+strconv.Itoa(i%10)+"zzz", 1)
		alt = strings.Replace(alt, "/browser?x=1", "/other?y="+strconv.Itoa(i%10), 1)
		n := copy(buf, alt)
		req.resetFastH1()
		end, _, _, _, reject, _, _, ok := ParseH1RequestHead(buf[:n], &req, 0, 0)
		if !ok || reject {
			t.Fatal("alt head did not parse")
		}
		req.Host = req.cachedHost
		promoteRequestHead(&req, buf[:end])
	}
	perfPoison(buf)
	if firstUA != "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36" {
		t.Fatalf("retained User-Agent changed: %q", firstUA)
	}
	if firstPath != "/browser" {
		t.Fatalf("retained Path changed: %q", firstPath)
	}
	if firstCookie != "sid=abc123; theme=dark; lang=en" {
		t.Fatalf("retained Cookie changed: %q", firstCookie)
	}
}

func TestPerfZeroCopyArenaHeaderViewsSurviveParserReuse(t *testing.T) {
	var p h1Parser
	perfFillH1Parser(&p)
	kept := append([][2]string(nil), perfStringHeadersArena(&p)...)
	perfPoison(p.hdrBuf)
	perfFillH1Parser(&p)
	perfPoison(p.hdrBuf)
	for i, h := range kept {
		if h[1] != perfBackendHeaders[i][1] {
			t.Fatalf("arena header %d value changed after parser reuse: %q", i, h[1])
		}
		if h[0] != strings.ToLower(perfBackendHeaders[i][0]) {
			t.Fatalf("arena header %d name %q", i, h[0])
		}
	}
}
