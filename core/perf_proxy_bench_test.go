//go:build linux && amd64

package core

import (
	"crypto/tls"
	"runtime"
	"testing"
)

const (
	perfProxyPath            = "/bench?q=1"
	perfProxySocketAllocsMax = 0.05
)

var perfProxySizes = []perfSize{
	{"13B", 13},
	{"64KB", proxyBufferedResponseLimit},
	{"128KB-stream", 2 * proxyBufferedResponseLimit},
}

func perfProxyDriver(tb testing.TB, tr perfTransport, bodySize int) func(n int) {
	tb.Helper()
	origin := zeroAllocOrigin(tb, bodySize)
	if !tr.tls {
		domains := []DomainConfig{{Domain: proxyFixDomain, Backends: []BackendConfig{{Addr: origin}}}}
		_, addr := proxyFixStart(tb, Config{}, domains, nil)
		return proxyFixKeepAliveConnDriver(tb, perfDialRaw(tb, addr), proxyFixDomain, perfProxyPath)
	}
	_, httpsAddr, _ := proxyFixStartTLS(tb, Config{MaxConnsPerIP: -1}, func(s *Server) {
		s.AddProxyDomain(DomainConfig{Domain: proxyFixTLSDomain, Backends: []BackendConfig{{Addr: origin}}})
	})
	conn := perfDialTLSClient(tb, httpsAddr, &tls.Config{
		InsecureSkipVerify: true, ServerName: proxyFixTLSDomain, NextProtos: []string{"http/1.1"},
	})
	return proxyFixKeepAliveConnDriver(tb, conn, proxyFixTLSDomain, perfProxyPath)
}

func BenchmarkPerfProxyRoundTrip(b *testing.B) {
	for _, tr := range perfTransports {
		for _, sz := range perfProxySizes {
			b.Run(tr.name+"/"+sz.name, func(b *testing.B) {
				if raceEnabled {
					b.Skip("the race detector distorts per-request cost")
				}
				drive := perfProxyDriver(b, tr, sz.size)
				drive(proxyFixBenchWarmup)
				b.SetBytes(int64(sz.size))
				b.ReportAllocs()
				for b.Loop() {
					drive(1)
				}
			})
		}
	}
}

func perfAllocsPerCall(runs int, call func()) float64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		call()
	}
	runtime.ReadMemStats(&after)
	return float64(after.Mallocs-before.Mallocs) / float64(runs)
}

func TestPerfProxyRoundTripAllocLock(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation")
	}
	for _, tr := range perfTransports {
		for _, sz := range perfProxySizes {
			t.Run(tr.name+"/"+sz.name, func(t *testing.T) {
				drive := perfProxyDriver(t, tr, sz.size)
				drive(proxyFixBenchWarmup)
				got := perfAllocsPerCall(perfSocketLockRuns, func() { drive(1) })
				t.Logf("%s %s: %.3f allocs per proxied request (client, proxy and origin in one process)", tr.name, sz.name, got)
				if got > perfProxySocketAllocsMax {
					t.Fatalf("%.3f allocs per proxied request; the in-loop proxy path must stay allocation-free", got)
				}
			})
		}
	}
}

type perfProxyRequestCase struct {
	name    string
	headers [][2]string
}

var perfProxyBrowserHeaders = [][2]string{
	{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"},
	{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
	{"Accept-Language", "en-US,en;q=0.9"},
	{"Accept-Encoding", "gzip, deflate, br"},
	{"Connection", "keep-alive"},
	{"Upgrade-Insecure-Requests", "1"},
	{"Sec-Fetch-Dest", "document"},
	{"Sec-Fetch-Mode", "navigate"},
	{"Sec-Fetch-Site", "none"},
	{"Sec-Fetch-User", "?1"},
	{"Cache-Control", "max-age=0"},
	{"Sec-Ch-Ua", `"Chromium";v="124", "Not-A.Brand";v="99"`},
	{"Sec-Ch-Ua-Mobile", "?0"},
	{"Sec-Ch-Ua-Platform", `"Linux"`},
	{"Cookie", "sid=abc123; theme=dark; lang=en"},
}

var perfProxyRequestCases = []perfProxyRequestCase{
	{"minimal", nil},
	{"browser", perfProxyBrowserHeaders},
	{"connection-close", [][2]string{{"Connection", "close"}}},
	{"nominated", [][2]string{{"Connection", "x-trace"}, {"X-Trace", "1"}, {"Accept", "*/*"}}},
}

func perfProxyRequest(headers [][2]string) *Request {
	req := newTestReq()
	req.Host = proxyFixDomain
	req.Path = "/bench"
	req.Query = "q=1"
	req.RawPath = perfProxyPath
	req.RemoteAddr = "127.0.0.1:41234"
	req.Headers = append(req.Headers, headers...)
	return req
}

func BenchmarkPerfProxyAppendRequest(b *testing.B) {
	for _, rc := range perfProxyRequestCases {
		b.Run(rc.name, func(b *testing.B) {
			req := perfProxyRequest(rc.headers)
			dst := appendProxyRequest(nil, req, proxyFixDomain)
			b.ReportAllocs()
			for b.Loop() {
				dst = appendProxyRequest(dst[:0], req, proxyFixDomain)
			}
		})
	}
}

var perfProxyOriginHead = []byte("HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\nDate: Mon, 19 Oct 2026 00:00:00 GMT\r\nServer: origin\r\nCache-Control: no-cache\r\nX-Request-Id: 0123456789abcdef")

func BenchmarkPerfProxyParseResponseHead(b *testing.B) {
	var p h1Parser
	b.ReportAllocs()
	for b.Loop() {
		p.hdr = p.hdr[:0]
		if _, n, err := p.parseHeaderBlock(perfProxyOriginHead, "GET"); err != nil || n != 13 {
			b.Fatalf("parse: n=%d err=%v", n, err)
		}
	}
}

func BenchmarkPerfProxyResponseHead(b *testing.B) {
	var p h1Parser
	if _, _, err := p.parseHeaderBlock(perfProxyOriginHead, "GET"); err != nil {
		b.Fatal(err)
	}
	headers := respHeaders{raw: p.hdr}
	dst := appendProxyResponseHead(nil, 200, headers, 13, true, "")
	b.Run("buffered", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			dst = appendProxyResponseHead(dst[:0], 200, headers, 13, true, "")
		}
	})
	b.Run("stream", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			dst = appendProxyStreamHead(dst[:0], 200, headers, -1, true)
		}
	})
}

func TestPerfProxySerializationAllocLock(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation")
	}
	for _, rc := range perfProxyRequestCases[:2] {
		req := perfProxyRequest(rc.headers)
		dst := appendProxyRequest(nil, req, proxyFixDomain)
		if got := testing.AllocsPerRun(perfAllocLockRuns, func() { dst = appendProxyRequest(dst[:0], req, proxyFixDomain) }); got != 0 {
			t.Errorf("appendProxyRequest %s: %.0f allocs, want 0", rc.name, got)
		}
	}
	var p h1Parser
	if got := testing.AllocsPerRun(perfAllocLockRuns, func() {
		p.hdr = p.hdr[:0]
		_, _, _ = p.parseHeaderBlock(perfProxyOriginHead, "GET")
	}); got != 0 {
		t.Errorf("parseHeaderBlock: %.0f allocs, want 0", got)
	}
	headers := respHeaders{raw: p.hdr}
	dst := appendProxyResponseHead(nil, 200, headers, 13, true, "")
	if got := testing.AllocsPerRun(perfAllocLockRuns, func() {
		dst = appendProxyResponseHead(dst[:0], 200, headers, 13, true, "")
		dst = appendProxyStreamHead(dst[:0], 200, headers, -1, true)
	}); got != 0 {
		t.Errorf("response head serialisation: %.0f allocs, want 0", got)
	}
}
