//go:build linux && amd64

package core

import (
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	proxyFix2HugeContentLength  = 1 << 50
	proxyFix2LargeContentLength = 64 << 20
	proxyFix2BodyAllocCeiling   = 1 << 20
)

func proxyFix2ReadRouteBodyFromClosedPeer(contentLength int) (allocated uint64, panicked any) {
	raw := []byte(fmt.Sprintf("POST /public/x HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\nabc", contentLength))
	headerEnd := len(raw) - len("abc")
	server, client := net.Pipe()
	client.Close()
	defer server.Close()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	func() {
		defer func() { panicked = recover() }()
		_, _ = readHTTPRouteBody(server, raw, headerEnd, contentLength, false)
	}()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, panicked
}

func TestProxyFix2Port80RouteBodyHugeContentLengthDoesNotPanic(t *testing.T) {
	if _, p := proxyFix2ReadRouteBodyFromClosedPeer(proxyFix2HugeContentLength); p != nil {
		t.Fatalf("Content-Length %d with 3 body bytes received panicked: %v", proxyFix2HugeContentLength, p)
	}
}

func TestProxyFix2Port80RouteUnlimitedBodySurvivesHugeContentLength(t *testing.T) {
	o := newProxyFixRecordingOrigin(t)
	_, _, httpAddr := proxyFixStartTLS(t, Config{MaxConnsPerIP: -1, MaxBodySize: -1, MaxReadSize: -1}, func(s *Server) {
		s.SetHTTPRoutes([]HTTPRoute{{PathPrefix: proxyFixRoutePrefix, Backend: o.addr()}})
	})
	head := fmt.Sprintf("POST /public/x HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\nabc", proxyFixTLSDomain, proxyFix2HugeContentLength)
	c := proxyFixDial(t, httpAddr)
	if _, err := io.WriteString(c, head); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.(*net.TCPConn).CloseWrite()
	_, _ = io.ReadAll(c)
	c.Close()
	out := proxyFixRawExchange(t, httpAddr, "GET /public/ok HTTP/1.1\r\nHost: "+proxyFixTLSDomain+"\r\n\r\n")
	if !strings.HasSuffix(out, "BACKEND:/public/ok") {
		t.Fatalf("route after a huge Content-Length answered %q", out)
	}
}

func TestProxyFix2Port80RouteBodyNotPresizedFromContentLength(t *testing.T) {
	allocated, p := proxyFix2ReadRouteBodyFromClosedPeer(proxyFix2LargeContentLength)
	if p != nil {
		t.Fatalf("panicked: %v", p)
	}
	if allocated > proxyFix2BodyAllocCeiling {
		t.Fatalf("Content-Length %d with 3 body bytes received allocated %d bytes, want <= %d", proxyFix2LargeContentLength, allocated, proxyFix2BodyAllocCeiling)
	}
}

var proxyFix2CanonicalDotNamedTargets = []string{
	"/public/.well-known/",
	"/public/static/.vite/",
	"/public/docs/.hidden/?v=1",
}

func TestProxyFix2Port80RouteAcceptsTrailingSlashAfterDotNamedSegment(t *testing.T) {
	_, addr := proxyFixPort80Route(t)
	for _, target := range proxyFix2CanonicalDotNamedTargets {
		out := proxyFixRawExchange(t, addr, "GET "+target+" HTTP/1.1\r\nHost: "+proxyFixTLSDomain+"\r\n\r\n")
		if !strings.HasPrefix(out, "HTTP/1.1 200") || !strings.HasSuffix(out, "BACKEND:"+target) {
			t.Errorf("legal target %s on a port-80 route answered %q", target, firstLine(out))
		}
	}
}

func TestProxyFix2PlainListenerRouteAcceptsTrailingSlashAfterDotNamedSegment(t *testing.T) {
	o := newProxyFixRecordingOrigin(t)
	_, addr := proxyFixStart(t, Config{}, nil, func(s *Server) {
		s.SetHTTPRoutes([]HTTPRoute{{PathPrefix: proxyFixRoutePrefix, Backend: o.addr()}})
	})
	for _, target := range proxyFix2CanonicalDotNamedTargets {
		if _, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, target)); body != "BACKEND:"+target {
			t.Errorf("legal target %s on the plain listener route answered %q", target, body)
		}
	}
}

func TestProxyFix2HTTPRouteTargetSafeRejectsNonCanonicalSegments(t *testing.T) {
	for target, want := range map[string]bool{
		"/":                    true,
		"/public/":             true,
		"/public/a/.b/":        true,
		"/public/a..b/c.":      true,
		"/public/.well-known/": true,
		"/public/x?y=/../":     true,
		"/public/.":            false,
		"/public/./x":          false,
		"/public/..":           false,
		"/public/x/../":        false,
		"/public//x":           false,
		"//public/x":           false,
		"/public/%2e%2e/x":     false,
		"/public/a%2Fb":        false,
		`/public/a\b`:          false,
		"*":                    false,
	} {
		req := &Request{}
		raw := "GET " + target + " HTTP/1.1\r\nHost: h\r\n\r\n"
		if _, _, _, _, _, _, _, ok := parseH1RequestHead([]byte(raw), req, 8192, 64); !ok {
			t.Fatalf("parse %q failed", target)
		}
		if got := httpRouteTargetSafe(req); got != want {
			t.Errorf("httpRouteTargetSafe(%q) = %v, want %v", target, got, want)
		}
	}
}

const (
	proxyFix2ChunkedBody     = "hello world"
	proxyFix2ChunkedEncoding = "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n"
	proxyFix2ChunkedSmallMax = 8
)

func proxyFix2ChunkedPost(target string) string {
	return "POST " + target + " HTTP/1.1\r\nHost: " + proxyFixTLSDomain + "\r\nTransfer-Encoding: chunked\r\n\r\n"
}

func TestProxyFix2Port80RouteDechunksChunkedBody(t *testing.T) {
	o, addr := proxyFixPort80Route(t)
	c := proxyFixDial(t, addr)
	defer c.Close()
	split := len(proxyFix2ChunkedEncoding) / 2
	if _, err := io.WriteString(c, proxyFix2ChunkedPost("/public/up")+proxyFix2ChunkedEncoding[:split]); err != nil {
		t.Fatalf("write head: %v", err)
	}
	time.Sleep(proxyFixStep)
	if _, err := io.WriteString(c, proxyFix2ChunkedEncoding[split:]); err != nil {
		t.Fatalf("write rest: %v", err)
	}
	out, _ := io.ReadAll(c)
	if !strings.HasPrefix(string(out), "HTTP/1.1 200") || !strings.HasSuffix(string(out), "BACKEND:/public/up") {
		t.Fatalf("chunked upload on a port-80 route answered %q", firstLine(string(out)))
	}
	reqs := o.requests()
	if len(reqs) != 1 || string(reqs[0].body) != proxyFix2ChunkedBody {
		t.Fatalf("backend received %d requests, want one with body %q", len(reqs), proxyFix2ChunkedBody)
	}
}

func TestProxyFix2Port80RouteRejectsMalformedChunkedBody(t *testing.T) {
	o, addr := proxyFixPort80Route(t)
	out := proxyFixRawExchange(t, addr, proxyFix2ChunkedPost("/public/up")+"zz\r\nhello\r\n0\r\n\r\n")
	if !strings.HasPrefix(out, "HTTP/1.1 400") {
		t.Fatalf("malformed chunked upload answered %q, want 400", firstLine(out))
	}
	if n := len(o.requests()); n != 0 {
		t.Fatalf("malformed chunked upload reached the backend %d times", n)
	}
}

func TestProxyFix2Port80RouteChunkedBodyHonoursMaxBodySize(t *testing.T) {
	o := newProxyFixRecordingOrigin(t)
	_, _, httpAddr := proxyFixStartTLS(t, Config{MaxConnsPerIP: -1, MaxBodySize: proxyFix2ChunkedSmallMax}, func(s *Server) {
		s.SetHTTPRoutes([]HTTPRoute{{PathPrefix: proxyFixRoutePrefix, Backend: o.addr()}})
	})
	out := proxyFixRawExchange(t, httpAddr, proxyFix2ChunkedPost("/public/up")+proxyFix2ChunkedEncoding)
	if !strings.HasPrefix(out, "HTTP/1.1 413") {
		t.Fatalf("chunked upload over MaxBodySize answered %q, want 413", firstLine(out))
	}
	if n := len(o.requests()); n != 0 {
		t.Fatalf("oversized chunked upload reached the backend %d times", n)
	}
}
