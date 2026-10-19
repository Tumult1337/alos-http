//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

var appFixCompressibleBody = strings.Repeat("compress me please ", 200)

func appFixCompressed(method string, status int, headers ...[2]string) *Response {
	req := &Request{Method: method, Path: "/f", Headers: [][2]string{{"Accept-Encoding", "gzip"}}}
	resp := &Response{}
	resp.Reset()
	resp.lazyReq = req
	resp.Status(status).String(appFixCompressibleBody)
	for _, h := range headers {
		resp.SetHeaderUnsafe(h[0], h[1])
	}
	applyConfiguredCompression(req, resp, CompressConfig{})
	return resp
}

func TestAppFixCompressSkipsPartialContent(t *testing.T) {
	resp := appFixCompressed("GET", 206, [2]string{"Content-Range", "bytes 0-3799/9000"})
	if len(appFixHeaderValues(resp, "content-encoding")) != 0 || resp.BodyLen() != len(appFixCompressibleBody) {
		t.Fatalf("206 partial body was compressed: encoding %q, body %d bytes", appFixHeaderValues(resp, "content-encoding"), resp.BodyLen())
	}
	resp = appFixCompressed("GET", 200, [2]string{"Content-Range", "bytes 0-3799/3800"})
	if len(appFixHeaderValues(resp, "content-encoding")) != 0 {
		t.Fatal("a response carrying Content-Range was compressed")
	}
}

func TestAppFixCompressWeakensStrongETag(t *testing.T) {
	resp := appFixCompressed("GET", 200, [2]string{"ETag", `"v1"`})
	if enc := appFixHeaderValues(resp, "content-encoding"); len(enc) != 1 {
		t.Fatalf("expected gzip, got %q", enc)
	}
	if etag := appFixHeaderValues(resp, "etag"); len(etag) != 1 || etag[0] != `W/"v1"` {
		t.Fatalf("compressed variant kept ETag %q, want W/\"v1\"", etag)
	}
	if etag := appFixHeaderValues(appFixCompressed("GET", 200, [2]string{"ETag", `W/"v2"`}), "etag"); etag[0] != `W/"v2"` {
		t.Fatalf("weak ETag rewritten to %q", etag[0])
	}
}

func TestAppFixCompressHeadMatchesGet(t *testing.T) {
	get := appFixCompressed("GET", 200)
	head := appFixCompressed("HEAD", 200)
	if enc := appFixHeaderValues(head, "content-encoding"); len(enc) != 1 || enc[0] != appFixHeaderValues(get, "content-encoding")[0] {
		t.Fatalf("HEAD Content-Encoding %q differs from GET %q", enc, appFixHeaderValues(get, "content-encoding"))
	}
	if head.BodyLen() != get.BodyLen() {
		t.Fatalf("HEAD advertises %d bytes, GET sends %d", head.BodyLen(), get.BodyLen())
	}
}
