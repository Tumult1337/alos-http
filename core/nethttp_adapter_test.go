//go:build linux && amd64

package core

import (
	"errors"
	"io"
	"net/http"
	"net/http/pprof"
	"strings"
	"testing"
	"testing/fstest"
)

func runWrapped(t *testing.T, h http.Handler, req *Request) *Response {
	t.Helper()
	resp := newTestResp()
	WrapHTTPHandler(h)(req, resp)
	return resp
}

func respHeaderValues(resp *Response, name string) []string {
	var out []string
	for _, h := range resp.Headers {
		if EqualFoldASCII(h[0], name) {
			out = append(out, h[1])
		}
	}
	return out
}

func TestWrapHTTPHandlerRequestConversion(t *testing.T) {
	var seen *http.Request
	var body string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	})
	req := &Request{
		Method: "POST", Path: "/items/42", RawPath: "/items/42?sort=desc&x=%20y", Query: "sort=desc&x=%20y",
		Proto: "HTTP/1.1", Host: "shop.test", RemoteAddr: "10.0.0.9:5555", Body: []byte("payload"),
		Headers: [][2]string{{"host", "shop.test"}, {"x-trace", "a"}, {"X-Trace", "b"}, {"content-type", "text/plain"}},
	}
	runWrapped(t, h, req)
	if seen.Method != "POST" || seen.URL.Path != "/items/42" || seen.URL.Query().Get("x") != " y" || seen.RequestURI != "/items/42?sort=desc&x=%20y" {
		t.Fatalf("method %q url %v requestURI %q", seen.Method, seen.URL, seen.RequestURI)
	}
	if seen.Host != "shop.test" || seen.RemoteAddr != "10.0.0.9:5555" || seen.Proto != "HTTP/1.1" || seen.ProtoMajor != 1 || seen.ProtoMinor != 1 {
		t.Fatalf("host %q remote %q proto %q", seen.Host, seen.RemoteAddr, seen.Proto)
	}
	if got := seen.Header.Values("X-Trace"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("X-Trace %q", got)
	}
	if seen.Header.Get("Host") != "" || seen.ContentLength != 7 || body != "payload" || seen.TLS != nil || seen.Context() == nil {
		t.Fatalf("host header %q length %d body %q tls %v", seen.Header.Get("Host"), seen.ContentLength, body, seen.TLS)
	}

	h2 := &Request{Method: "GET", Path: "/p", Proto: "HTTP/2", IsH2: true, IsTLS: true, TLSVersion: 0x0304}
	runWrapped(t, h, h2)
	if seen.Proto != "HTTP/2.0" || seen.ProtoMajor != 2 || seen.TLS == nil || seen.TLS.Version != 0x0304 || seen.URL.Path != "/p" {
		t.Fatalf("h2 request: proto %q tls %+v", seen.Proto, seen.TLS)
	}

	bad := &Request{Method: "GET", Path: "/p", RawPath: "/%zz"}
	if resp := runWrapped(t, h, bad); resp.StatusCode != 400 {
		t.Fatalf("unparseable target: status %d", resp.StatusCode)
	}
}

func TestWrapHTTPHandlerResponse(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("X-Multi", "one")
		w.Header().Add("X-Multi", "two")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "999")
		w.Header().Set("Connection", "close")
		w.Header().Set("X-Inject", "a\r\nSet-Cookie: x=1")
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusCreated)
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"a":`))
		_, _ = io.WriteString(w, `1}`)
	})
	resp := runWrapped(t, h, newTestReq())
	if resp.StatusCode != http.StatusCreated || string(resp.body) != `{"a":1}` || resp.ContentType != "application/json" {
		t.Fatalf("status %d body %q content type %q", resp.StatusCode, resp.body, resp.ContentType)
	}
	if got := respHeaderValues(resp, "x-multi"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("X-Multi %q", got)
	}
	if len(respHeaderValues(resp, "content-length")) != 0 || len(respHeaderValues(resp, "connection")) != 0 {
		t.Fatalf("Content-Length or Connection copied: %q", resp.Headers)
	}
	if v := respHeaderValues(resp, "x-inject"); len(v) != 1 || strings.ContainsAny(v[0], "\r\n") {
		t.Fatalf("X-Inject %q", v)
	}
}

func TestWrapHTTPHandlerDefaults(t *testing.T) {
	empty := runWrapped(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), newTestReq())
	if empty.StatusCode != 200 || len(empty.body) != 0 {
		t.Fatalf("empty handler: status %d body %q", empty.StatusCode, empty.body)
	}
	sniffed := runWrapped(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<!DOCTYPE html><html><body>hi</body></html>")
	}), newTestReq())
	if sniffed.ContentType != "text/html; charset=utf-8" {
		t.Fatalf("sniffed content type %q", sniffed.ContentType)
	}
	optedOut := runWrapped(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Type"] = nil
		_, _ = io.WriteString(w, "<html></html>")
	}), newTestReq())
	if optedOut.ContentType != "" {
		t.Fatalf("Content-Type set to nil was sniffed anyway: %q", optedOut.ContentType)
	}
	var hijackErr error
	runWrapped(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, hijackErr = w.(http.Hijacker).Hijack()
	}), newTestReq())
	if !errors.Is(hijackErr, errNetHTTPHijack) {
		t.Fatalf("Hijack: %v", hijackErr)
	}
}

func TestWrapHTTPHandlerStandardHandlers(t *testing.T) {
	files := fstest.MapFS{"hello.txt": {Data: []byte("hello from FileServer")}, "css/site.css": {Data: []byte("body{}")}}
	fileServer := http.FileServer(http.FS(files))
	resp := runWrapped(t, fileServer, &Request{Method: "GET", Path: "/hello.txt", Proto: "HTTP/1.1"})
	if resp.StatusCode != 200 || string(resp.body) != "hello from FileServer" || !strings.HasPrefix(resp.ContentType, "text/plain") {
		t.Fatalf("FileServer: status %d body %q type %q", resp.StatusCode, resp.body, resp.ContentType)
	}
	missing := runWrapped(t, fileServer, &Request{Method: "GET", Path: "/nope.txt", Proto: "HTTP/1.1"})
	if missing.StatusCode != 404 {
		t.Fatalf("FileServer missing file: status %d", missing.StatusCode)
	}
	stripped := runWrapped(t, http.StripPrefix("/static", fileServer), &Request{Method: "GET", Path: "/static/css/site.css", Proto: "HTTP/1.1"})
	if stripped.StatusCode != 200 || string(stripped.body) != "body{}" || !strings.HasPrefix(stripped.ContentType, "text/css") {
		t.Fatalf("StripPrefix: status %d body %q type %q", stripped.StatusCode, stripped.body, stripped.ContentType)
	}

	index := runWrapped(t, http.HandlerFunc(pprof.Index), &Request{Method: "GET", Path: "/debug/pprof/", Proto: "HTTP/1.1"})
	if index.StatusCode != 200 || !strings.Contains(string(index.body), "goroutine") || !strings.HasPrefix(index.ContentType, "text/html") {
		t.Fatalf("pprof.Index: status %d type %q", index.StatusCode, index.ContentType)
	}
	goroutines := runWrapped(t, http.HandlerFunc(pprof.Index), &Request{Method: "GET", Path: "/debug/pprof/goroutine", RawPath: "/debug/pprof/goroutine?debug=1", Query: "debug=1", Proto: "HTTP/1.1"})
	if goroutines.StatusCode != 200 || !strings.Contains(string(goroutines.body), "goroutine profile") {
		t.Fatalf("pprof goroutine: status %d body %.80q", goroutines.StatusCode, goroutines.body)
	}
}
