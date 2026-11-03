//go:build linux && amd64

package core

import (
	"bufio"
	"net/http"
	"strconv"
	"testing"
)

const routerE2EBody = "hello"

func startRouterMethodsServer(t *testing.T, plainH2 bool) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		Config: func(cfg *Config) { cfg.PlainHTTP = plainH2 },
		Routes: func(r *Router) {
			r.GET("/a", func(req *Request, resp *Response) {
				resp.SetHeader("X-A", "1")
				resp.Status(200).String(routerE2EBody)
			})
		},
	})
}

func TestRouterMethodsOverHTTP1(t *testing.T) {
	ts := startRouterMethodsServer(t, false)
	c := ts.dial(t)
	br := bufio.NewReader(c)
	host := "Host: " + ts.domain + "\r\n"
	writeAll(t, c, "HEAD /a HTTP/1.1\r\n"+host+"\r\nGET /a HTTP/1.1\r\n"+host+"\r\nOPTIONS /a HTTP/1.1\r\n"+host+"\r\nPOST /a HTTP/1.1\r\n"+host+"Content-Length: 0\r\n\r\n")

	head, body := readH1Response(t, br, http.MethodHead)
	if head.StatusCode != 200 || len(body) != 0 || head.Header.Get("X-A") != "1" {
		t.Fatalf("HEAD: %d body %q headers %v", head.StatusCode, body, head.Header)
	}
	if got := head.Header.Get("Content-Length"); got != strconv.Itoa(len(routerE2EBody)) {
		t.Fatalf("HEAD Content-Length %q, want %d", got, len(routerE2EBody))
	}

	get, body := readH1Response(t, br, http.MethodGet)
	if get.StatusCode != 200 || string(body) != routerE2EBody {
		t.Fatalf("GET after HEAD: %d %q (HEAD leaked a body?)", get.StatusCode, body)
	}

	opts, body := readH1Response(t, br, http.MethodOptions)
	if opts.StatusCode != 204 || opts.Header.Get("Allow") != "GET, HEAD, OPTIONS" || len(body) != 0 {
		t.Fatalf("OPTIONS: %d allow %q body %q", opts.StatusCode, opts.Header.Get("Allow"), body)
	}

	post, _ := readH1Response(t, br, http.MethodPost)
	if post.StatusCode != 405 || post.Header.Get("Allow") != "GET, HEAD, OPTIONS" {
		t.Fatalf("POST: %d allow %q", post.StatusCode, post.Header.Get("Allow"))
	}
}

func TestRouterHEADOverHTTP2SendsNoData(t *testing.T) {
	ts := startRouterMethodsServer(t, true)
	rc := dialCancelH2(t, ts)
	var enc HpackEncoder
	enc.EncodeHeader(":method", "HEAD")
	enc.EncodeHeader(":scheme", "http")
	enc.EncodeHeader(":path", "/a")
	enc.EncodeHeader(":authority", cancelH2Authority)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, enc.Buf)
	for {
		f := rc.read()
		if f.streamID != 1 {
			continue
		}
		if f.typ == H2FrameData && len(f.payload) > 0 {
			t.Fatalf("HEAD over HTTP/2 sent %d body bytes", len(f.payload))
		}
		if f.typ == H2FrameHeaders {
			if status := f.status(t); status != 200 {
				t.Fatalf("HEAD status %d", status)
			}
		}
		if f.flags&H2FlagEndStream != 0 {
			return
		}
	}
}
