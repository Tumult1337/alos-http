//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	tlsEpollFixReadTimeout   = 300 * time.Millisecond
	tlsEpollFixDripInterval  = 100 * time.Millisecond
	tlsEpollFixDripLimit     = 2400 * time.Millisecond
	tlsEpollFixSmallReadCap  = 64 << 10
	tlsEpollFixIdleConns     = 16
	tlsEpollFixIdleBody      = 1 << 20
	tlsEpollFixIdleHeapSlack = 6 << 20
)

func TestTLSEpollFixSlowBodyBoundedByReadTimeout(t *testing.T) {
	ts := newTestServer(t, testServerOptions{
		Config: func(c *Config) { c.ReadTimeout = tlsEpollFixReadTimeout },
		Routes: func(r *Router) {
			r.POST("/upload", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
		},
	})
	for _, framing := range []string{"Content-Length: 1000\r\n", "Transfer-Encoding: chunked\r\n"} {
		t.Run(strings.TrimSpace(framing), func(t *testing.T) {
			t.Parallel()
			tlsEpollFixDripBody(t, ts, framing)
		})
	}
}

func tlsEpollFixDripBody(t *testing.T, ts *testServer, framing string) {
	c := ts.dial(t)
	_ = c.SetDeadline(wallDeadline(tlsEpollFixDripLimit + time.Second))
	if _, err := io.WriteString(c, "POST /upload HTTP/1.1\r\nHost: x\r\n"+framing+"\r\n"); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(framing, "Transfer") {
		if _, err := io.WriteString(c, "3e8\r\n"); err != nil {
			t.Fatal(err)
		}
	}
	start := turbo.Now()
	for turbo.Since(start) < tlsEpollFixDripLimit {
		if _, err := c.Write([]byte{'b'}); err != nil {
			return
		}
		_ = c.SetReadDeadline(wallDeadline(tlsEpollFixDripInterval))
		if _, err := c.Read(make([]byte, 1)); err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				return
			}
		}
	}
	t.Fatalf("a body trickled one byte per %v stayed open for %v with ReadTimeout %v", tlsEpollFixDripInterval, tlsEpollFixDripLimit, tlsEpollFixReadTimeout)
}

func TestTLSEpollFixBodyAboveReadCapGets413(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		ts := newTestServer(t, testServerOptions{
			TLS:    useTLS,
			Config: func(c *Config) { c.MaxReadSize = tlsEpollFixSmallReadCap; c.MaxBodySize = 4 * tlsEpollFixSmallReadCap },
			Routes: func(r *Router) {
				r.POST("/upload", func(req *Request, resp *Response) { resp.Status(200).String(strconv.Itoa(len(req.Body))) })
			},
		})
		resp, body := ts.rawH1(t, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: "+strconv.Itoa(2*tlsEpollFixSmallReadCap)+"\r\n\r\n")
		if resp.StatusCode != 413 {
			t.Fatalf("tls=%v: body above the read cap answered %d %q, want 413", useTLS, resp.StatusCode, body)
		}
		small := strings.Repeat("s", tlsEpollFixSmallReadCap/2)
		resp, body = ts.rawH1(t, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: "+strconv.Itoa(len(small))+"\r\n\r\n"+small)
		if resp.StatusCode != 200 || string(body) != strconv.Itoa(len(small)) {
			t.Fatalf("tls=%v: body under the read cap answered %d %q", useTLS, resp.StatusCode, body)
		}
	}
}

func TestTLSEpollFixRootFastPathAnswers503WhenSaturated(t *testing.T) {
	h := newBlockingHandler()
	ts := newTestServer(t, testServerOptions{
		Config: func(c *Config) { c.MaxConcurrentReqs = 1 },
		Routes: func(r *Router) {
			r.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("root") })
			h.route(r)
		},
	})
	if ts.srv.plainRootFast.Load() == nil {
		t.Fatal("root fast path not active; the test would not exercise it")
	}
	blocked := ts.dial(t)
	if _, err := io.WriteString(blocked, "GET /block HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	h.awaitEntered(t)
	c := ts.dial(t)
	_ = c.SetDeadline(wallDeadline(harnessIOTimeout))
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, body := readH1Response(t, br, "GET")
	if resp.StatusCode != 503 {
		t.Fatalf("saturated GET / answered %d %q, want 503", resp.StatusCode, body)
	}
	close(h.release)
	if resp, body := readH1Response(t, bufio.NewReader(blocked), "GET"); resp.StatusCode != 200 {
		t.Fatalf("blocked request answered %d %q", resp.StatusCode, body)
	}
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if resp, body = readH1Response(t, br, "GET"); resp.StatusCode != 200 || string(body) != "root" {
		t.Fatalf("keep-alive GET / after the slot freed answered %d %q", resp.StatusCode, body)
	}
}

func tlsEpollFixHeapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

func TestTLSEpollFixIdleConnReleasesBodyCopy(t *testing.T) {
	ts := newTestServer(t, testServerOptions{Routes: func(r *Router) {
		r.POST("/upload", func(req *Request, resp *Response) { resp.Status(200).String(strconv.Itoa(len(req.Body))) })
	}})
	body := strings.Repeat("u", tlsEpollFixIdleBody)
	request := "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	before := tlsEpollFixHeapInUse()
	for i := 0; i < tlsEpollFixIdleConns; i++ {
		c := ts.dial(t)
		if _, err := io.WriteString(c, request); err != nil {
			t.Fatal(err)
		}
		if resp, got := readH1Response(t, bufio.NewReader(c), "POST"); resp.StatusCode != 200 || string(got) != strconv.Itoa(len(body)) {
			t.Fatalf("upload %d answered %d %q", i, resp.StatusCode, got)
		}
	}
	request, body = "", ""
	grown := int64(tlsEpollFixHeapInUse()) - int64(before)
	if grown > tlsEpollFixIdleHeapSlack {
		t.Fatalf("%d idle keep-alive conns still hold %d KiB after one %d KiB upload each", tlsEpollFixIdleConns, grown>>10, tlsEpollFixIdleBody>>10)
	}
}
