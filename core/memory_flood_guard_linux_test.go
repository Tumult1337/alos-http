//go:build linux && amd64

package core

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestH1ConnectionsShareBodyBudget(t *testing.T) {
	srv := New(Config{MaxInFlightBodyBytes: 1024, MaxConnsPerIP: -1})
	w := &epollWorker{server: srv}
	a := &epollConn{worker: w}
	b := &epollConn{worker: w}
	if !a.reserveH1BodyBudget(srv, 768) {
		t.Fatal("first H1 body should reserve capacity")
	}
	if b.reserveH1BodyBudget(srv, 257) {
		t.Fatal("second H1 body exceeded the aggregate capacity")
	}
	a.releaseH1BodyBudget()
	if !b.reserveH1BodyBudget(srv, 1024) {
		t.Fatal("released H1 body capacity was not reusable")
	}
	b.releaseH1BodyBudget()
}

func TestChunkedBufferedBodyUsesSmallerReadCap(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(fmt.Sprintf("oversized=%v", oversized), func(t *testing.T) {
			w, c, peer := h1ReceivedFixture(t, Config{MaxBodySize: 100 << 20, MaxReadSize: 2 * epollReadBufCap, InlineHandlers: true})
			w.server.Router.POST("/body", func(req *Request, resp *Response) { resp.Status(200).Bytes(req.Body) })
			w.server.Router.Build()
			w.server.computeFastDispatch()
			body := "hello"
			if oversized {
				body = strings.Repeat("x", 3*epollReadBufCap)
			}
			wire := fmt.Sprintf("POST /body HTTP/1.1\r\nHost: body.test\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body)
			if n, err := unix.Write(peer, []byte(wire)); err != nil || n != len(wire) {
				t.Fatalf("write %d/%d: %v", n, len(wire), err)
			}
			w.readable(c, false)
			if oversized {
				if c.fd >= 0 {
					t.Fatal("buffered chunked upload bypassed smaller read cap")
				}
			} else {
				output := make([]byte, epollReadBufCap)
				length, err := unix.Read(peer, output)
				if err != nil || !bytes.Contains(output[:length], []byte("200 OK")) || !bytes.HasSuffix(output[:length], []byte("hello")) {
					t.Fatalf("valid below-cap upload: output=%q error=%v", output[:max(0, length)], err)
				}
			}
			if held := w.server.inFlightBodyBytes.Load(); held != 0 {
				t.Fatalf("finished/rejected upload retained %d bytes", held)
			}
		})
	}
}
