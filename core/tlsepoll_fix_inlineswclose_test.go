//go:build linux && amd64

package core

import (
	"bufio"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

func TestTLSEpollFixInlineStreamWriterWithoutSetStreamerClosesConn(t *testing.T) {
	routes := func(r *Router) {
		r.GET("/sw", func(req *Request, resp *Response) {
			sw := resp.EnsureStreamWriter()
			if sw == nil {
				resp.Status(500).String("no stream")
				return
			}
			_ = sw.WriteHeader(200, nil, "text/plain")
			_ = sw.WriteChunk([]byte("streamed"))
			_ = sw.Close()
		})
		r.GET("/set", func(req *Request, resp *Response) {
			sw := resp.EnsureStreamWriter()
			if sw == nil {
				resp.Status(500).String("no stream")
				return
			}
			_ = sw.WriteHeader(200, nil, "text/plain")
			resp.SetStreamer(sw)
			_ = sw.WriteChunk([]byte("streamed"))
			_ = sw.Close()
		})
	}
	ts := newTestServer(t, testServerOptions{Routes: routes, Config: func(c *Config) { c.InlineHandlers = true }})
	for _, path := range []string{"/sw", "/set"} {
		conn := ts.dial(t)
		if _, err := io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(conn)
		resp, body := readH1Response(t, br, "GET")
		if resp.StatusCode != 200 || string(body) != "streamed" {
			t.Fatalf("%s: status %d body %q", path, resp.StatusCode, body)
		}
		_ = conn.SetReadDeadline(time.Unix(0, turbo.UnixNano()+int64(2*time.Second)))
		_, err := br.ReadByte()
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("%s: server kept the taken-over conn open after the handler returned", path)
		}
		if err != io.EOF {
			t.Fatalf("%s: want EOF after the streamed response, got %v", path, err)
		}
		_ = conn.Close()
	}
}
