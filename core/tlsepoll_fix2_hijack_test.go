//go:build linux && amd64

package core

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

const tlsEpollFix2PipelinedLen = 2048

func tlsEpollFix2CloseWithoutWritingRoutes(r *Router) {
	r.GET("/a", func(req *Request, resp *Response) {
		resp.Status(200).String(strings.Repeat("A", tlsEpollFix2PipelinedLen))
	})
	r.GET("/hijack-close", func(req *Request, resp *Response) {
		if conn := req.HijackConn(); conn != nil {
			_ = conn.Close()
			return
		}
		resp.Status(500).String("no hijack")
	})
	r.GET("/stream-nothing", func(req *Request, resp *Response) {
		if resp.EnsureStreamWriter() == nil {
			resp.Status(500).String("no stream")
		}
	})
}

func TestTLSEpollFix2HandoffCloseDeliversEarlierPipelinedResponse(t *testing.T) {
	for _, inline := range []bool{false, true} {
		for _, useTLS := range []bool{false, true} {
			ts := newTestServer(t, testServerOptions{TLS: useTLS, Routes: tlsEpollFix2CloseWithoutWritingRoutes, Config: func(c *Config) { c.InlineHandlers = inline }})
			versions := []uint16{0}
			if useTLS {
				versions = tlsEpollFixVersions()
			}
			for _, v := range versions {
				for _, path := range []string{"/hijack-close", "/stream-nothing"} {
					t.Run(fmt.Sprintf("inline=%v/tls=%v/%s%s", inline, useTLS, tls.VersionName(v), path), func(t *testing.T) {
						var conn net.Conn
						if useTLS {
							conn, _ = tlsEpollFixDialTapped(t, ts, v)
						} else {
							conn = ts.dial(t)
						}
						if _, err := io.WriteString(conn, "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET "+path+" HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
							t.Fatal(err)
						}
						resp, body := readH1Response(t, bufio.NewReader(conn), "GET")
						if resp.StatusCode != 200 || len(body) != tlsEpollFix2PipelinedLen {
							t.Fatalf("response before a handoff closed without writing: %d with %d bytes, want 200 with %d", resp.StatusCode, len(body), tlsEpollFix2PipelinedLen)
						}
					})
				}
			}
		}
	}
}
