//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

const (
	tlsEpollFixHijackSecret = "SECRET-TOKEN-0xC0FFEE"
	tlsEpollFixPingLen      = 5
	tlsEpollFixPipelinedA   = 200000
)

type tlsEpollFixWireTap struct {
	net.Conn
	mu   sync.Mutex
	seen bytes.Buffer
}

func (c *tlsEpollFixWireTap) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.seen.Write(b[:n])
	c.mu.Unlock()
	return n, err
}

func (c *tlsEpollFixWireTap) wire() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.seen.Bytes()...)
}

func tlsEpollFixHijackRoutes(injected chan<- string) func(*Router) {
	return func(r *Router) {
		r.GET("/a", func(req *Request, resp *Response) {
			resp.Status(200).String(strings.Repeat("A", tlsEpollFixPipelinedA))
		})
		r.GET("/hj", func(req *Request, resp *Response) {
			conn := req.HijackConn()
			if conn == nil {
				resp.Status(500).String("no hijack")
				return
			}
			defer conn.Close()
			if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n\r\n"+tlsEpollFixHijackSecret); err != nil {
				return
			}
			ping := make([]byte, tlsEpollFixPingLen)
			_ = conn.SetReadDeadline(wallDeadline(harnessIOTimeout))
			if _, err := io.ReadFull(conn, ping); err != nil {
				if injected != nil {
					injected <- "error"
				}
				return
			}
			if injected != nil {
				injected <- string(ping)
			}
			_, _ = io.WriteString(conn, "pong:"+string(ping))
		})
		r.GET("/stream", func(req *Request, resp *Response) {
			sw := resp.EnsureStreamWriter()
			if sw == nil {
				resp.Status(500).String("no stream")
				return
			}
			_ = sw.WriteHeader(200, nil, "text/plain")
			_ = sw.WriteChunk([]byte(tlsEpollFixHijackSecret))
			_ = sw.Close()
		})
	}
}

func tlsEpollFixDialTapped(t *testing.T, ts *testServer, version uint16) (*tls.Conn, *tlsEpollFixWireTap) {
	t.Helper()
	raw, err := (&net.Dialer{Timeout: harnessIOTimeout}).Dial("tcp4", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	tap := &tlsEpollFixWireTap{Conn: raw}
	cfg := ts.tlsConfig("http/1.1")
	cfg.MinVersion, cfg.MaxVersion = version, version
	tc := tls.Client(tap, cfg)
	t.Cleanup(func() { _ = tc.Close() })
	_ = tc.SetDeadline(wallDeadline(harnessIOTimeout))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tc, tap
}

func tlsEpollFixVersions() []uint16 { return []uint16{tls.VersionTLS12, tls.VersionTLS13} }

func TestTLSEpollFixHijackedTLSConnStaysEncrypted(t *testing.T) {
	for _, inline := range []bool{false, true} {
		ts := newTestServer(t, testServerOptions{TLS: true, Routes: tlsEpollFixHijackRoutes(nil), Config: func(c *Config) { c.InlineHandlers = inline }})
		for _, v := range tlsEpollFixVersions() {
			t.Run(tls.VersionName(v), func(t *testing.T) {
				tc, tap := tlsEpollFixDialTapped(t, ts, v)
				if _, err := io.WriteString(tc, "GET /hj HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				want := "HTTP/1.1 101 Switching Protocols\r\n\r\n" + tlsEpollFixHijackSecret
				got := make([]byte, len(want))
				if _, err := io.ReadFull(tc, got); err != nil || string(got) != want {
					t.Fatalf("inline=%v: hijacked response %q err=%v", inline, got, err)
				}
				if _, err := io.WriteString(tc, "ping!"); err != nil {
					t.Fatal(err)
				}
				echo := make([]byte, len("pong:ping!"))
				if _, err := io.ReadFull(tc, echo); err != nil || string(echo) != "pong:ping!" {
					t.Fatalf("inline=%v: echo %q err=%v", inline, echo, err)
				}
				if wire := tap.wire(); bytes.Contains(wire, []byte(tlsEpollFixHijackSecret)) || bytes.Contains(wire, []byte("Switching")) {
					t.Fatalf("inline=%v: hijacked plaintext visible on the wire", inline)
				}
			})
		}
	}
}

func TestTLSEpollFixInlineStreamOverTLSIsEncrypted(t *testing.T) {
	ts := newTestServer(t, testServerOptions{TLS: true, Routes: tlsEpollFixHijackRoutes(nil), Config: func(c *Config) { c.InlineHandlers = true }})
	for _, v := range tlsEpollFixVersions() {
		t.Run(tls.VersionName(v), func(t *testing.T) {
			tc, tap := tlsEpollFixDialTapped(t, ts, v)
			if _, err := io.WriteString(tc, "GET /stream HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			_, body := readH1Response(t, bufio.NewReader(tc), "GET")
			if string(body) != tlsEpollFixHijackSecret {
				t.Fatalf("streamed body %q", body)
			}
			if bytes.Contains(tap.wire(), []byte(tlsEpollFixHijackSecret)) {
				t.Fatal("streamed plaintext visible on the wire")
			}
		})
	}
}

func TestTLSEpollFixHijackedTLS12RejectsInjectedPlaintext(t *testing.T) {
	injected := make(chan string, 1)
	ts := newTestServer(t, testServerOptions{TLS: true, Routes: tlsEpollFixHijackRoutes(injected)})
	tc, tap := tlsEpollFixDialTapped(t, ts, tls.VersionTLS12)
	if _, err := io.WriteString(tc, "GET /hj HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	want := "HTTP/1.1 101 Switching Protocols\r\n\r\n" + tlsEpollFixHijackSecret
	if _, err := io.ReadFull(tc, make([]byte, len(want))); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tap.Conn, "\x17\x03\x03\x00\x05INJ!!"); err != nil {
		t.Fatal(err)
	}
	if got := <-injected; got != "error" {
		t.Fatalf("hijacked TLS 1.2 conn accepted unauthenticated bytes %q", got)
	}
}

func TestTLSEpollFixHijackKeepsEarlierPipelinedResponse(t *testing.T) {
	for _, inline := range []bool{false, true} {
		for _, useTLS := range []bool{false, true} {
			ts := newTestServer(t, testServerOptions{TLS: useTLS, Routes: tlsEpollFixHijackRoutes(nil), Config: func(c *Config) { c.InlineHandlers = inline }})
			versions := []uint16{0}
			if useTLS {
				versions = tlsEpollFixVersions()
			}
			for _, v := range versions {
				var conn net.Conn
				if useTLS {
					conn, _ = tlsEpollFixDialTapped(t, ts, v)
				} else {
					conn = ts.dial(t)
				}
				if _, err := io.WriteString(conn, "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /hj HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				br := bufio.NewReader(conn)
				resp, body := readH1Response(t, br, "GET")
				if resp.StatusCode != 200 || len(body) != tlsEpollFixPipelinedA {
					t.Fatalf("inline=%v tls=%v version=%#x: first pipelined response %d with %d bytes", inline, useTLS, v, resp.StatusCode, len(body))
				}
				want := "HTTP/1.1 101 Switching Protocols\r\n\r\n" + tlsEpollFixHijackSecret
				got := make([]byte, len(want))
				if _, err := io.ReadFull(br, got); err != nil || string(got) != want {
					t.Fatalf("inline=%v tls=%v version=%#x: hijacker output %q err=%v", inline, useTLS, v, got, err)
				}
				if _, err := io.WriteString(conn, "ping!"); err != nil {
					t.Fatal(err)
				}
				echo := make([]byte, len("pong:ping!"))
				if _, err := io.ReadFull(br, echo); err != nil || string(echo) != "pong:ping!" {
					t.Fatalf("inline=%v tls=%v version=%#x: echo %q err=%v", inline, useTLS, v, echo, err)
				}
			}
		}
	}
}
