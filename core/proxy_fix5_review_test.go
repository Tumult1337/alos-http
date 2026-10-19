//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const proxyFix5AliasHost = "alias.test"

func proxyFix5LargeOrigin(t *testing.T, size int) *inloopOrigin {
	t.Helper()
	body := proxyFixPattern(size)
	return newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
		_, _ = conn.Write(body)
	})
}

func TestProxyFix5InlineHostRewriteStreamedProxyKeepsTakeover(t *testing.T) {
	const size = 128 << 10
	o := proxyFix5LargeOrigin(t, size)
	srv, addr := proxyFixStart(t, Config{InlineHandlers: true}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.OnRequest(func(req *Request, resp *Response) bool {
			if req.Host == proxyFix5AliasHost {
				req.Host = proxyFixDomain
			}
			return true
		})
	})
	for i := 0; i < 3; i++ {
		c := proxyFixDial(t, addr)
		if _, err := io.WriteString(c, proxyFixGet(proxyFix5AliasHost, "/big")); err != nil {
			t.Fatalf("write: %v", err)
		}
		resp, body := proxyFixReadResponse(t, bufio.NewReader(c))
		if resp.StatusCode != http.StatusOK || len(body) != size {
			t.Fatalf("round %d: status %d len %d", i, resp.StatusCode, len(body))
		}
		rest, err := io.ReadAll(c)
		if err != nil {
			t.Errorf("round %d: server did not close the taken-over conn after the streamed response: %v (activeConns=%d)", i, err, srv.activeConns.Load())
		}
		if len(rest) != 0 {
			t.Fatalf("round %d: %d trailing bytes after the streamed response: %q", i, len(rest), rest[:min(len(rest), 120)])
		}
		_ = c.Close()
	}
	proxyFixEventually(t, "all conns released", func() bool { return srv.activeConns.Load() == 0 })
}

func TestProxyFix5DispatchedRouteKeepsTrailingSlashAfterDotSegment(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		mu.Lock()
		seen = append(seen, req.RequestURI)
		mu.Unlock()
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	for _, hooked := range []bool{false, true} {
		_, addr := proxyFixStart(t, Config{}, nil, func(s *Server) {
			s.SetHTTPRoutes([]HTTPRoute{{PathPrefix: "/public/", Backend: o.addr()}})
			if hooked {
				s.OnRequest(func(*Request, *Response) bool { return true })
			}
		})
		mu.Lock()
		seen = seen[:0]
		mu.Unlock()
		resp, _ := proxyFixRoundTrip(t, addr, proxyFixGet("vhost.example", "/public/.well-known/"))
		mu.Lock()
		got := append([]string(nil), seen...)
		mu.Unlock()
		if resp.StatusCode != http.StatusOK || len(got) != 1 || got[0] != "/public/.well-known/" {
			t.Errorf("hooked=%v: status %d, backend saw %q, want [\"/public/.well-known/\"]", hooked, resp.StatusCode, strings.Join(got, ","))
		}
	}
}

func TestProxyFix5DispatchedRouteForwardsHookRewrittenPath(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		mu.Lock()
		seen = append(seen, req.RequestURI)
		mu.Unlock()
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	_, addr := proxyFixStart(t, Config{}, nil, func(s *Server) {
		s.SetHTTPRoutes([]HTTPRoute{{PathPrefix: "/public/", Backend: o.addr()}})
		s.OnRequest(func(req *Request, _ *Response) bool {
			if req.Path == "/public/.well-known" {
				req.Path = "/public/rewritten.txt"
			}
			return true
		})
	})
	resp, _ := proxyFixRoundTrip(t, addr, proxyFixGet("vhost.example", "/public/.well-known/"))
	mu.Lock()
	got := append([]string(nil), seen...)
	mu.Unlock()
	if resp.StatusCode != http.StatusOK || len(got) != 1 || got[0] != "/public/rewritten.txt" {
		t.Errorf("status %d, backend saw %q, want the hook's [\"/public/rewritten.txt\"]", resp.StatusCode, strings.Join(got, ","))
	}
}

func TestProxyFix5DispatchedDeclinedUpgradeStreamsLargeBodies(t *testing.T) {
	const size = 200 << 10
	body := proxyFixPattern(size)
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		switch req.URL.Path {
		case "/declined-big":
			fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\n", size)
			_, _ = conn.Write(body)
		case "/declined-eof":
			fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
			_, _ = conn.Write(body)
			_ = conn.Close()
		case "/declined-chunked-big":
			fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n", size)
			_, _ = conn.Write(body)
			_, _ = io.WriteString(conn, "\r\n0\r\n\r\n")
		default:
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
	})
	for _, mode := range proxyFix3Modes {
		t.Run(mode.name, func(t *testing.T) {
			srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
				if mode.hooks {
					s.OnRequest(func(*Request, *Response) bool { return true })
				}
			})
			c := proxyFixDial(t, addr)
			defer c.Close()
			br := bufio.NewReader(c)
			for _, path := range []string{"/declined-big", "/declined-eof", "/declined-chunked-big"} {
				if _, err := io.WriteString(c, proxyFix3Upgrade(path, "websocket")); err != nil {
					t.Fatalf("write: %v", err)
				}
				resp, got := proxyFixReadResponse(t, br)
				if resp.StatusCode != http.StatusForbidden || got != string(body) {
					t.Fatalf("%s: status %d len %d", path, resp.StatusCode, len(got))
				}
			}
			if _, err := io.WriteString(c, proxyFixGet(proxyFixDomain, "/after")); err != nil {
				t.Fatalf("write: %v", err)
			}
			resp, got := proxyFixReadResponse(t, br)
			if resp.StatusCode != http.StatusOK || got != "ok" {
				t.Fatalf("follow-up: %d %q", resp.StatusCode, got)
			}
			_ = c.Close()
			proxyFixEventually(t, "conns released", func() bool { return srv.activeConns.Load() == 0 })
		})
	}
}
