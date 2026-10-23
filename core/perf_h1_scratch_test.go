//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	perfH1ScratchConns    = 32
	perfH1ScratchRequests = 20
	perfH1ScratchHold     = 2 * time.Millisecond

	perfH1ScratchIdleTimeout       = 150 * time.Millisecond
	perfH1ScratchReapCeiling       = 3 * time.Second
	perfH1ScratchKeepAliveRequests = 3
)

func perfH1ScratchTrailer(req *Request, name string) string {
	for _, f := range req.Trailers() {
		if EqualFoldASCII(f[0], name) {
			return f[1]
		}
	}
	return ""
}

func perfH1ScratchRoutes(r *Router) {
	echo := func(req *Request, resp *Response) {
		turbo.Sleep(perfH1ScratchHold)
		resp.String(req.ParamValue("id") + "|" + req.Query + "|" + req.Header("X-Tag") + "|" + req.Cookie("sid") + "|" + string(req.Body) + "|" + perfH1ScratchTrailer(req, "X-Sum"))
	}
	r.GET("/echo/:id", echo)
	r.POST("/echo/:id", echo)
}

func perfH1ScratchExpect(t *testing.T, br *bufio.Reader, want string) error {
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if string(body) != want {
		return fmt.Errorf("got %q, want %q", body, want)
	}
	return nil
}

func perfH1ScratchClient(t *testing.T, addr string, id int) error {
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(perfH1IODeadline))
	br := bufio.NewReader(conn)
	for i := 0; i < perfH1ScratchRequests; i++ {
		tag := strconv.Itoa(id) + "-" + strconv.Itoa(i)
		var req, want string
		switch i % 3 {
		case 0:
			req = "GET /echo/" + tag + "?q=" + tag + " HTTP/1.1\r\nHost: h\r\nX-Tag: t" + tag + "\r\nCookie: sid=s" + tag + "\r\n\r\n"
			want = tag + "|q=" + tag + "|t" + tag + "|s" + tag + "||"
		case 1:
			body := "body-" + tag
			req = "POST /echo/" + tag + " HTTP/1.1\r\nHost: h\r\nX-Tag: t" + tag + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
			want = tag + "||t" + tag + "||" + body + "|"
		default:
			body := "chunk-" + tag
			req = "POST /echo/" + tag + " HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n" +
				strconv.FormatInt(int64(len(body)), 16) + "\r\n" + body + "\r\n0\r\nX-Sum: sum" + tag + "\r\n\r\n"
			want = tag + "|||" + "|" + body + "|sum" + tag
		}
		if _, err := conn.Write([]byte(req)); err != nil {
			return err
		}
		if err := perfH1ScratchExpect(t, br, want); err != nil {
			return fmt.Errorf("conn %d request %d: %w", id, i, err)
		}
	}
	var batch strings.Builder
	var wants []string
	for i := 0; i < 4; i++ {
		tag := strconv.Itoa(id) + "-p" + strconv.Itoa(i)
		batch.WriteString("GET /echo/" + tag + " HTTP/1.1\r\nHost: h\r\nX-Tag: " + tag + "\r\n\r\n")
		wants = append(wants, tag+"||"+tag+"|||")
	}
	if _, err := conn.Write([]byte(batch.String())); err != nil {
		return err
	}
	for i, want := range wants {
		if err := perfH1ScratchExpect(t, br, want); err != nil {
			return fmt.Errorf("conn %d pipelined %d: %w", id, i, err)
		}
	}
	return nil
}

func TestPerfH1ScratchKeepAliveConnIsReapedWhenIdle(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		for _, inline := range []bool{false, true} {
			perfH1ScratchExpectIdleReap(t, useTLS, inline)
		}
	}
}

func perfH1ScratchExpectIdleReap(t *testing.T, useTLS, inline bool) {
	ts := newTestServer(t, testServerOptions{TLS: useTLS, Routes: perfH1ScratchRoutes, Config: func(cfg *Config) {
		cfg.InlineHandlers, cfg.DisableInlineHandlers = inline, !inline
		cfg.IdleTimeout = perfH1ScratchIdleTimeout
	}})
	conn := ts.dial(t)
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(perfH1IODeadline))
	br := bufio.NewReader(conn)
	for i := 0; i < perfH1ScratchKeepAliveRequests; i++ {
		tag := strconv.Itoa(i)
		if _, err := conn.Write([]byte("GET /echo/" + tag + " HTTP/1.1\r\nHost: h\r\n\r\n")); err != nil {
			t.Fatalf("tls=%v inline=%v request %d: %v", useTLS, inline, i, err)
		}
		if err := perfH1ScratchExpect(t, br, tag+"|||||"); err != nil {
			t.Fatalf("tls=%v inline=%v request %d: %v", useTLS, inline, i, err)
		}
	}
	_ = conn.SetReadDeadline(wallDeadline(perfH1ScratchReapCeiling))
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("tls=%v inline=%v: idle keep-alive conn after %d requests was not closed by the idle timeout: %v", useTLS, inline, perfH1ScratchKeepAliveRequests, err)
	}
}

func TestPerfH1SharedReadScratchKeepsRequestsIsolated(t *testing.T) {
	for _, inline := range []bool{false, true} {
		ts := newTestServer(t, testServerOptions{Routes: perfH1ScratchRoutes, Config: func(cfg *Config) { cfg.InlineHandlers, cfg.DisableInlineHandlers = inline, !inline }})
		var wg sync.WaitGroup
		errs := make(chan error, perfH1ScratchConns)
		for id := 0; id < perfH1ScratchConns; id++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				if err := perfH1ScratchClient(t, ts.addr, id); err != nil {
					errs <- err
				}
			}(id)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("inline=%v: %v", inline, err)
		}
	}
}
