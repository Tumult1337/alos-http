//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

const (
	perfH1DirectMaxBody   = 8 << 20
	perfH1DirectSlowChunk = 4 << 10
	perfH1DirectSlowPause = 2 * time.Millisecond
	perfH1DirectRecvBuf   = 4 << 10
)

var perfH1DirectPattern = func() []byte {
	b := make([]byte, perfH1DirectMaxBody)
	for i := range b {
		b[i] = byte(i*31 + i>>8 + 7)
	}
	return b
}()

var perfH1DirectText = string(perfH1DirectPattern[:3<<20])

func perfH1DirectRoutes(r *Router) {
	r.GET("/sized/:n", func(req *Request, resp *Response) {
		n, err := strconv.Atoi(req.ParamValue("n"))
		if err != nil || n < 0 || n > perfH1DirectMaxBody {
			resp.Status(http.StatusBadRequest).String("bad size")
			return
		}
		resp.Bytes(perfH1DirectPattern[:n])
	})
	r.HEAD("/sized/:n", func(req *Request, resp *Response) {
		n, _ := strconv.Atoi(req.ParamValue("n"))
		resp.Bytes(perfH1DirectPattern[:n])
	})
	r.GET("/text-large", func(req *Request, resp *Response) { resp.String(perfH1DirectText) })
}

func perfH1DirectServer(tb testing.TB, inline bool) *testServer {
	tb.Helper()
	return newTestServer(tb, testServerOptions{Routes: perfH1DirectRoutes, Config: func(cfg *Config) {
		cfg.InlineHandlers, cfg.DisableInlineHandlers = inline, !inline
		cfg.WriteTimeout = 30 * time.Second
	}})
}

func perfH1DirectDial(tb testing.TB, addr string) net.Conn {
	tb.Helper()
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(wallDeadline(perfH1IODeadline))
	return conn
}

func perfH1DirectExpect(tb testing.TB, br *bufio.Reader, method string, want []byte) {
	tb.Helper()
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		tb.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("status %d", resp.StatusCode)
	}
	if resp.ContentLength != int64(len(want)) {
		tb.Fatalf("Content-Length %d, want %d", resp.ContentLength, len(want))
	}
	if method == http.MethodHead {
		if len(body) != 0 {
			tb.Fatalf("HEAD carried %d body bytes", len(body))
		}
		return
	}
	if !bytes.Equal(body, want) {
		tb.Fatalf("body of %d bytes differs from the expected %d bytes", len(body), len(want))
	}
}

func perfH1DirectSizes() []int {
	return []int{h1DirectBodyMin - 1, h1DirectBodyMin, 64 << 10, 64<<10 + 1, h1ProgressiveBodyThreshold + 1, 1<<20 + 7, perfH1DirectMaxBody}
}

func TestPerfH1DirectBodyKeepAliveSizes(t *testing.T) {
	for _, inline := range []bool{false, true} {
		ts := perfH1DirectServer(t, inline)
		conn := perfH1DirectDial(t, ts.addr)
		br := bufio.NewReader(conn)
		for round := 0; round < 2; round++ {
			for _, n := range perfH1DirectSizes() {
				if _, err := conn.Write(perfH1Get("/sized/"+strconv.Itoa(n), "")); err != nil {
					t.Fatalf("write: %v", err)
				}
				perfH1DirectExpect(t, br, http.MethodGet, perfH1DirectPattern[:n])
			}
		}
		if _, err := conn.Write(perfH1Get("/text-large", "")); err != nil {
			t.Fatalf("write: %v", err)
		}
		perfH1DirectExpect(t, br, http.MethodGet, []byte(perfH1DirectText))
	}
}

func TestPerfH1DirectBodyPipelinedInOrder(t *testing.T) {
	sizes := []int{5, 64 << 10, 1 << 20, 13, h1DirectBodyMin, 3 << 20, 1}
	for _, inline := range []bool{false, true} {
		ts := perfH1DirectServer(t, inline)
		conn := perfH1DirectDial(t, ts.addr)
		var batch []byte
		for _, n := range sizes {
			batch = append(batch, perfH1Get("/sized/"+strconv.Itoa(n), "")...)
		}
		head := []byte("HEAD /sized/" + strconv.Itoa(1<<20) + " HTTP/1.1\r\nHost: alos.gg\r\n\r\n")
		batch = append(batch, head...)
		batch = append(batch, perfH1Get("/sized/7", "")...)
		if _, err := conn.Write(batch); err != nil {
			t.Fatalf("write: %v", err)
		}
		br := bufio.NewReader(conn)
		for _, n := range sizes {
			perfH1DirectExpect(t, br, http.MethodGet, perfH1DirectPattern[:n])
		}
		perfH1DirectExpect(t, br, http.MethodHead, perfH1DirectPattern[:1<<20])
		perfH1DirectExpect(t, br, http.MethodGet, perfH1DirectPattern[:7])
	}
}

func TestPerfH1DirectBodySlowReaderIntact(t *testing.T) {
	ts := perfH1DirectServer(t, false)
	conn := dialTCPRecvBuf(t, ts.addr, perfH1IODeadline, perfH1DirectRecvBuf)
	_ = conn.SetDeadline(wallDeadline(perfH1IODeadline))
	if _, err := conn.Write(perfH1Get("/sized/"+strconv.Itoa(perfH1DirectMaxBody), "Connection: close\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	var got bytes.Buffer
	chunk := make([]byte, perfH1DirectSlowChunk)
	for got.Len() < 2<<20 {
		n, err := conn.Read(chunk)
		got.Write(chunk[:n])
		if err != nil {
			t.Fatalf("slow read after %d bytes: %v", got.Len(), err)
		}
		time.Sleep(perfH1DirectSlowPause)
	}
	rest, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	got.Write(rest)
	resp, err := http.ReadResponse(bufio.NewReader(&got), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, perfH1DirectPattern) {
		t.Fatalf("slow reader got %d body bytes, want %d intact", len(body), perfH1DirectMaxBody)
	}
}

func TestPerfH1DirectBodyClientGoneMidSend(t *testing.T) {
	ts := perfH1DirectServer(t, false)
	for i := 0; i < 8; i++ {
		conn := perfH1DirectDial(t, ts.addr)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(perfH1DirectRecvBuf)
		}
		if _, err := conn.Write(perfH1Get("/sized/"+strconv.Itoa(perfH1DirectMaxBody), "")); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, perfH1DirectSlowChunk)
		_, _ = io.ReadFull(conn, buf)
		_ = conn.Close()
	}
	conn := perfH1DirectDial(t, ts.addr)
	if _, err := conn.Write(perfH1Get("/sized/"+strconv.Itoa(64<<10), "")); err != nil {
		t.Fatalf("write: %v", err)
	}
	perfH1DirectExpect(t, bufio.NewReader(conn), http.MethodGet, perfH1DirectPattern[:64<<10])
	waitFor(t, perfH1IODeadline, func() bool { return ts.srv.activeConns.Load() == 1 })
}
