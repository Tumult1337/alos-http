//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	h1StreamBudgetBody  = 200 << 10
	h1StreamBudgetLimit = 64 << 10
	h1StreamLimitBytes  = 1000
	h1StreamLimitBody   = 5000
)

func h1StreamBudgetHeld(t *testing.T, cfg Config) (*epollWorker, *epollConn, chan struct{}, int) {
	t.Helper()
	w, c, _ := h1ReceivedFixture(t, cfg)
	release := make(chan struct{})
	entered := make(chan int, 1)
	w.server.Router.POST("/body", func(req *Request, resp *Response) {
		entered <- req.BodyStream().buffered()
		<-release
		resp.Status(200).String("ok")
	})
	w.server.Router.Build()
	w.server.computeFastDispatch()
	body := strings.Repeat("b", h1StreamBudgetBody)
	head := fmt.Sprintf("POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: %d\r\n\r\n", len(body))
	h1ReceivedInput(t, c, head+body)
	if _, step := c.serveH1(w.server, nil); step != h1StepDispatched {
		t.Fatalf("step=%d", step)
	}
	select {
	case buffered := <-entered:
		return w, c, release, buffered
	case <-time.After(h2FixCeiling):
		t.Fatal("handler did not run")
	}
	return nil, nil, nil, 0
}

func TestH1StreamedBodyChargesBodyBudget(t *testing.T) {
	w, c, release, buffered := h1StreamBudgetHeld(t, Config{StreamBodyAbove: 1, MaxInFlightBodyBytes: 1 << 20})
	if buffered == 0 {
		t.Fatal("fixture buffered no streamed body bytes")
	}
	if got := w.server.inFlightBodyBytes.Load(); got != int64(buffered) {
		t.Fatalf("streamed body buffers %d bytes; server body budget counts %d", buffered, got)
	}
	close(release)
	h1ReceivedFinish(t, w, c)
	if got := w.server.inFlightBodyBytes.Load(); got != 0 {
		t.Fatalf("body budget after the handler returned = %d, want 0", got)
	}
}

func TestH1StreamedBodyBudgetReleasedWhenConnClosesUnderHandler(t *testing.T) {
	w, c, release, buffered := h1StreamBudgetHeld(t, Config{StreamBodyAbove: 1, MaxInFlightBodyBytes: 1 << 20})
	if got := w.server.inFlightBodyBytes.Load(); got != int64(buffered) || got == 0 {
		t.Fatalf("precondition: budget=%d buffered=%d", got, buffered)
	}
	w.closeConn(c)
	close(release)
	h1ReceivedFinish(t, w, c)
	if got := w.server.inFlightBodyBytes.Load(); got != 0 {
		t.Fatalf("body budget after close and handler return = %d, want 0", got)
	}
}

func h1StreamPost(t *testing.T, addr, path string, body string) (*http.Response, string, bool) {
	t.Helper()
	return h1StreamPostWait(t, addr, path, body, false)
}

func h1StreamPostWait(t *testing.T, addr, path string, body string, waitClose bool) (*http.Response, string, bool) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, h2FixCeiling)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(h2FixCeiling))
	var req strings.Builder
	fmt.Fprintf(&req, "POST %s HTTP/1.1\r\nHost: body.test\r\nTransfer-Encoding: chunked\r\n\r\n", path)
	for off := 0; off < len(body); off += 1000 {
		end := min(off+1000, len(body))
		fmt.Fprintf(&req, "%x\r\n%s\r\n", end-off, body[off:end])
	}
	req.WriteString("0\r\n\r\n")
	go func() { _, _ = io.WriteString(conn, req.String()) }()
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !waitClose {
		return resp, string(got), false
	}
	_, err = br.ReadByte()
	return resp, string(got), err != nil
}

func TestH1StreamedBodyRefusedByFullBudgetGets503AndClose(t *testing.T) {
	var read atomic.Int64
	var readErr atomic.Bool
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.StreamBodyAbove = 1
		c.MaxInFlightBodyBytes = h1StreamBudgetLimit
	}, func(s *Server) {
		s.Router.POST("/body", func(req *Request, resp *Response) {
			n, err := io.Copy(io.Discard, req.BodyStream())
			read.Store(n)
			readErr.Store(err != nil)
			resp.Status(200).String("handler-ok")
		})
	})
	if !srv.tryReserveBodyBytes(h1StreamBudgetLimit) {
		t.Fatal("could not occupy the body budget")
	}
	resp, body, closed := h1StreamPostWait(t, addr, "/body", strings.Repeat("u", h1StreamBudgetBody), true)
	if resp.StatusCode != 503 {
		t.Fatalf("status=%d body=%q handler read %d bytes; want 503 while other requests hold all of MaxInFlightBodyBytes %d", resp.StatusCode, body, read.Load(), h1StreamBudgetLimit)
	}
	if read.Load() != 0 || !readErr.Load() {
		t.Fatalf("handler read %d body bytes, error=%v; a refused body must end in an error", read.Load(), readErr.Load())
	}
	if !closed {
		t.Fatal("connection stayed open after the body budget refused the request")
	}
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == h1StreamBudgetLimit }) {
		t.Fatalf("body budget after the refused request = %d, want only the occupied %d", srv.inFlightBodyBytes.Load(), h1StreamBudgetLimit)
	}
	srv.releaseBodyBytes(h1StreamBudgetLimit)
}

func TestH1StreamedBodyUnderBudgetIsServed(t *testing.T) {
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.StreamBodyAbove = 1
		c.MaxInFlightBodyBytes = h1StreamBudgetLimit
	}, func(s *Server) {
		s.Router.POST("/body", func(req *Request, resp *Response) {
			n, err := io.Copy(io.Discard, req.BodyStream())
			resp.Status(200).String(fmt.Sprintf("read=%d err=%v", n, err))
		})
	})
	resp, body, _ := h1StreamPost(t, addr, "/body", strings.Repeat("u", h1StreamBudgetBody))
	if resp.StatusCode != 200 || body != fmt.Sprintf("read=%d err=<nil>", h1StreamBudgetBody) {
		t.Fatalf("status=%d body=%q; a reading handler must receive the whole body", resp.StatusCode, body)
	}
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
		t.Fatalf("body budget after the request = %d, want 0", srv.inFlightBodyBytes.Load())
	}
}

func bodyLimitRoutes(read *atomic.Int64) func(*Server) {
	return func(s *Server) {
		s.Router.Use(BodyLimit(h1StreamLimitBytes))
		s.Router.POST("/limited", func(req *Request, resp *Response) {
			n, _ := io.Copy(io.Discard, req.BodyStream())
			read.Store(n)
			resp.Status(200).String("handler-ok")
		})
	}
}

func TestBodyLimitCapsStreamedChunkedH1Body(t *testing.T) {
	var read atomic.Int64
	addr, _ := startH2FixServerWith(t, func(c *Config) { c.StreamBodyAbove = 1 }, bodyLimitRoutes(&read))
	resp, body, _ := h1StreamPost(t, addr, "/limited", strings.Repeat("l", h1StreamLimitBody))
	if resp.StatusCode != 413 {
		t.Fatalf("status=%d body=%q; want 413 for a %d-byte chunked body over BodyLimit(%d)", resp.StatusCode, body, h1StreamLimitBody, h1StreamLimitBytes)
	}
	if n := read.Load(); n > h1StreamLimitBytes {
		t.Fatalf("handler read %d body bytes through BodyLimit(%d)", n, h1StreamLimitBytes)
	}
}

func TestBodyLimitPassesStreamedBodyAtLimit(t *testing.T) {
	var read atomic.Int64
	addr, _ := startH2FixServerWith(t, func(c *Config) { c.StreamBodyAbove = 1 }, bodyLimitRoutes(&read))
	resp, body, _ := h1StreamPost(t, addr, "/limited", strings.Repeat("l", h1StreamLimitBytes))
	if resp.StatusCode != 200 || read.Load() != h1StreamLimitBytes {
		t.Fatalf("status=%d body=%q read=%d; a body of exactly the limit must pass", resp.StatusCode, body, read.Load())
	}
}

func TestBodyLimitCapsStreamedH2Body(t *testing.T) {
	var read atomic.Int64
	addr, _ := startH2FixServerWith(t, func(c *Config) { c.StreamBodyAbove = 1 }, bodyLimitRoutes(&read))
	rc := h2RawDial(t, addr, nil)
	rc.write(H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/limited"))
	payload := []byte(strings.Repeat("l", h1StreamLimitBody))
	rc.write(H2FrameData, H2FlagEndStream, 1, payload)
	f, err := rc.awaitStreamOutcome(1)
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	if f.typ != H2FrameHeaders {
		t.Fatalf("stream 1 ended with frame type %d, want HEADERS", f.typ)
	}
	if got := f.status(t); got != 413 {
		t.Fatalf("status=%d read=%d; want 413 for a %d-byte H2 body over BodyLimit(%d)", got, read.Load(), len(payload), h1StreamLimitBytes)
	}
	if n := read.Load(); n > h1StreamLimitBytes {
		t.Fatalf("handler read %d body bytes through BodyLimit(%d)", n, h1StreamLimitBytes)
	}
}

func TestH1StreamedBodyLargerThanBudgetStreams(t *testing.T) {
	const budget = 16 << 10
	w, c, _ := h1ReceivedFixture(t, Config{StreamBodyAbove: 1, MaxInFlightBodyBytes: budget})
	var read atomic.Int64
	var readErr atomic.Value
	w.server.Router.POST("/body", func(req *Request, resp *Response) {
		n, err := io.Copy(io.Discard, req.BodyStream())
		read.Store(n)
		readErr.Store(fmt.Sprint(err))
		resp.Status(200).String("ok")
	})
	w.server.Router.Build()
	w.server.computeFastDispatch()
	body := strings.Repeat("b", h1StreamBudgetBody)
	head := fmt.Sprintf("POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: %d\r\n\r\n", len(body))
	h1ReceivedInput(t, c, head+body)
	if _, step := c.serveH1(w.server, nil); step != h1StepDispatched {
		t.Fatalf("step=%d", step)
	}
	deadline := time.Now().Add(h2FixCeiling)
	for w.h1Done.Load() == nil && time.Now().Before(deadline) {
		w.drainTasks()
		time.Sleep(time.Millisecond)
	}
	h1ReceivedFinish(t, w, c)
	if read.Load() != h1StreamBudgetBody || readErr.Load() != "<nil>" {
		t.Fatalf("handler read %d of %d bytes, err=%v, with MaxInFlightBodyBytes %d", read.Load(), h1StreamBudgetBody, readErr.Load(), budget)
	}
	if got := w.server.inFlightBodyBytes.Load(); got != 0 {
		t.Fatalf("body budget after the request = %d, want 0", got)
	}
}

func TestBodyLimitZeroRejectsStreamedBody(t *testing.T) {
	var read atomic.Int64
	addr, _ := startH2FixServerWith(t, func(c *Config) { c.StreamBodyAbove = 1 }, func(s *Server) {
		s.Router.Use(BodyLimit(0))
		s.Router.POST("/limited", func(req *Request, resp *Response) {
			n, _ := io.Copy(io.Discard, req.BodyStream())
			read.Store(n)
			resp.Status(200).String("handler-ok")
		})
	})
	resp, body, _ := h1StreamPost(t, addr, "/limited", "x")
	if resp.StatusCode != 413 || read.Load() != 0 {
		t.Fatalf("status=%d body=%q read=%d; BodyLimit(0) must reject a non-empty streamed body as the buffered path does", resp.StatusCode, body, read.Load())
	}
}
