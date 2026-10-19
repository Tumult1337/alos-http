//go:build linux && amd64

package core

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

func appFix5InlineHijackServer(t *testing.T, maxConns int64, handle func(req *Request)) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		Config: func(cfg *Config) {
			cfg.PlainHTTP = true
			cfg.InlineHandlers = true
			if maxConns > 0 {
				cfg.MaxConns = maxConns
				cfg.MinPrealloc = 1
			}
		},
		Routes: func(r *Router) {
			r.GET("/hijack", func(req *Request, resp *Response) { handle(req) })
		},
	})
}

func TestAppFix5InlineHijackRefusedByMaxConnsReleasesSlot(t *testing.T) {
	refused := make(chan bool, 1)
	ts := appFix5InlineHijackServer(t, 1, func(req *Request) {
		conn := req.HijackConn()
		refused <- conn == nil
		if conn != nil {
			_ = conn.Close()
		}
	})
	var c net.Conn
	for attempt := 0; c == nil; attempt++ {
		if attempt == 10 {
			t.Fatal("handler never ran")
		}
		waitFor(t, harnessIOTimeout, func() bool { return ts.srv.activeConns.Load() == 0 })
		try := ts.dial(t)
		if _, err := io.WriteString(try, appFix2HijackRequest); err != nil {
			_ = try.Close()
			continue
		}
		select {
		case r := <-refused:
			if !r {
				t.Fatal("hijack was not refused at MaxConns=1, so the test does not reach the refused handoff")
			}
			c = try
		case <-turbo.After(150 * time.Millisecond):
			_ = try.Close()
		}
	}
	_ = c.SetReadDeadline(wallDeadline(450 * time.Millisecond))
	got, err := io.ReadAll(c)
	t.Logf("client read %q err=%v", got, err)
	_ = c.Close()
	deadline := turbo.Deadline(450 * time.Millisecond)
	for turbo.Until(deadline) > 0 && ts.srv.activeConns.Load() != 0 {
		time.Sleep(15 * time.Millisecond)
	}
	if n := ts.srv.activeConns.Load(); n != 0 {
		w := appFix2SoleWorker(t, ts.srv)
		done := make(chan int, 1)
		w.postTask(func(w *epollWorker) { done <- w.pool.slotsHeld() })
		held := <-done
		t.Fatalf("activeConns=%d slotsHeld=%d after the client closed: an inline hijack refused by MaxConns leaked its epoll conn slot", n, held)
	}
}

func TestAppFix5InlineHijackRefusedDuringShutdownLetsWorkerExit(t *testing.T) {
	entered := make(chan struct{})
	gate := make(chan struct{})
	refused := make(chan bool, 1)
	ts := appFix5InlineHijackServer(t, 0, func(req *Request) {
		close(entered)
		<-gate
		conn := req.HijackConn()
		refused <- conn == nil
		if conn != nil {
			_ = conn.Close()
		}
	})
	worker := appFix2SoleWorker(t, ts.srv)
	c := ts.dial(t)
	defer c.Close()
	if _, err := io.WriteString(c, appFix2HijackRequest); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-entered:
	case <-turbo.After(harnessIOTimeout):
		t.Fatal("handler never ran")
	}
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 450*time.Millisecond)
		defer cancel()
		result <- ts.srv.Shutdown(ctx)
	}()
	waitFor(t, harnessIOTimeout, func() bool { return ts.srv.shuttingDown.Load() })
	close(gate)
	if !<-refused {
		t.Fatal("hijack was not refused during Shutdown, so the test does not reach the refused handoff")
	}
	err := <-result
	t.Logf("Shutdown err=%v activeConns=%d", err, ts.srv.activeConns.Load())
	deadline := turbo.Deadline(450 * time.Millisecond)
	for turbo.Until(deadline) > 0 && appFix2WorkerRegistered(ts.srv, worker) {
		time.Sleep(15 * time.Millisecond)
	}
	if appFix2WorkerRegistered(ts.srv, worker) {
		t.Fatalf("epoll worker still running after Shutdown returned %v: the struct leaked by the refused inline hijack keeps slotsHeld above 0 forever", err)
	}
	if err != nil {
		t.Fatalf("Shutdown returned %v", err)
	}
}
