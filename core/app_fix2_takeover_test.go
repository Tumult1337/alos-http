//go:build linux && amd64

package core

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	appFix2TakeoverWithin = 2 * time.Second
	appFix2ShutdownGrace  = 450 * time.Millisecond
	appFix2HijackRequest  = "GET /hijack HTTP/1.1\r\nHost: " + harnessDomain + "\r\n\r\n"
)

func appFix2SoleWorker(t *testing.T, srv *Server) *epollWorker {
	t.Helper()
	var worker *epollWorker
	waitFor(t, harnessIOTimeout, func() bool {
		srv.wakersMu.Lock()
		defer srv.wakersMu.Unlock()
		worker = nil
		for waker := range srv.wakers {
			if w, ok := waker.(*epollWorker); ok {
				if worker != nil {
					t.Fatal("more than one epoll worker registered")
				}
				worker = w
			}
		}
		return worker != nil
	})
	return worker
}

func appFix2WorkerRegistered(srv *Server, w *epollWorker) bool {
	srv.wakersMu.Lock()
	defer srv.wakersMu.Unlock()
	_, ok := srv.wakers[w]
	return ok
}

func appFix2FillTaskQueue(w *epollWorker) {
	noop := func(*epollWorker) {}
	for {
		select {
		case w.taskCh <- noop:
		default:
			return
		}
	}
}

func appFix2TrackedConnCount(srv *Server) int {
	srv.trackedConnMu.Lock()
	defer srv.trackedConnMu.Unlock()
	return len(srv.trackedConns)
}

func appFix2StartHijackServer(t *testing.T, inline bool, handle func(req *Request)) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		Config: func(cfg *Config) {
			cfg.PlainHTTP = true
			cfg.InlineHandlers, cfg.DisableInlineHandlers = inline, !inline
		},
		Routes: func(r *Router) {
			r.GET("/hijack", func(req *Request, resp *Response) { handle(req) })
		},
	})
}

func appFix2SendHijackRequest(t *testing.T, ts *testServer) {
	t.Helper()
	c := ts.dial(t)
	if _, err := io.WriteString(c, appFix2HijackRequest); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestAppFix2InlineHijackCloseWithFullTaskQueueDoesNotDeadlockWorker(t *testing.T) {
	var worker atomic.Pointer[epollWorker]
	closed := make(chan struct{})
	ts := appFix2StartHijackServer(t, true, func(req *Request) {
		conn := req.HijackConn()
		if conn == nil {
			return
		}
		appFix2FillTaskQueue(worker.Load())
		_ = conn.Close()
		close(closed)
	})
	worker.Store(appFix2SoleWorker(t, ts.srv))
	appFix2SendHijackRequest(t, ts)
	select {
	case <-closed:
	case <-turbo.After(appFix2TakeoverWithin):
		<-worker.Load().taskCh
		t.Fatal("closing a hijacked conn on its own worker with a full task queue blocked the worker")
	}
	waitFor(t, harnessIOTimeout, func() bool { return ts.srv.activeConns.Load() == 0 })
}

func TestAppFix2ShutdownClosesHijackedConnAfterWorkerExit(t *testing.T) {
	hijacked := make(chan struct{})
	ts := appFix2StartHijackServer(t, false, func(req *Request) {
		conn := req.HijackConn()
		if conn == nil {
			return
		}
		close(hijacked)
		go func() {
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		}()
	})
	worker := appFix2SoleWorker(t, ts.srv)
	appFix2SendHijackRequest(t, ts)
	select {
	case <-hijacked:
	case <-turbo.After(appFix2TakeoverWithin):
		t.Fatal("handler never hijacked the conn")
	}
	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), appFix2ShutdownGrace)
		defer cancel()
		shutdownDone <- ts.srv.Shutdown(ctx)
	}()
	waitFor(t, harnessIOTimeout, func() bool { return !appFix2WorkerRegistered(ts.srv, worker) })
	appFix2FillTaskQueue(worker)
	select {
	case <-shutdownDone:
	case <-turbo.After(appFix2TakeoverWithin):
		<-worker.taskCh
		t.Fatal("Shutdown hung closing a hijacked conn after its worker exited with a full task queue")
	}
	if n := appFix2TrackedConnCount(ts.srv); n != 0 {
		t.Fatalf("%d hijacked conns still tracked after Shutdown", n)
	}
}

func TestAppFix2HijackedConnPublishedWithItsCloseHook(t *testing.T) {
	release := make(chan struct{})
	ts := appFix2StartHijackServer(t, false, func(req *Request) {
		if req.HijackConn() != nil {
			<-release
		}
	})
	t.Cleanup(func() { close(release) })
	appFix2SendHijackRequest(t, ts)
	waitFor(t, harnessIOTimeout, func() bool { return appFix2TrackedConnCount(ts.srv) == 1 })
	ts.srv.closeTrackedHandoffConns()
	if n := appFix2TrackedConnCount(ts.srv); n != 0 {
		t.Fatalf("%d hijacked conns still tracked after closing them", n)
	}
}
