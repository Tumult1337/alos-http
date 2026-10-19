//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	appFix4ShutdownGrace     = 2 * time.Second
	appFix4PromptShutdown    = 450 * time.Millisecond
	appFix4WorkerExitWindow  = 150 * time.Millisecond
	appFix4WorkerExitPoll    = 10 * time.Millisecond
	appFix4PlainRequest      = "GET /slow HTTP/1.1\r\nHost: " + harnessDomain + "\r\n\r\n"
	appFix4LateResponseBody  = "late"
	appFix4StreamedChunkBody = "streamed"
)

type appFix4ShutdownResult struct {
	err     error
	elapsed time.Duration
}

type appFix4Gate struct {
	ch   chan struct{}
	once sync.Once
}

func newAppFix4Gate(t *testing.T) *appFix4Gate {
	g := &appFix4Gate{ch: make(chan struct{})}
	t.Cleanup(g.open)
	return g
}

func (g *appFix4Gate) open() { g.once.Do(func() { close(g.ch) }) }

func (g *appFix4Gate) wait() { <-g.ch }

func appFix4Await(t *testing.T, ch <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-ch:
	case <-turbo.After(harnessIOTimeout):
		t.Fatal(failure)
	}
}

func appFix4DialAndSend(t *testing.T, ts *testServer, raw string) net.Conn {
	t.Helper()
	c := ts.dial(t)
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	return c
}

func appFix4StartShutdown(srv *Server) <-chan appFix4ShutdownResult {
	result := make(chan appFix4ShutdownResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), appFix4ShutdownGrace)
		defer cancel()
		start := turbo.Now()
		err := srv.Shutdown(ctx)
		result <- appFix4ShutdownResult{err: err, elapsed: turbo.Since(start)}
	}()
	return result
}

func appFix4WorkerExitsWithin(srv *Server, w *epollWorker, window time.Duration) bool {
	deadline := turbo.Deadline(window)
	for turbo.Until(deadline) > 0 {
		if !appFix2WorkerRegistered(srv, w) {
			return true
		}
		time.Sleep(appFix4WorkerExitPoll)
	}
	return !appFix2WorkerRegistered(srv, w)
}

func appFix4ExpectPromptShutdown(t *testing.T, srv *Server, result <-chan appFix4ShutdownResult, since int64) {
	t.Helper()
	var got appFix4ShutdownResult
	select {
	case got = <-result:
	case <-turbo.After(appFix4ShutdownGrace + harnessIOTimeout):
		t.Fatal("Shutdown never returned")
	}
	if got.err != nil {
		t.Fatalf("Shutdown returned %v after %v with %d conns still counted, want nil (a finished handler's conn slot was never released)", got.err, got.elapsed, srv.activeConns.Load())
	}
	if waited := turbo.Since(since); waited > appFix4PromptShutdown {
		t.Fatalf("Shutdown returned %v after the last handler finished, want under %v", waited, appFix4PromptShutdown)
	}
	if n := srv.activeConns.Load(); n != 0 {
		t.Fatalf("%d conns still counted after Shutdown", n)
	}
}

func appFix4ShutdownWhileHandlerOutstanding(t *testing.T, srv *Server, worker *epollWorker, release *appFix4Gate) {
	t.Helper()
	result := appFix4StartShutdown(srv)
	exitedEarly := appFix4WorkerExitsWithin(srv, worker, appFix4WorkerExitWindow)
	released := turbo.Now()
	release.open()
	appFix4ExpectPromptShutdown(t, srv, result, released)
	if exitedEarly {
		t.Fatal("the epoll worker exited while a handler it dispatched was still running")
	}
	waitFor(t, harnessIOTimeout, func() bool { return !appFix2WorkerRegistered(srv, worker) })
}

func TestAppFix4ShutdownAfterHijackHandlerOutlivesClient(t *testing.T) {
	hijacked := make(chan struct{})
	connClosed := make(chan struct{})
	release := newAppFix4Gate(t)
	ts := appFix2StartHijackServer(t, false, func(req *Request) {
		conn := req.HijackConn()
		if conn == nil {
			return
		}
		close(hijacked)
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
		close(connClosed)
		release.wait()
	})
	worker := appFix2SoleWorker(t, ts.srv)
	c := appFix4DialAndSend(t, ts, appFix2HijackRequest)
	appFix4Await(t, hijacked, "handler never hijacked the conn")
	_ = c.Close()
	appFix4Await(t, connClosed, "hijack handler never saw the client close")
	appFix4ShutdownWhileHandlerOutstanding(t, ts.srv, worker, release)
}

func TestAppFix4ShutdownAfterClientAbandonsDispatchedRequest(t *testing.T) {
	for _, streamed := range []bool{false, true} {
		name := "buffered"
		if streamed {
			name = "streamed"
		}
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{})
			cancelled := make(chan struct{})
			release := newAppFix4Gate(t)
			ts := newTestServer(t, testServerOptions{
				Config: func(cfg *Config) { cfg.PlainHTTP = true },
				Routes: func(r *Router) {
					r.GET("/slow", func(req *Request, resp *Response) {
						var sw StreamWriter
						if streamed {
							sw = resp.EnsureStreamWriter()
							if sw == nil {
								return
							}
							_ = sw.WriteHeader(200, nil, "text/plain")
							resp.SetStreamer(sw)
							_ = sw.WriteChunk([]byte(appFix4StreamedChunkBody))
							_ = sw.Flush()
						}
						close(entered)
						<-req.Context().Done()
						close(cancelled)
						release.wait()
						if sw != nil {
							_ = sw.Close()
							return
						}
						resp.String(appFix4LateResponseBody)
					})
				},
			})
			worker := appFix2SoleWorker(t, ts.srv)
			c := appFix4DialAndSend(t, ts, appFix4PlainRequest)
			appFix4Await(t, entered, "handler never ran")
			_ = c.Close()
			appFix4Await(t, cancelled, "handler context was not cancelled after the client closed")
			appFix4ShutdownWhileHandlerOutstanding(t, ts.srv, worker, release)
		})
	}
}

func TestAppFix4PoolCountsSlotsUntilReleased(t *testing.T) {
	s := &Server{}
	w := &epollWorker{server: s}
	w.pool = epollConnPool{batchSize: 4, server: s}
	w.pool.prewarm(4)
	plain := w.pool.get()
	takenOver := w.pool.get()
	s.activeConns.Add(2)
	Stats.ActiveConns.Add(2)
	if w.pool.slotsHeld() != 2 {
		t.Fatalf("slotsHeld=%d after two gets, want 2", w.pool.slotsHeld())
	}
	w.pool.put(plain)
	if w.pool.slotsHeld() != 1 {
		t.Fatalf("slotsHeld=%d after put, want 1", w.pool.slotsHeld())
	}
	takenOver.takeoverPinned = true
	w.putTakenOver(takenOver)
	if w.pool.slotsHeld() != 0 {
		t.Fatalf("slotsHeld=%d after a parked takeover released its slot, want 0", w.pool.slotsHeld())
	}
	takenOver.unpinTakenOver(w)
	if w.pool.slotsHeld() != 0 || s.activeConns.Load() != 0 {
		t.Fatalf("slotsHeld=%d activeConns=%d after the unpin recycled the struct, want 0 and 0", w.pool.slotsHeld(), s.activeConns.Load())
	}
}

func TestAppFix4ShutdownRightAfterClientClosesHijackedConn(t *testing.T) {
	hijacked := make(chan struct{})
	ts := appFix2StartHijackServer(t, false, func(req *Request) {
		conn := req.HijackConn()
		if conn == nil {
			return
		}
		close(hijacked)
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
	})
	c := appFix4DialAndSend(t, ts, appFix2HijackRequest)
	appFix4Await(t, hijacked, "handler never hijacked the conn")
	closed := turbo.Now()
	_ = c.Close()
	appFix4ExpectPromptShutdown(t, ts.srv, appFix4StartShutdown(ts.srv), closed)
}

func TestAppFix4ShutdownRightAfterDispatchedTunnelClientCloses(t *testing.T) {
	srv, addr, _ := proxyFix3StartUpgradeProxy(t, Config{}, proxyFix3Mode{name: "dispatch", hooks: true})
	c := proxyFixDial(t, addr)
	if _, err := io.WriteString(c, proxyFix3Upgrade("/ws", "websocket")+proxyFix3TunnelProbe); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	proxyFix3ExpectTunnel(t, c, bufio.NewReader(c))
	closed := turbo.Now()
	_ = c.Close()
	appFix4ExpectPromptShutdown(t, srv, appFix4StartShutdown(srv), closed)
}
