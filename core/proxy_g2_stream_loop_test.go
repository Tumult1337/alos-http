//go:build linux && amd64

package core

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	proxyG2StreamBody  = 1 << 20
	proxyG2FloodBody   = 64 << 20
	proxyG2FloodBound  = 32 << 20
	proxyG2SmallPerRun = 48
)

var proxyG2UpstreamLoopFrame = []byte(".(*eventLoop).run(")

type proxyG2LoopWriter struct {
	mu      sync.Mutex
	out     bytes.Buffer
	calls   atomic.Int64
	onLoop  atomic.Int64
	block   chan struct{}
	blocked chan struct{}
	once    sync.Once
}

func (w *proxyG2LoopWriter) WriteHeader(int, [][2]string, string) error { return nil }

func (w *proxyG2LoopWriter) WriteChunk(data []byte) error {
	w.calls.Add(1)
	buf := make([]byte, 64<<10)
	if bytes.Contains(buf[:runtime.Stack(buf, false)], proxyG2UpstreamLoopFrame) {
		w.onLoop.Add(1)
	}
	if w.block != nil {
		w.once.Do(func() { close(w.blocked) })
		<-w.block
	}
	w.mu.Lock()
	w.out.Write(data)
	w.mu.Unlock()
	return nil
}

func (w *proxyG2LoopWriter) Flush() error { return nil }
func (w *proxyG2LoopWriter) Close() error { return nil }

func proxyG2Forward(origin string, path string, sw StreamWriter) (*Response, error) {
	req := &Request{Method: "GET", Host: "origin.test", Path: path, StreamWriter: sw}
	resp := &Response{}
	err := (&ProxyEngine{}).forwardRequestFP(req, resp, &backend{Addr: origin}, &DomainConfig{
		ConnectTimeout: time.Second,
		ReadTimeout:    10 * time.Second,
	}, proxyCacheTarget{path: fpProxyPath(req), storable: true})
	return resp, err
}

func proxyG2SizedOrigin(t *testing.T, written *atomic.Int64) string {
	t.Helper()
	return rawOrigin(t, func(conn net.Conn) {
		size := 5
		switch {
		case written != nil:
			size = proxyG2FloodBody
		default:
			size = proxyG2StreamBody
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
		chunk := bytes.Repeat([]byte("s"), 64<<10)
		for sent := 0; sent < size; {
			n, err := conn.Write(chunk[:min(len(chunk), size-sent)])
			sent += n
			if written != nil {
				written.Add(int64(n))
			}
			if err != nil {
				return
			}
		}
	})
}

func TestFPProxyStreamWritesRunOffTheUpstreamLoop(t *testing.T) {
	origin := proxyG2SizedOrigin(t, nil)
	w := &proxyG2LoopWriter{}
	if _, err := proxyG2Forward(origin, "/big", w); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if w.out.Len() != proxyG2StreamBody || w.calls.Load() == 0 {
		t.Fatalf("streamed %d bytes in %d writes, want %d", w.out.Len(), w.calls.Load(), proxyG2StreamBody)
	}
	if n := w.onLoop.Load(); n != 0 {
		t.Fatalf("%d of %d client writes ran on the shared upstream event loop", n, w.calls.Load())
	}
}

func TestFPProxyBlockedClientPausesBackendAndSparesOtherExchanges(t *testing.T) {
	var written atomic.Int64
	flood := proxyG2SizedOrigin(t, &written)
	small := rawOrigin(t, func(conn net.Conn) {
		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nsmall")
	})
	w := &proxyG2LoopWriter{block: make(chan struct{}), blocked: make(chan struct{})}
	stuck := make(chan error, 1)
	go func() {
		_, err := proxyG2Forward(flood, "/flood", w)
		stuck <- err
	}()
	defer func() {
		close(w.block)
		<-stuck
	}()
	select {
	case <-w.blocked:
	case <-time.After(5 * time.Second):
		t.Fatalf("the stalled client never received a chunk")
	}
	results := make(chan error, proxyG2SmallPerRun)
	for range proxyG2SmallPerRun {
		go func() {
			resp, err := proxyG2Forward(small, "/small", nil)
			if err == nil && string(resp.GetBody()) != "small" {
				err = fmt.Errorf("body %q", resp.GetBody())
			}
			results <- err
		}()
	}
	deadline := time.After(3 * time.Second)
	for i := range proxyG2SmallPerRun {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("small exchange %d: %v", i, err)
			}
		case <-deadline:
			t.Fatalf("%d of %d small exchanges stalled behind a client that stopped reading", proxyG2SmallPerRun-i, proxyG2SmallPerRun)
		}
	}
	time.Sleep(500 * time.Millisecond)
	if got := written.Load(); got >= proxyG2FloodBound {
		t.Fatalf("backend wrote %d MiB for a client that reads nothing; reads were not paused", got>>20)
	}
}
