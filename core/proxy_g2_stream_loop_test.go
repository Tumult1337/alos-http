//go:build linux && amd64

package core

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
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

const (
	proxyG2SlowBody        = 4 << 20
	proxyG2SlowReadTimeout = 500 * time.Millisecond
	proxyG2SlowChunkDelay  = 20 * time.Millisecond
	proxyG2InLoopSlowBody  = 1 << 20
)

type proxyG2SlowWriter struct{ n atomic.Int64 }

func (w *proxyG2SlowWriter) WriteHeader(int, [][2]string, string) error { return nil }
func (w *proxyG2SlowWriter) WriteChunk(d []byte) error {
	time.Sleep(proxyG2SlowChunkDelay)
	w.n.Add(int64(len(d)))
	return nil
}
func (w *proxyG2SlowWriter) Flush() error { return nil }
func (w *proxyG2SlowWriter) Close() error { return nil }

func proxyG2BurstOrigin(t *testing.T, size, stallAfter int) string {
	t.Helper()
	return rawOrigin(t, func(conn net.Conn) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
		if stallAfter > 0 {
			_, _ = conn.Write(bytes.Repeat([]byte("s"), stallAfter))
			time.Sleep(10 * proxyG2SlowReadTimeout)
			return
		}
		_, _ = conn.Write(bytes.Repeat([]byte("s"), size))
	})
}

func TestFPProxySlowSteadyClientIsNotCutByBackendReadTimeout(t *testing.T) {
	w := &proxyG2SlowWriter{}
	req := &Request{Method: "GET", Host: "origin.test", Path: "/big", StreamWriter: w, server: New(Config{})}
	err := (&ProxyEngine{}).forwardRequestFP(req, &Response{}, &backend{Addr: proxyG2BurstOrigin(t, proxyG2SlowBody, 0)}, &DomainConfig{
		ConnectTimeout: time.Second, ReadTimeout: proxyG2SlowReadTimeout,
	}, proxyCacheTarget{path: "/big", storable: true})
	if err != nil || w.n.Load() != proxyG2SlowBody {
		t.Fatalf("slow but steady client: err=%v relayed %d of %d", err, w.n.Load(), proxyG2SlowBody)
	}
}

func TestFPProxyStalledBackendStillTimesOut(t *testing.T) {
	w := &proxyG2SlowWriter{}
	req := &Request{Method: "GET", Host: "origin.test", Path: "/big", StreamWriter: w}
	start := time.Now()
	err := (&ProxyEngine{}).forwardRequestFP(req, &Response{}, &backend{Addr: proxyG2BurstOrigin(t, proxyG2SlowBody, 64<<10)}, &DomainConfig{
		ConnectTimeout: time.Second, ReadTimeout: proxyG2SlowReadTimeout,
	}, proxyCacheTarget{path: "/big", storable: true})
	if err == nil {
		t.Fatalf("a backend that stopped sending was not timed out")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the stalled backend took %v to time out", elapsed)
	}
}

func TestProxyInLoopSlowSteadyClientIsNotCutByBackendReadTimeout(t *testing.T) {
	origin := proxyG2BurstOrigin(t, proxyG2InLoopSlowBody, 0)
	_, addr := proxyFixStart(t, Config{}, []DomainConfig{{Domain: proxyFixDomain, ReadTimeout: proxyG2SlowReadTimeout, Backends: []BackendConfig{{Addr: origin}}}}, nil)
	dialer := net.Dialer{Timeout: proxyFixIOTimeout, Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<10)
		}); err != nil {
			return err
		}
		return serr
	}}
	c, err := dialer.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(proxyFixGet(proxyFixDomain, "/big"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 32<<10)
	total := 0
	for {
		n, err := c.Read(buf)
		total += n
		if err != nil {
			break
		}
		time.Sleep(proxyG2SlowChunkDelay)
	}
	if want := proxyG2InLoopSlowBody; total < want {
		t.Fatalf("slow but steady in-loop client got %d bytes, want the head plus %d body bytes", total, want)
	}
}

func proxyG2ReleaseOrigin(t *testing.T, released chan<- struct{}) string {
	t.Helper()
	return rawOrigin(t, func(conn net.Conn) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", 64<<20)
		chunk := bytes.Repeat([]byte("s"), 64<<10)
		for {
			if _, err := conn.Write(chunk); err != nil {
				close(released)
				return
			}
		}
	})
}

type proxyG2StuckWriter struct{ unblock chan struct{} }

func (w *proxyG2StuckWriter) WriteHeader(int, [][2]string, string) error { return nil }
func (w *proxyG2StuckWriter) WriteChunk([]byte) error {
	<-w.unblock
	return ErrStreamClosed
}
func (w *proxyG2StuckWriter) Flush() error { return nil }
func (w *proxyG2StuckWriter) Close() error { return nil }

func TestFPProxyPausedBackendIsReleasedWithoutClientWriteTimeout(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server *Server
	}{{"write timeout disabled", New(Config{WriteTimeout: -1})}, {"no server", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			released := make(chan struct{})
			origin := proxyG2ReleaseOrigin(t, released)
			w := &proxyG2StuckWriter{unblock: make(chan struct{})}
			done := make(chan struct{})
			go func() {
				defer close(done)
				req := &Request{Method: "GET", Host: "origin.test", Path: "/big", StreamWriter: w, server: tc.server}
				_ = (&ProxyEngine{}).forwardRequestFP(req, &Response{}, &backend{Addr: origin}, &DomainConfig{
					ConnectTimeout: time.Second, ReadTimeout: proxyG2SlowReadTimeout,
				}, proxyCacheTarget{path: "/big", storable: true})
			}()
			defer func() {
				close(w.unblock)
				<-done
			}()
			select {
			case <-released:
			case <-time.After(10 * proxyG2SlowReadTimeout):
				t.Fatalf("a backend paused for a consumer with no write timeout was held past %v", 10*proxyG2SlowReadTimeout)
			}
		})
	}
}

func TestProxyInLoopPausedBackendIsReleasedWithoutClientWriteTimeout(t *testing.T) {
	released := make(chan struct{})
	origin := proxyG2ReleaseOrigin(t, released)
	_, addr := proxyFixStart(t, Config{WriteTimeout: -1}, []DomainConfig{{Domain: proxyFixDomain, ReadTimeout: proxyG2SlowReadTimeout, Backends: []BackendConfig{{Addr: origin}}}}, nil)
	c := proxyFixDial(t, addr)
	defer c.Close()
	if _, err := c.Write([]byte(proxyFixGet(proxyFixDomain, "/big"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-released:
	case <-time.After(10 * proxyG2SlowReadTimeout):
		t.Fatalf("a backend paused for a client that never reads was held past %v with the write timeout disabled", 10*proxyG2SlowReadTimeout)
	}
}

type proxyG2OnePauseWriter struct {
	n      atomic.Int64
	paused atomic.Bool
}

func (w *proxyG2OnePauseWriter) WriteHeader(int, [][2]string, string) error { return nil }
func (w *proxyG2OnePauseWriter) WriteChunk(d []byte) error {
	if !w.paused.Swap(true) {
		time.Sleep(3 * proxyG2SlowReadTimeout)
	}
	w.n.Add(int64(len(d)))
	return nil
}
func (w *proxyG2OnePauseWriter) Flush() error { return nil }
func (w *proxyG2OnePauseWriter) Close() error { return nil }

func TestFPProxyLongPauseWithClientWriteTimeoutKeepsBackend(t *testing.T) {
	w := &proxyG2OnePauseWriter{}
	req := &Request{Method: "GET", Host: "origin.test", Path: "/big", StreamWriter: w, server: New(Config{})}
	err := (&ProxyEngine{}).forwardRequestFP(req, &Response{}, &backend{Addr: proxyG2BurstOrigin(t, proxyG2SlowBody, 0)}, &DomainConfig{
		ConnectTimeout: time.Second, ReadTimeout: proxyG2SlowReadTimeout,
	}, proxyCacheTarget{path: "/big", storable: true})
	if err != nil || w.n.Load() != proxyG2SlowBody {
		t.Fatalf("a pause bounded by the client write timeout cut the download: err=%v relayed %d of %d", err, w.n.Load(), proxyG2SlowBody)
	}
}
