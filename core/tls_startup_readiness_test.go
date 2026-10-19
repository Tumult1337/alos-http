//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type startupLogBarrier struct {
	message     string
	entered     chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
	releaseOnce sync.Once
	ready       atomic.Int32
}

func newStartupLogBarrier(message string) *startupLogBarrier {
	return &startupLogBarrier{message: message, entered: make(chan struct{}), release: make(chan struct{})}
}
func (h *startupLogBarrier) Enabled(context.Context, slog.Level) bool { return true }
func (h *startupLogBarrier) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *startupLogBarrier) WithGroup(string) slog.Handler            { return h }
func (h *startupLogBarrier) Handle(_ context.Context, record slog.Record) error {
	if record.Message == "HTTPS listening" {
		h.ready.Add(1)
	}
	if record.Message == h.message {
		h.enterOnce.Do(func() { close(h.entered) })
		<-h.release
	}
	return nil
}
func (h *startupLogBarrier) resume() { h.releaseOnce.Do(func() { close(h.release) }) }

func startTLSStartupServer(t *testing.T, handler *startupLogBarrier, cfg Config) (*Server, <-chan error) {
	t.Helper()
	if cfg.Addr == "" {
		cfg.Addr = freeLoopbackAddr(t)
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = "-"
	}
	if cfg.Listeners == 0 {
		cfg.Listeners = 1
	}
	cfg.MaxConnsPerIP = -1
	cfg.DisableOCSPStapling = true
	cfg.Logger = slog.New(handler)
	cfg.Certs = []CertConfig{{Domain: harnessDomain, Source: CertSelfSigned}}
	server := New(cfg)
	server.Router.GET("/ready", func(req *Request, resp *Response) { resp.Status(200).String("ready handler") })
	served := make(chan error, 1)
	returned := make(chan struct{})
	go func() { served <- server.ListenAndServeTLS(); close(returned) }()
	t.Cleanup(func() {
		handler.resume()
		stopServer(server)
		select {
		case <-returned:
		case <-time.After(tlsEpollFixServeReturnLimit):
			t.Error("TLS server did not stop during cleanup")
		}
	})
	return server, served
}

func startupWaitResult(t *testing.T, served <-chan error) error {
	t.Helper()
	select {
	case err := <-served:
		return err
	case <-time.After(tlsEpollFixServeReturnLimit):
		t.Fatal("TLS startup did not return")
		return nil
	}
}
func requireStartupPortReleased(t *testing.T, addr string) {
	t.Helper()
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("startup retained listener %s: %v", addr, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}
func requireStartupWakersReleased(t *testing.T, server *Server) {
	t.Helper()
	server.wakersMu.Lock()
	remaining := len(server.wakers)
	server.wakersMu.Unlock()
	if remaining != 0 {
		t.Fatalf("startup retained %d shutdown wakers", remaining)
	}
}

func TestTLSReadyEventServesRealRequests(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			barrier := newStartupLogBarrier("HTTPS listening")
			server, served := startTLSStartupServer(t, barrier, Config{Listeners: 2})
			select {
			case <-barrier.entered:
			case <-time.After(tlsEpollFixServeReturnLimit):
				t.Fatal("no HTTPS readiness event")
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: harnessIOTimeout}, "tcp4", server.config.Addr, &tls.Config{ServerName: harnessDomain, InsecureSkipVerify: true, MinVersion: version, MaxVersion: version, NextProtos: []string{"http/1.1"}})
			if err != nil {
				t.Fatalf("HTTPS readiness event preceded a usable TLS worker: %v", err)
			}
			defer conn.Close()
			if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
				t.Fatalf("ALPN %q, want http/1.1", got)
			}
			if err := conn.SetDeadline(wallDeadline(harnessIOTimeout)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, "GET /ready HTTP/1.1\r\nHost: "+harnessDomain+"\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, body := readH1Response(t, bufio.NewReader(conn), "GET")
			if response.StatusCode != 200 || string(body) != "ready handler" {
				t.Fatalf("ready response status=%d body=%q", response.StatusCode, body)
			}
			barrier.resume()
			stopServer(server)
			if err := startupWaitResult(t, served); err != nil {
				t.Fatal(err)
			}
			if got := barrier.ready.Load(); got != 1 {
				t.Fatalf("HTTPS readiness events=%d, want 1", got)
			}
			requireStartupWakersReleased(t, server)
		})
	}
}

func TestTLSStartupBindFailurePrecedesRedirect(t *testing.T) {
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	barrier := newStartupLogBarrier("")
	redirectAddr := freeLoopbackAddr(t)
	server, served := startTLSStartupServer(t, barrier, Config{Addr: occupied.Addr().String(), HTTPAddr: redirectAddr})
	if err := startupWaitResult(t, served); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("occupied HTTPS port error=%v, want EADDRINUSE", err)
	}
	if barrier.ready.Load() != 0 {
		t.Fatal("failed HTTPS bind emitted readiness")
	}
	requireStartupWakersReleased(t, server)
	requireStartupPortReleased(t, redirectAddr)
}

func TestTLSStartupRedirectFailureReleasesPreparedWorkers(t *testing.T) {
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	barrier := newStartupLogBarrier("")
	server, served := startTLSStartupServer(t, barrier, Config{HTTPAddr: occupied.Addr().String()})
	if err := startupWaitResult(t, served); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("occupied redirect port error=%v, want EADDRINUSE", err)
	}
	if barrier.ready.Load() != 0 {
		t.Fatal("failed redirect startup emitted HTTPS readiness")
	}
	requireStartupWakersReleased(t, server)
	requireStartupPortReleased(t, server.config.Addr)
}

func TestTLSShutdownBeforeHandoffReleasesPreparedWorkers(t *testing.T) {
	barrier := newStartupLogBarrier("HTTP redirect listening")
	redirectAddr := freeLoopbackAddr(t)
	server, served := startTLSStartupServer(t, barrier, Config{HTTPAddr: redirectAddr})
	select {
	case <-barrier.entered:
	case <-time.After(tlsEpollFixServeReturnLimit):
		t.Fatal("redirect preparation did not finish")
	}
	server.wakersMu.Lock()
	prepared := len(server.wakers)
	server.wakersMu.Unlock()
	if prepared != 1 {
		t.Fatalf("registered prepared workers=%d, want 1", prepared)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	barrier.resume()
	if err := startupWaitResult(t, served); err != nil {
		t.Fatal(err)
	}
	if barrier.ready.Load() != 0 {
		t.Fatal("shutdown before handoff emitted HTTPS readiness")
	}
	requireStartupWakersReleased(t, server)
	requireStartupPortReleased(t, server.config.Addr)
	proxyFixEventually(t, "asynchronous redirect listener teardown", func() bool {
		listener, err := net.Listen("tcp4", redirectAddr)
		if err != nil {
			return false
		}
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
		return true
	})
	if server.x25519Pool != nil {
		t.Fatal("shutdown before handoff created a TLS key pool")
	}
}

func TestTLSPartialWorkerPreparationRollsBack(t *testing.T) {
	if os.Getenv("ALOS_TLS_PARTIAL_PREP_CHILD") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestTLSPartialWorkerPreparationRollsBack$", "-test.count=1", "-test.v")
		command.Env = append(os.Environ(), "ALOS_TLS_PARTIAL_PREP_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("partial-preparation child: %v\n%s", err, output)
		}
		return
	}
	addr := freeLoopbackAddr(t)
	server := New(Config{Addr: addr, HTTPAddr: "-", Listeners: 2, MaxConnsPerIP: -1, DisableOCSPStapling: true})
	defer stopServer(server)
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	limited := original
	limited.Cur = uint64(len(entries) + tlsEpollFixEMFILEHeadroom)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limited); err != nil {
		t.Fatal(err)
	}
	var held []int
	restore := func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &original); err != nil {
			t.Error(err)
		}
		for _, fd := range held {
			if err := syscall.Close(fd); err != nil {
				t.Error(err)
			}
		}
		held = nil
	}
	defer restore()
	for {
		fd, err := syscall.Dup(1)
		if errors.Is(err, syscall.EMFILE) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, fd)
	}
	if len(held) < 3 {
		t.Fatal("insufficient fixture descriptors to release one worker's three fd slots")
	}
	for range 3 {
		last := len(held) - 1
		if err := syscall.Close(held[last]); err != nil {
			t.Fatal(err)
		}
		held = held[:last]
	}
	probe, err := newEpollWorker(server, addr, 0)
	if err != nil {
		t.Fatalf("three free descriptor slots did not construct one whole worker: %v", err)
	}
	server.wakersMu.Lock()
	registered := len(server.wakers)
	server.wakersMu.Unlock()
	if registered != 1 {
		t.Fatalf("fixture worker wakers=%d, want 1", registered)
	}
	closeUnstartedEpollWorkers([]*epollWorker{probe})
	workers, err := server.prepareEpollWorkers(addr, true)
	restore()
	if !errors.Is(err, syscall.EMFILE) || !strings.Contains(err.Error(), "epoll listen") {
		t.Fatalf("second worker error=%v, want listener EMFILE", err)
	}
	if len(workers) != 0 {
		t.Fatalf("failed preparation returned %d workers", len(workers))
	}
	requireStartupWakersReleased(t, server)
	requireStartupPortReleased(t, addr)
}

type startupHelloProbe struct {
	net.Conn
	sent chan struct{}
	once sync.Once
}

func (c *startupHelloProbe) Write(data []byte) (int, error) {
	written, err := c.Conn.Write(data)
	if written > 0 {
		c.once.Do(func() { close(c.sent) })
	}
	return written, err
}

func TestTLSConnectionQueuedDuringStartupSurvivesHandoff(t *testing.T) {
	barrier := newStartupLogBarrier("HTTP redirect listening")
	server, served := startTLSStartupServer(t, barrier, Config{HTTPAddr: freeLoopbackAddr(t)})
	select {
	case <-barrier.entered:
	case <-time.After(tlsEpollFixServeReturnLimit):
		t.Fatal("startup did not reach redirect preparation")
	}
	tcp, err := net.DialTimeout("tcp4", server.config.Addr, harnessIOTimeout)
	if err != nil {
		t.Fatalf("actual TLS listener was not retained during preparation: %v", err)
	}
	defer tcp.Close()
	probe := &startupHelloProbe{Conn: tcp, sent: make(chan struct{})}
	conn := tls.Client(probe, &tls.Config{ServerName: harnessDomain, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	ctx, cancel := context.WithTimeout(context.Background(), tlsEpollFixServeReturnLimit)
	defer cancel()
	handshake := make(chan error, 1)
	go func() { handshake <- conn.HandshakeContext(ctx) }()
	select {
	case <-probe.sent:
	case <-ctx.Done():
		t.Fatal("TLS ClientHello was not queued before handoff")
	}
	if barrier.ready.Load() != 0 {
		t.Fatal("HTTPS advertised ready before handoff")
	}
	barrier.resume()
	select {
	case err := <-handshake:
		if err != nil {
			t.Fatalf("queued TLS connection did not survive listener handoff: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("queued TLS handshake did not finish")
	}
	if err := conn.SetDeadline(wallDeadline(harnessIOTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET /ready HTTP/1.1\r\nHost: "+harnessDomain+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, body := readH1Response(t, bufio.NewReader(conn), "GET")
	if response.StatusCode != 200 || string(body) != "ready handler" {
		t.Fatalf("queued response status=%d body=%q", response.StatusCode, body)
	}
	stopServer(server)
	if err := startupWaitResult(t, served); err != nil {
		t.Fatal(err)
	}
}

func TestEpollUnstartedWorkersCloseResources(t *testing.T) {
	server := New(Config{Addr: freeLoopbackAddr(t), HTTPAddr: "-", Listeners: 1, MaxConnsPerIP: -1, DisableOCSPStapling: true})
	defer stopServer(server)
	workers, err := server.prepareEpollWorkers(server.config.Addr, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(workers) != 1 {
		t.Fatalf("prepared workers=%d, want 1", len(workers))
	}
	closeUnstartedEpollWorkers(workers)
	worker := workers[0]
	for name, fd := range map[string]int{"listener": worker.listenerFD, "epoll": worker.epfd, "wake": worker.wakeFd} {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != syscall.EBADF {
			t.Errorf("unstarted %s descriptor remained open: %v", name, errno)
		}
	}
	select {
	case _, open := <-worker.handlers.tasks:
		if open {
			t.Error("unstarted handler pool remained open")
		}
	default:
		t.Error("unstarted handler pool remained open")
	}
	requireStartupWakersReleased(t, server)
	requireStartupPortReleased(t, server.config.Addr)
}
