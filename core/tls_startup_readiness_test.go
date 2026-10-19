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
	if server.doneClosed() || server.x25519Pool != nil {
		t.Fatal("ordinary initial bind failure stopped the Server or started TLS runtime")
	}
	if err := occupied.Close(); err != nil {
		t.Fatal(err)
	}
	retried := make(chan error, 1)
	returned := make(chan struct{})
	t.Cleanup(func() {
		stopServer(server)
		select {
		case <-returned:
		case <-time.After(tlsEpollFixServeReturnLimit):
			t.Error("retried server did not stop")
		}
	})
	go func() { retried <- server.ListenAndServeTLS(); close(returned) }()
	waitFor(t, tlsEpollFixServeReturnLimit, func() bool { return barrier.ready.Load() == 1 })
	requireStartupTLSRequest(t, server, tls.VersionTLS13)
	stopServer(server)
	if err := startupWaitResult(t, retried); err != nil {
		t.Fatal(err)
	}
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
	if !errors.Is(err, syscall.EMFILE) || !strings.Contains(err.Error(), "epoll bind") {
		t.Fatalf("second worker error=%v, want listener EMFILE", err)
	}
	if len(workers) != 0 {
		t.Fatalf("failed preparation returned %d workers", len(workers))
	}
	requireStartupWakersReleased(t, server)
	requireStartupPortReleased(t, addr)
}

func TestTLSStartupDoesNotAcceptBeforeRuntime(t *testing.T) {
	barrier := newStartupLogBarrier("HTTP redirect listening")
	server, served := startTLSStartupServer(t, barrier, Config{HTTPAddr: freeLoopbackAddr(t)})
	select {
	case <-barrier.entered:
	case <-time.After(tlsEpollFixServeReturnLimit):
		t.Fatal("startup did not reach pre-runtime preparation")
	}
	if server.x25519Pool != nil {
		t.Fatal("fixture did not hold startup before TLS runtime initialization")
	}
	server.wakersMu.Lock()
	var descriptors []int
	for registered := range server.wakers {
		descriptors = append(descriptors, registered.(*epollWorker).listenerFD)
	}
	server.wakersMu.Unlock()
	if len(descriptors) != 1 {
		t.Fatalf("prepared workers=%d, want 1", len(descriptors))
	}
	for _, fd := range descriptors {
		accepting, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
		if err != nil {
			t.Fatal(err)
		}
		if accepting != 0 {
			t.Errorf("prepared socket accepts TCP before runtime initialization: SO_ACCEPTCONN=%d", accepting)
		}
	}
	raw, err := net.DialTimeout("tcp4", server.config.Addr, harnessIOTimeout)
	if err == nil {
		if err := raw.Close(); err != nil {
			t.Error(err)
		}
		t.Error("TCP connected before TLS runtime was initialized")
	} else if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("pre-runtime connect error=%v, want ECONNREFUSED", err)
	}
	if barrier.ready.Load() != 0 {
		t.Fatal("HTTPS advertised ready before runtime initialization")
	}
	barrier.resume()
	waitFor(t, tlsEpollFixServeReturnLimit, func() bool { return barrier.ready.Load() == 1 })
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		requireStartupTLSRequest(t, server, version)
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
	requireStartupWorkerFDsClosed(t, workers)
	requireStartupWakersReleased(t, server)
	requireStartupPortReleased(t, server.config.Addr)
}

func requireStartupTLSRequest(t *testing.T, server *Server, version uint16) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: harnessIOTimeout}, "tcp4", server.config.Addr, &tls.Config{ServerName: harnessDomain, InsecureSkipVerify: true, MinVersion: version, MaxVersion: version, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("ready %s handshake: %v", tls.VersionName(version), err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("ALPN=%q, want http/1.1", got)
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
}

func startupPreparedWorkers(server *Server) []*epollWorker {
	server.wakersMu.Lock()
	defer server.wakersMu.Unlock()
	var workers []*epollWorker
	for registered := range server.wakers {
		workers = append(workers, registered.(*epollWorker))
	}
	return workers
}

func requireStartupWorkerFDsClosed(t *testing.T, workers []*epollWorker) {
	t.Helper()
	for _, worker := range workers {
		for name, fd := range map[string]int{"listener": worker.listenerFD, "epoll": worker.epfd, "wake": worker.wakeFd} {
			_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
			if errno != syscall.EBADF {
				t.Errorf("startup %s descriptor remained open: %v", name, errno)
			}
		}
		select {
		case _, open := <-worker.handlers.tasks:
			if open {
				t.Error("startup handler pool remained open")
			}
		default:
			t.Error("startup handler pool remained open")
		}
	}
}

func TestTLSActivationConflictStopsStartup(t *testing.T) {
	barrier := newStartupLogBarrier("HTTP redirect listening")
	redirectAddr := freeLoopbackAddr(t)
	server, served := startTLSStartupServer(t, barrier, Config{HTTPAddr: redirectAddr})
	select {
	case <-barrier.entered:
	case <-time.After(tlsEpollFixServeReturnLimit):
		t.Fatal("startup did not reach pre-runtime preparation")
	}
	workers := startupPreparedWorkers(server)
	if len(workers) != 1 {
		t.Fatalf("prepared workers=%d, want 1", len(workers))
	}
	contender, err := net.Listen("tcp4", server.config.Addr)
	if err != nil {
		t.Fatalf("fixture contender could not occupy the bound-but-unlistening address: %v", err)
	}
	defer contender.Close()
	ai := &acmeIntegration{server: server, stop: make(chan struct{}), now: time.Now}
	ai.sleep = ai.sleepUnlessStopped
	server.replaceACME(ai)
	barrier.resume()
	err = startupWaitResult(t, served)
	if !errors.Is(err, syscall.EADDRINUSE) || !strings.Contains(err.Error(), "epoll listen") {
		t.Fatalf("activation error=%v, want contextual Listen/EADDRINUSE", err)
	}
	if barrier.ready.Load() != 0 {
		t.Error("failed activation advertised HTTPS readiness")
	}
	if !server.doneClosed() {
		t.Error("terminal activation failure did not shut down the Server")
	}
	requireStartupWorkerFDsClosed(t, workers)
	requireStartupWakersReleased(t, server)
	if server.x25519Pool == nil {
		t.Fatal("fixture did not reach TLS runtime initialization")
	}
	select {
	case <-server.x25519Pool.stop:
	default:
		t.Error("terminal activation failure retained TLS keypool fillers")
	}
	select {
	case <-ai.stop:
	default:
		t.Error("terminal activation failure did not signal ACME Stop")
	}
	proxyFixEventually(t, "redirect listener teardown after failed activation", func() bool {
		listener, err := net.Listen("tcp4", redirectAddr)
		if err != nil {
			return false
		}
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
		return true
	})
}

func startupBoundWorker(t *testing.T, server *Server, addr string) *epollWorker {
	t.Helper()
	fd, err := epollBind(addr)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := newEpollWorkerFromFD(server, fd, 0)
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func TestEpollPartialActivationRollsBackListeners(t *testing.T) {
	server := New(Config{HTTPAddr: "-", Listeners: 1, MaxConnsPerIP: -1, DisableOCSPStapling: true})
	defer stopServer(server)
	firstAddr := freeLoopbackAddr(t)
	first := startupBoundWorker(t, server, firstAddr)
	workers := []*epollWorker{first}
	owned := true
	t.Cleanup(func() {
		if owned {
			closeUnstartedEpollWorkers(workers)
		}
	})
	secondAddr := freeLoopbackAddr(t)
	second := startupBoundWorker(t, server, secondAddr)
	second.coreID = 1
	workers = append(workers, second)
	if err := syscall.Listen(first.listenerFD, epollListenBacklog); err != nil {
		t.Fatal(err)
	}
	accepting, err := syscall.GetsockoptInt(first.listenerFD, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
	if err != nil || accepting != 1 {
		t.Fatalf("first listener precondition: accepting=%d err=%v", accepting, err)
	}
	contender, err := net.Listen("tcp4", secondAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer contender.Close()
	owned = false
	results, err := server.startEpollWorkers(workers)
	if !errors.Is(err, syscall.EADDRINUSE) || !strings.Contains(err.Error(), "epoll listen worker 1") {
		t.Fatalf("partial activation error=%v, want second-listener EADDRINUSE", err)
	}
	if results != nil {
		t.Error("partial activation handed workers to run goroutines")
	}
	requireStartupWorkerFDsClosed(t, workers)
	requireStartupWakersReleased(t, server)
	requireStartupPortReleased(t, firstAddr)
	if server.doneClosed() {
		t.Error("direct activation error changed external Server lifecycle ownership")
	}
}

func TestEpollActivationHonorsPriorShutdown(t *testing.T) {
	server := New(Config{Addr: freeLoopbackAddr(t), HTTPAddr: "-", Listeners: 1, MaxConnsPerIP: -1, DisableOCSPStapling: true})
	defer stopServer(server)
	workers, err := server.prepareEpollWorkers(server.config.Addr, true)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := syscall.Dup(workers[0].listenerFD)
	if err != nil {
		closeUnstartedEpollWorkers(workers)
		t.Fatal(err)
	}
	defer syscall.Close(duplicate)
	if err := server.Shutdown(context.Background()); err != nil {
		closeUnstartedEpollWorkers(workers)
		t.Fatal(err)
	}
	results, err := server.startEpollWorkers(workers)
	if !errors.Is(err, ErrServerShutdown) || results != nil {
		t.Fatalf("activation after shutdown: results=%v err=%v", results, err)
	}
	accepting, err := syscall.GetsockoptInt(duplicate, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
	if err != nil || accepting != 0 {
		t.Fatalf("activation listened after observed shutdown: accepting=%d err=%v", accepting, err)
	}
	requireStartupWorkerFDsClosed(t, workers)
	requireStartupWakersReleased(t, server)
}

func TestEpollShutdownRacesActivation(t *testing.T) {
	for range tlsEpollFixShutdownRaceRuns {
		server := New(Config{Addr: freeLoopbackAddr(t), HTTPAddr: "-", Listeners: 2, MaxConnsPerIP: -1, DisableOCSPStapling: true})
		workers, err := server.prepareEpollWorkers(server.config.Addr, true)
		if err != nil {
			stopServer(server)
			t.Fatal(err)
		}
		activated := make(chan struct {
			results <-chan error
			err     error
		}, 1)
		shutdown := make(chan error, 1)
		go func() {
			results, err := server.startEpollWorkers(workers)
			activated <- struct {
				results <-chan error
				err     error
			}{results, err}
		}()
		go func() { shutdown <- server.Shutdown(context.Background()) }()
		result := <-activated
		if err := <-shutdown; err != nil {
			t.Fatal(err)
		}
		if result.err != nil {
			if !errors.Is(result.err, ErrServerShutdown) {
				t.Fatal(result.err)
			}
		} else {
			for range workers {
				if err := startupWaitResult(t, result.results); err != nil {
					t.Fatal(err)
				}
			}
		}
		requireStartupWorkerFDsClosed(t, workers)
		requireStartupWakersReleased(t, server)
		requireStartupPortReleased(t, server.config.Addr)
	}
}

func TestEpollImmediateListenerWrappersStillAccept(t *testing.T) {
	for _, mode := range []string{"socket", "worker"} {
		t.Run(mode, func(t *testing.T) {
			addr := freeLoopbackAddr(t)
			var fd int
			if mode == "socket" {
				var err error
				fd, err = epollListen(addr)
				if err != nil {
					t.Fatal(err)
				}
				defer syscall.Close(fd)
			} else {
				server := New(Config{HTTPAddr: "-", Listeners: 1, MaxConnsPerIP: -1, DisableOCSPStapling: true})
				defer stopServer(server)
				worker, err := newEpollWorker(server, addr, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer closeUnstartedEpollWorkers([]*epollWorker{worker})
				fd = worker.listenerFD
			}
			accepting, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
			if err != nil || accepting != 1 {
				t.Fatalf("immediate-listen wrapper: accepting=%d err=%v", accepting, err)
			}
			conn, err := net.DialTimeout("tcp4", addr, harnessIOTimeout)
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTLSActivationConflictPreservesShutdownError(t *testing.T) {
	barrier := newStartupLogBarrier("HTTP redirect listening")
	server, served := startTLSStartupServer(t, barrier, Config{HTTPAddr: freeLoopbackAddr(t), ShutdownTimeout: tlsEpollFixShutdownCtx})
	select {
	case <-barrier.entered:
	case <-time.After(tlsEpollFixServeReturnLimit):
		t.Fatal("startup did not reach pre-runtime preparation")
	}
	contender, err := net.Listen("tcp4", server.config.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer contender.Close()
	if !server.tryTrackConn() {
		t.Fatal("fixture could not reserve one active connection")
	}
	defer server.releaseTrackedConn()
	if server.activeConns.Load() != 1 {
		t.Fatal("fixture does not hold one active connection across failed activation")
	}
	barrier.resume()
	err = startupWaitResult(t, served)
	if !errors.Is(err, syscall.EADDRINUSE) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("activation and shutdown error=%v, want both EADDRINUSE and DeadlineExceeded", err)
	}
	if barrier.ready.Load() != 0 {
		t.Error("failed activation advertised HTTPS readiness")
	}
	if !server.doneClosed() {
		t.Error("terminal activation failure did not shut down the Server")
	}
	requireStartupWakersReleased(t, server)
}
