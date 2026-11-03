//go:build linux && amd64

package core

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	startupProbeTimeout = 2 * time.Second
	startupPollInterval = 15 * time.Millisecond
)

type startupHookHandler struct {
	hooks map[string]func()
}

func (h *startupHookHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *startupHookHandler) Handle(_ context.Context, r slog.Record) error {
	if hook := h.hooks[r.Message]; hook != nil {
		hook()
	}
	return nil
}

func (h *startupHookHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *startupHookHandler) WithGroup(string) slog.Handler      { return h }

func startupTestConfig(addr, httpAddr string, hooks map[string]func()) Config {
	return Config{
		Addr:          addr,
		HTTPAddr:      httpAddr,
		Listeners:     1,
		MaxConnsPerIP: -1,
		Certs:         []CertConfig{{Domain: "localhost", Source: CertSelfSigned}},
		Logger:        slog.New(&startupHookHandler{hooks: hooks}),
	}
}

func startupHandshake(addr string) error {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: startupProbeTimeout},
		Config:    &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), startupProbeTimeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

func TestHTTPSListeningLoggedOnlyWhenServing(t *testing.T) {
	addr := freeLoopbackAddr(t)
	handshakeErr := make(chan error, 1)
	srv := New(startupTestConfig(addr, "-", map[string]func(){
		"HTTPS listening": func() { handshakeErr <- startupHandshake(addr) },
	}))
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServeTLS() }()
	t.Cleanup(func() { stopServer(srv) })
	select {
	case err := <-handshakeErr:
		if err != nil {
			t.Fatalf("handshake at the moment HTTPS listening was logged failed: %v", err)
		}
	case err := <-served:
		t.Fatalf("ListenAndServeTLS returned before logging HTTPS listening: %v", err)
	case <-time.After(3 * startupProbeTimeout):
		t.Fatal("HTTPS listening was never logged")
	}
}

func TestHTTPSPortHeldThroughTLSStartup(t *testing.T) {
	addr := freeLoopbackAddr(t)
	httpAddr := freeLoopbackAddr(t)
	stealErr := make(chan error, 1)
	srv := New(startupTestConfig(addr, httpAddr, map[string]func(){
		"HTTP redirect listening": func() {
			ln, err := net.Listen("tcp4", addr)
			if err == nil {
				_ = ln.Close()
				stealErr <- errors.New("HTTPS port was free while the redirect listener started")
				return
			}
			conn, err := net.DialTimeout("tcp4", addr, startupProbeTimeout)
			if err == nil {
				_ = conn.Close()
				stealErr <- errors.New("HTTPS port accepted TCP before the TLS runtime was ready")
				return
			}
			stealErr <- nil
		},
	}))
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServeTLS() }()
	t.Cleanup(func() { stopServer(srv) })
	select {
	case err := <-stealErr:
		if err != nil {
			t.Fatal(err)
		}
	case err := <-served:
		t.Fatalf("ListenAndServeTLS returned during startup: %v", err)
	case <-time.After(3 * startupProbeTimeout):
		t.Fatal("redirect listener never started")
	}
	waitForProxy(t, addr)
	if err := startupHandshake(addr); err != nil {
		t.Fatalf("server not serving after startup: %v", err)
	}
}

func TestShutdownDuringTLSStartupIsRaceFree(t *testing.T) {
	for _, delay := range []time.Duration{0, time.Millisecond, 5 * time.Millisecond, 25 * time.Millisecond} {
		srv := New(startupTestConfig(freeLoopbackAddr(t), "-", nil))
		served := make(chan error, 1)
		go func() { served <- srv.ListenAndServeTLS() }()
		turbo.Sleep(delay)
		stopServer(srv)
		select {
		case err := <-served:
			if err != nil {
				t.Fatalf("delay %v: ListenAndServeTLS after Shutdown: %v", delay, err)
			}
		case <-time.After(3 * startupProbeTimeout):
			t.Fatalf("delay %v: ListenAndServeTLS did not return after Shutdown", delay)
		}
	}
}

func startupLeaveTimeWait(t *testing.T, listener net.Listener) {
	t.Helper()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := accepted.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("client did not read the server FIN: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTLSReservationToleratesForeignTimeWait(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	startupLeaveTimeWait(t, listener)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	fd, err := epollReserve(addr, true)
	if err != nil {
		t.Fatalf("TLS reservation failed on TIME_WAIT sockets of a replaced listener: %v", err)
	}
	defer unix.Close(fd)
	if contender, err := net.Listen("tcp4", addr); err == nil {
		_ = contender.Close()
		t.Fatal("retried TLS reservation let a contender take the port")
	}
	if err := activateEpollListener(fd); err != nil {
		t.Fatalf("retried TLS reservation did not activate: %v", err)
	}
}

func TestTLSReservationRefusesLiveListener(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fd, err := epollReserve(listener.Addr().String(), true)
	if err == nil {
		_ = unix.Close(fd)
		t.Fatal("TLS reservation shared the port of a live listener")
	}
	if !errors.Is(err, unix.EADDRINUSE) {
		t.Fatalf("reservation error=%v, want EADDRINUSE", err)
	}
}

func TestActivatedListenerTimeWaitAllowsForeignRebind(t *testing.T) {
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	fd, err := epollBind(addr, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := activateEpollListener(fd); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	client, err := net.Dial("tcp4", addr)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	var acceptedFD int
	for {
		acceptedFD, _, err = unix.Accept(fd)
		if err != unix.EAGAIN {
			break
		}
		turbo.Sleep(startupPollInterval)
	}
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err := unix.Close(acceptedFD); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("client did not read the server FIN: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	rebound, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("listener with SO_REUSEADDR only could not rebind: %v", err)
	}
	if err := rebound.Close(); err != nil {
		t.Fatal(err)
	}
}
