//go:build linux && amd64

package core

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

const proxyFixTLSDomain = "redirect.test"

func proxyFixStartTLS(t testing.TB, cfg Config, tune func(*Server)) (srv *Server, httpsAddr, httpAddr string) {
	t.Helper()
	httpsAddr = proxyFixFreeAddr(t)
	httpAddr = proxyFixFreeAddr(t)
	cfg.Addr = httpsAddr
	cfg.HTTPAddr = httpAddr
	if cfg.Listeners == 0 {
		cfg.Listeners = 1
	}
	cfg.Certs = []CertConfig{{Domain: proxyFixTLSDomain, Source: CertSelfSigned}}
	srv = New(cfg)
	if tune != nil {
		tune(srv)
	}
	srv.ensureTLSRuntime()
	go func() { _ = srv.ListenAndServeTLS() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), proxyFixShutdownTO)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	proxyFixEventually(t, "https and redirect listeners accept", func() bool {
		if !proxyFixTLSHandshakeOK(httpsAddr) {
			return false
		}
		c, err := net.DialTimeout("tcp", httpAddr, proxyFixStep)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
	proxyFixEventually(t, "probe connections released", func() bool { return srv.activeConns.Load() == 0 })
	return srv, httpsAddr, httpAddr
}

func proxyFixTLSHandshakeOK(addr string) bool {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: proxyFixStep}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: proxyFixTLSDomain})
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func proxyFixOpenStalled(t *testing.T, addr string, n int) []net.Conn {
	t.Helper()
	conns := make([]net.Conn, 0, n)
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	for i := 0; i < n; i++ {
		c := proxyFixDial(t, addr)
		if _, err := c.Write([]byte("G")); err != nil {
			t.Fatalf("stalled conn %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	return conns
}

const proxyFixRedirectMaxConns = 16

func TestProxyFixRedirectFloodCannotStarveHTTPS(t *testing.T) {
	srv, httpsAddr, httpAddr := proxyFixStartTLS(t, Config{MaxConns: proxyFixRedirectMaxConns, MaxConnsPerIP: -1}, nil)
	proxyFixOpenStalled(t, httpAddr, proxyFixRedirectMaxConns+4)
	proxyFixEventually(t, "redirect connections admitted or refused", func() bool {
		return srv.activeConns.Load() > 0
	})
	time.Sleep(proxyFixStep)
	if !proxyFixTLSHandshakeOK(httpsAddr) {
		t.Fatalf("HTTPS handshake refused while port-80 connections hold activeConns=%d of MaxConns=%d",
			srv.activeConns.Load(), proxyFixRedirectMaxConns)
	}
}

const proxyFixRedirectPerIP = 3

func TestProxyFixRedirectEnforcesPerIPLimit(t *testing.T) {
	_, _, httpAddr := proxyFixStartTLS(t, Config{MaxConnsPerIP: proxyFixRedirectPerIP}, nil)
	total := proxyFixRedirectPerIP + 1
	conns := proxyFixOpenStalled(t, httpAddr, total)
	closedByServer := make(chan bool, total)
	for _, c := range conns {
		go func(c net.Conn) {
			_ = c.SetReadDeadline(wallDeadline(3 * proxyFixStep))
			var one [1]byte
			_, err := c.Read(one[:])
			closedByServer <- err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
		}(c)
	}
	closed := 0
	for range conns {
		if <-closedByServer {
			closed++
		}
	}
	held := total - closed
	if closed < 1 || held < proxyFixRedirectPerIP-1 || held > proxyFixRedirectPerIP {
		t.Fatalf("%d of %d connections from one IP to the redirect listener were held open; MaxConnsPerIP=%d admits %d, or %d when the startup probe still holds a slot",
			held, total, proxyFixRedirectPerIP, proxyFixRedirectPerIP, proxyFixRedirectPerIP-1)
	}
}
