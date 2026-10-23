//go:build linux && amd64

package core

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

const (
	proxyG2TunnelIdle  = 400 * time.Millisecond
	proxyG2TunnelReap  = 5 * time.Second
	proxyG2TunnelAlive = 6 * proxyG2TunnelIdle
	proxyG2TunnelTick  = proxyG2TunnelIdle / 4
)

type proxyG2TunnelOrigin struct {
	ln       net.Listener
	closed   chan struct{}
	received atomic.Int64
}

func newProxyG2TunnelOrigin(t *testing.T, push bool) *proxyG2TunnelOrigin {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	o := &proxyG2TunnelOrigin{ln: ln, closed: make(chan struct{})}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		for {
			line, rerr := br.ReadString('\n')
			if rerr != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		stop := make(chan struct{})
		if push {
			go func() {
				for {
					select {
					case <-stop:
						return
					case <-time.After(proxyG2TunnelTick):
					}
					if _, werr := conn.Write([]byte{'b'}); werr != nil {
						return
					}
				}
			}()
		}
		buf := make([]byte, 512)
		for {
			n, rerr := br.Read(buf)
			o.received.Add(int64(n))
			if rerr != nil {
				close(stop)
				close(o.closed)
				return
			}
		}
	}()
	return o
}

func proxyG2TunnelServer(t *testing.T, o *proxyG2TunnelOrigin) (*Server, net.Conn) {
	t.Helper()
	srv, addr := proxyFixStart(t, Config{IdleTimeout: proxyG2TunnelIdle}, proxyFixSingleBackend(o.ln.Addr().String()), nil)
	return srv, proxyFixTunnelUpgrade(t, addr)
}

func proxyG2ReadUntilClosed(c net.Conn, within time.Duration) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(within))
	total := 0
	buf := make([]byte, 512)
	for {
		n, err := c.Read(buf)
		total += n
		if err != nil {
			return total, err
		}
	}
}

func TestProxyTunnelIdleClientIsReaped(t *testing.T) {
	o := newProxyG2TunnelOrigin(t, false)
	srv, c := proxyG2TunnelServer(t, o)
	defer c.Close()
	if _, err := proxyG2ReadUntilClosed(c, proxyG2TunnelReap); !errors.Is(err, io.EOF) {
		t.Fatalf("idle tunnel was not closed within %v: %v", proxyG2TunnelReap, err)
	}
	select {
	case <-o.closed:
	case <-time.After(proxyG2TunnelReap):
		t.Fatalf("the backend half of an idle tunnel stayed open")
	}
	proxyFixAssertConnsDrain(t, srv, "idle tunnel")
}

func TestProxyTunnelBackendTrafficKeepsTunnelOpen(t *testing.T) {
	o := newProxyG2TunnelOrigin(t, true)
	_, c := proxyG2TunnelServer(t, o)
	defer c.Close()
	got, err := proxyG2ReadUntilClosed(c, proxyG2TunnelAlive)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("tunnel with backend traffic closed after %d bytes: %v", got, err)
	}
	if got < int(proxyG2TunnelAlive/proxyG2TunnelTick)/2 {
		t.Fatalf("client got %d bytes in %v, the backend sends one per %v", got, proxyG2TunnelAlive, proxyG2TunnelTick)
	}
}

func TestProxyTunnelClientTrafficKeepsTunnelOpen(t *testing.T) {
	o := newProxyG2TunnelOrigin(t, false)
	_, c := proxyG2TunnelServer(t, o)
	defer c.Close()
	sent := 0
	for end := time.Now().Add(proxyG2TunnelAlive); time.Now().Before(end); sent++ {
		_ = c.SetWriteDeadline(time.Now().Add(proxyFixIOTimeout))
		if _, err := c.Write([]byte{'c'}); err != nil {
			t.Fatalf("tunnel with client traffic closed after %d bytes: %v", sent, err)
		}
		time.Sleep(proxyG2TunnelTick)
	}
	select {
	case <-o.closed:
		t.Fatalf("the backend half closed while the client was sending")
	default:
	}
	proxyFixEventually(t, "client bytes reach the backend", func() bool { return o.received.Load() == int64(sent) })
}

func proxyG2TCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	dialed, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	inner := <-accepted
	if inner == nil {
		t.Fatalf("accept failed")
	}
	t.Cleanup(func() { _ = dialed.Close(); _ = inner.Close() })
	return dialed, inner
}

func TestPipeUpgradeTunnelClosesWhenIdle(t *testing.T) {
	clientPeer, clientSide := proxyG2TCPPair(t)
	backendSide, backendPeer := proxyG2TCPPair(t)
	done := make(chan struct{})
	go func() {
		pipeUpgradeTunnel(clientSide, backendSide, proxyG2TunnelIdle)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(proxyG2TunnelReap):
		t.Fatalf("idle goroutine tunnel still open after %v", proxyG2TunnelReap)
	}
	if _, err := proxyG2ReadUntilClosed(clientPeer, proxyFixIOTimeout); !errors.Is(err, io.EOF) {
		t.Fatalf("client half not closed: %v", err)
	}
	if _, err := proxyG2ReadUntilClosed(backendPeer, proxyFixIOTimeout); !errors.Is(err, io.EOF) {
		t.Fatalf("backend half not closed: %v", err)
	}
}

func TestPipeUpgradeTunnelOneWayTrafficKeepsItOpen(t *testing.T) {
	for _, dir := range []string{"backend to client", "client to backend"} {
		clientPeer, clientSide := proxyG2TCPPair(t)
		backendSide, backendPeer := proxyG2TCPPair(t)
		src, dst := backendPeer, clientPeer
		if dir == "client to backend" {
			src, dst = clientPeer, backendPeer
		}
		done := make(chan struct{})
		go func() {
			pipeUpgradeTunnel(clientSide, backendSide, proxyG2TunnelIdle)
			close(done)
		}()
		var delivered atomic.Int64
		go func() {
			buf := make([]byte, 64)
			for {
				n, err := dst.Read(buf)
				delivered.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
		sent := 0
		for end := time.Now().Add(proxyG2TunnelAlive); time.Now().Before(end); sent++ {
			if _, err := src.Write([]byte{'x'}); err != nil {
				t.Fatalf("%s: write %d failed: %v", dir, sent, err)
			}
			time.Sleep(proxyG2TunnelTick)
		}
		select {
		case <-done:
			t.Fatalf("%s: tunnel closed while bytes were flowing", dir)
		default:
		}
		proxyFixEventually(t, dir+" bytes delivered", func() bool { return delivered.Load() == int64(sent) })
	}
}

func TestPipeUpgradeTunnelClosesWhenBothPeersStopReading(t *testing.T) {
	clientPeer, clientSide := proxyG2TCPPair(t)
	backendSide, backendPeer := proxyG2TCPPair(t)
	done := make(chan struct{})
	go func() {
		pipeUpgradeTunnel(clientSide, backendSide, proxyG2TunnelIdle)
		close(done)
	}()
	flood := func(c net.Conn) {
		chunk := make([]byte, 64<<10)
		for {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	}
	go flood(clientPeer)
	go flood(backendPeer)
	select {
	case <-done:
	case <-time.After(proxyG2TunnelReap):
		t.Fatalf("tunnel whose peers both stopped reading still open after %v", proxyG2TunnelReap)
	}
}

func TestProxyTLSTunnelIdleClientIsReaped(t *testing.T) {
	o := newProxyFix3UpgradeOrigin(t)
	_, httpsAddr, _ := proxyFixStartTLS(t, Config{MaxConnsPerIP: -1, IdleTimeout: proxyG2TunnelIdle}, func(s *Server) {
		s.AddProxyDomain(DomainConfig{Domain: proxyFixTLSDomain, Backends: []BackendConfig{{Addr: o.addr()}}})
	})
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: proxyFixIOTimeout}, "tcp", httpsAddr, &tls.Config{
		InsecureSkipVerify: true, ServerName: proxyFixTLSDomain, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(wallDeadline(proxyFixIOTimeout))
	proxyFix4ExpectTLSTunnel(t, c, proxyFix4TLSUpgrade("/ws"), false)
	if _, err := proxyG2ReadUntilClosed(c, proxyG2TunnelReap); !errors.Is(err, io.EOF) {
		t.Fatalf("idle TLS tunnel was not closed within %v: %v", proxyG2TunnelReap, err)
	}
}
