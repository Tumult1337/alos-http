//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	proxyFixTunnelFlood      = 64 << 20
	proxyFixTunnelFloodBound = 32 << 20
	proxyFixTunnelChunk      = 64 << 10
	proxyFixTunnelDelivered  = 16 << 20
	proxyFixSettleSteps      = 6
)

type proxyFixUpgradeOrigin struct {
	ln       net.Listener
	received atomic.Int64
	reading  chan struct{}
}

func newProxyFixUpgradeOrigin(t *testing.T) *proxyFixUpgradeOrigin {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	o := &proxyFixUpgradeOrigin{ln: ln, reading: make(chan struct{})}
	t.Cleanup(func() { _ = ln.Close() })
	t.Cleanup(o.startReading)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go o.serve(conn)
		}
	}()
	return o
}

func (o *proxyFixUpgradeOrigin) startReading() {
	select {
	case <-o.reading:
	default:
		close(o.reading)
	}
}

func (o *proxyFixUpgradeOrigin) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	<-o.reading
	buf := make([]byte, proxyFixTunnelChunk)
	for {
		n, err := br.Read(buf)
		o.received.Add(int64(n))
		if err != nil {
			return
		}
	}
}

func proxyFixTunnelUpgrade(t *testing.T, addr string) net.Conn {
	t.Helper()
	c := proxyFixDial(t, addr)
	_ = c.SetDeadline(time.Time{})
	if _, err := io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: "+proxyFixDomain+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	_ = c.SetReadDeadline(wallDeadline(proxyFixIOTimeout))
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("upgrade status %q, err %v", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read upgrade headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	return c
}

func proxyFixPush(c net.Conn, total int, stop <-chan struct{}) *atomic.Int64 {
	var written atomic.Int64
	chunk := make([]byte, proxyFixTunnelChunk)
	go func() {
		for int(written.Load()) < total {
			select {
			case <-stop:
				return
			default:
			}
			_ = c.SetWriteDeadline(wallDeadline(proxyFixStep))
			n, err := c.Write(chunk)
			written.Add(int64(n))
			if err != nil && !proxyFixIsTimeout(err) {
				return
			}
		}
	}()
	return &written
}

func proxyFixIsTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func TestProxyFixTunnelPausesClientWhenBackendStalls(t *testing.T) {
	o := newProxyFixUpgradeOrigin(t)
	_, addr := proxyFixStart(t, Config{IdleTimeout: proxyFixSettleSteps * proxyFixStep},
		proxyFixSingleBackend(o.ln.Addr().String()), nil)
	c := proxyFixTunnelUpgrade(t, addr)
	defer c.Close()
	stop := make(chan struct{})
	defer close(stop)
	written := proxyFixPush(c, proxyFixTunnelFlood, stop)

	prev := int64(-1)
	for deadline := turbo.Deadline(proxyFixSettleSteps * proxyFixStep); turbo.Until(deadline) > 0; {
		time.Sleep(proxyFixStep)
		cur := written.Load()
		if cur >= proxyFixTunnelFloodBound || cur == prev {
			break
		}
		prev = cur
	}
	t.Logf("client pushed %d MiB before the tunnel stopped reading", written.Load()>>20)
	if got := written.Load(); got >= proxyFixTunnelFloodBound {
		t.Fatalf("client pushed %d MiB into a tunnel whose backend never reads; the proxy must stop reading the client (bound %d MiB)",
			got>>20, proxyFixTunnelFloodBound>>20)
	}
}

func TestProxyFixTunnelResumesAfterBackendDrains(t *testing.T) {
	o := newProxyFixUpgradeOrigin(t)
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.ln.Addr().String()), nil)
	c := proxyFixTunnelUpgrade(t, addr)
	defer c.Close()
	stop := make(chan struct{})
	defer close(stop)
	written := proxyFixPush(c, proxyFixTunnelDelivered, stop)
	time.Sleep(proxyFixStep)
	o.startReading()
	proxyFixEventually(t, "every client byte reaches the backend once it reads again", func() bool {
		return written.Load() >= proxyFixTunnelDelivered && o.received.Load() >= written.Load()
	})
}

func TestProxyFixPausedTunnelClosesWhenClientLeaves(t *testing.T) {
	o := newProxyFixUpgradeOrigin(t)
	srv, addr := proxyFixStart(t, Config{IdleTimeout: proxyFixSettleSteps * proxyFixStep},
		proxyFixSingleBackend(o.ln.Addr().String()), nil)
	c := proxyFixTunnelUpgrade(t, addr)
	stop := make(chan struct{})
	written := proxyFixPush(c, proxyFixTunnelFlood, stop)
	prev := int64(-1)
	for deadline := turbo.Deadline(proxyFixSettleSteps * proxyFixStep); turbo.Until(deadline) > 0; {
		time.Sleep(proxyFixStep)
		cur := written.Load()
		if cur == prev {
			break
		}
		prev = cur
	}
	close(stop)
	_ = c.Close()
	proxyFixAssertConnsDrain(t, srv, "paused tunnel whose client closed")
}
