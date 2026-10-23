//go:build linux && amd64

package core

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const g2LargeBuffer = 4 << 20

func TestProxyExchangePoolDropsLargeRequestBuffer(t *testing.T) {
	w := &epollWorker{}
	px := w.pxGet()
	px.reqRaw = make([]byte, 100, g2LargeBuffer)
	w.pxPut(px)
	again := w.pxGet()
	if again != px {
		t.Fatalf("the pool did not return the released exchange")
	}
	if cap(again.reqRaw) >= g2LargeBuffer {
		t.Fatalf("pooled exchange kept a %d-byte request buffer", cap(again.reqRaw))
	}
	again.reqRaw = make([]byte, 100, 1024)
	w.pxPut(again)
	if kept := w.pxGet(); cap(kept.reqRaw) != 1024 {
		t.Fatalf("a small request buffer was not reused: cap %d", cap(kept.reqRaw))
	}
}

func TestUpstreamH1ParserDropsLargeBodyBuffer(t *testing.T) {
	var p h1Parser
	p.body = make([]byte, 100, g2LargeBuffer)
	p.reset()
	if cap(p.body) >= g2LargeBuffer {
		t.Fatalf("parser kept a %d-byte body buffer across responses", cap(p.body))
	}
	p.body = make([]byte, 100, 1024)
	p.reset()
	if cap(p.body) != 1024 || len(p.body) != 0 {
		t.Fatalf("a small body buffer was not reused: len %d cap %d", len(p.body), cap(p.body))
	}
}

func TestUpstreamIdleConnDropsLargeIOBuffers(t *testing.T) {
	ep, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatalf("epoll_create: %v", err)
	}
	defer unix.Close(ep)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	l := &beLoop{}
	l.init(ep, &fpConfig{MaxIdlePerBackend: 4, IdleTimeout: time.Second, MaxResponseBody: 1 << 20}, nil)
	c := &backendConn{fd: fds[0], be: l, state: connReady, transport: &plainTransport{}, proto: &l.h1proto}
	l.ensureFD(c.fd)
	l.conns[c.fd] = c
	l.liveConns++
	c.wbuf.b = make([]byte, 0, g2LargeBuffer)
	c.rbuf.b = make([]byte, 0, g2LargeBuffer)
	l.idlePut(c)
	if !c.inIdle {
		t.Fatalf("connection did not go idle")
	}
	if cap(c.wbuf.b) >= g2LargeBuffer || cap(c.rbuf.b) >= g2LargeBuffer {
		t.Fatalf("idle connection kept write cap %d and read cap %d", cap(c.wbuf.b), cap(c.rbuf.b))
	}
}

func TestByteBufferReleaseKeepsUnreadBytes(t *testing.T) {
	var bb byteBuffer
	bb.b = make([]byte, 0, g2LargeBuffer)
	bb.write([]byte("pending"))
	bb.releaseLarge()
	if string(bb.unread()) != "pending" {
		t.Fatalf("release dropped unread bytes: %q", bb.unread())
	}
	bb.consume(len("pending"))
	bb.releaseLarge()
	if cap(bb.b) >= g2LargeBuffer {
		t.Fatalf("an empty buffer kept cap %d", cap(bb.b))
	}
	small := byteBuffer{b: make([]byte, 0, 1024)}
	small.releaseLarge()
	if cap(small.b) != 1024 {
		t.Fatalf("a small buffer was dropped: cap %d", cap(small.b))
	}
}
