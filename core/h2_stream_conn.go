//go:build linux && amd64

package core

import (
	"net"
	"sync"
	"time"
)

type h2StreamConn struct {
	body   *BodyReader
	sw     StreamWriter
	remote streamAddr
	mu     sync.Mutex
	closed bool
	done   chan struct{}
	ipSlot *ipReqCounter
}

type streamAddr string

func (a streamAddr) Network() string { return "tcp" }
func (a streamAddr) String() string  { return string(a) }

func newH2StreamConn(body *BodyReader, sw StreamWriter, remoteAddr string) *h2StreamConn {
	return &h2StreamConn{body: body, sw: sw, remote: streamAddr(remoteAddr), done: make(chan struct{})}
}

func (c *h2StreamConn) Read(p []byte) (int, error) { return c.body.Read(p) }

func (c *h2StreamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if err := c.sw.WriteChunk(p); err != nil {
		return 0, err
	}
	if err := c.sw.Flush(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *h2StreamConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		_ = c.sw.Close()
		close(c.done)
	}
	c.mu.Unlock()
	return c.body.Close()
}

func (c *h2StreamConn) detach() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

func (c *h2StreamConn) LocalAddr() net.Addr  { return streamAddr("") }
func (c *h2StreamConn) RemoteAddr() net.Addr { return c.remote }

func (c *h2StreamConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *h2StreamConn) SetReadDeadline(t time.Time) error {
	c.body.setReadDeadline(t)
	return nil
}

func (c *h2StreamConn) SetWriteDeadline(time.Time) error { return nil }

func (r *Request) awaitH2Tunnel() {
	if r.h2Tunnel != nil {
		r.waitH2Tunnel()
	}
}

func (r *Request) waitH2Tunnel() {
	t := r.h2Tunnel
	select {
	case <-t.done:
	case <-r.Context().Done():
	}
	t.detach()
	if t.ipSlot != nil {
		t.ipSlot.release()
		t.ipSlot = nil
	}
}
