//go:build linux && amd64

package core

import (
	"bytes"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

type pendingOutputConn struct {
	net.Conn
	raw  syscall.RawConn
	mu   sync.Mutex
	out  []byte
	sent atomic.Bool
}

func newHandoffConn(nc net.Conn, unread, pending []byte) net.Conn {
	handed := nc
	if len(unread) > 0 {
		handed = &prefixConn{Conn: nc, reader: io.MultiReader(bytes.NewReader(unread), nc)}
	}
	if len(pending) == 0 {
		return handed
	}
	return &pendingOutputConn{Conn: handed, raw: rawConnOf(nc), out: pending}
}

func rawConnOf(nc net.Conn) syscall.RawConn {
	sc, ok := nc.(syscall.Conn)
	if !ok {
		return nil
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	return raw
}

func (c *pendingOutputConn) sendPending() error {
	if c.sent.Load() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.out) > 0 {
		n, err := c.Conn.Write(c.out)
		c.out = c.out[n:]
		if err != nil {
			return err
		}
	}
	c.out = nil
	c.sent.Store(true)
	return nil
}

func (c *pendingOutputConn) Read(b []byte) (int, error) {
	if err := c.sendPending(); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *pendingOutputConn) Write(b []byte) (int, error) {
	if err := c.sendPending(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *pendingOutputConn) Close() error {
	c.sendPendingWithoutBlocking()
	return c.Conn.Close()
}

func (c *pendingOutputConn) sendPendingWithoutBlocking() {
	if c.sent.Load() || c.raw == nil || !c.mu.TryLock() {
		return
	}
	defer c.mu.Unlock()
	if c.sent.Load() {
		return
	}
	_ = c.raw.Write(func(fd uintptr) bool {
		sendUntilFull(int(fd), c.out)
		return true
	})
	c.out = nil
	c.sent.Store(true)
}

func sendUntilFull(fd int, b []byte) {
	for len(b) > 0 {
		n, err := socketSend(fd, b)
		if n > 0 {
			b = b[n:]
			continue
		}
		if err != unix.EINTR {
			return
		}
	}
}

func epollDetachToConn(fd int) (net.Conn, error) {
	f := os.NewFile(uintptr(fd), "epoll-conn")
	if f == nil {
		return nil, os.ErrInvalid
	}
	nc, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	return nc, nil
}

func (w *epollWorker) detachConnFd(c *epollConn) (net.Conn, bool) {
	if c.fd < 0 {
		return nil, false
	}
	fd := c.fd
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, fd, nil)
	if fd < len(w.conns) {
		w.conns[fd] = nil
	}
	nc, err := epollDetachToConn(fd)
	c.fd = -1
	if err != nil {
		return nil, false
	}
	return nc, true
}

func (w *epollWorker) cachedH1Attacher(c *epollConn, gen uint32) func(*Request) net.Conn {
	if c.h1AttacherFn == nil || c.h1AttacherGen != gen || c.h1AttacherInline {
		c.h1AttacherFn = w.h1Attacher(c, gen)
		c.h1AttacherGen = gen
		c.h1AttacherInline = false
	}
	return c.h1AttacherFn
}

func (w *epollWorker) cachedInlineH1Attacher(c *epollConn) func(*Request) net.Conn {
	if c.h1AttacherFn == nil || !c.h1AttacherInline {
		c.h1AttacherFn = w.inlineH1Attacher(c)
		c.h1AttacherInline = true
	}
	return c.h1AttacherFn
}

func (w *epollWorker) h1Attacher(c *epollConn, gen uint32) func(*Request) net.Conn {
	return func(req *Request) net.Conn {
		if req.connTakenOver {
			return req.conn
		}
		done := make(chan struct{})
		w.postTask(func(w *epollWorker) {
			defer close(done)
			if c.fd < 0 || c.generation != gen {
				return
			}
			w.handoffH1Conn(c, req)
		})
		<-done
		return req.conn
	}
}

func (w *epollWorker) inlineH1Attacher(c *epollConn) func(*Request) net.Conn {
	return func(req *Request) net.Conn {
		if req.connTakenOver {
			return req.conn
		}
		if c.fd >= 0 {
			w.handoffH1Conn(c, req)
		}
		return req.conn
	}
}

func (w *epollWorker) handoffH1Conn(c *epollConn, req *Request) {
	var rawPrefix, decryptedPrefix, pendingOut []byte
	if c.writeSent < len(c.writeBuf) {
		pendingOut = append([]byte(nil), c.writeBuf[c.writeSent:]...)
	}
	if c.tls {
		rawPrefix = append([]byte(nil), c.readBuf[:c.readN]...)
		if c.appBufOff < len(c.appBuf) {
			decryptedPrefix = append([]byte(nil), c.appBuf[c.appBufOff:]...)
		}
	} else {
		rawPrefix = append([]byte(nil), c.readBuf[c.h1Off:c.readN]...)
	}
	reader := c.appReader
	writer := c.appWriter
	tls12 := c.tls12
	nc, ok := w.detachConnFd(c)
	if !ok {
		return
	}
	handed := newHandoffConn(nc, rawPrefix, pendingOut)
	switch {
	case tls12 != nil:
		handed = newTLS12RecordConn(handed, tls12.reader, tls12.writer, decryptedPrefix)
	case c.tls:
		req.tlsReader = reader
		req.tlsWriter = writer
		req.hdrBuf = make([]byte, 5)
		req.hijackReadBuf = decryptedPrefix
	}
	ipKey, fromInFlight := w.handoffIPSlot(c, req)
	tracked := w.server.trackHandoffConn(handed, ipKey, fromInFlight, func() { w.pushTakeoverUnpin(c) })
	if tracked == nil {
		_ = nc.Close()
		return
	}
	c.ipHeld = false
	c.ipKey = ""
	c.takeoverPinned = true
	req.connTakenOver = true
	req.attachConn = nil
	req.conn = tracked
}

func (w *epollWorker) putTakenOver(c *epollConn) {
	if !c.takeoverPinned {
		w.pool.put(c)
		return
	}
	w.pool.releaseConnSlot()
	w.pool.parked++
	c.takeoverParked = true
}

func (c *epollConn) unpinTakenOver(w *epollWorker) {
	c.takeoverPinned = false
	if c.takeoverParked {
		c.takeoverParked = false
		w.pool.parked--
		w.pool.recycle(c)
	}
}

func (w *epollWorker) pushTakeoverUnpin(c *epollConn) {
	for {
		head := w.takeoverUnpins.Load()
		c.unpinNext = head
		if w.takeoverUnpins.CompareAndSwap(head, c) {
			break
		}
	}
	w.taskPending.Store(true)
	if w.parked.Load() {
		w.wakeForShutdown()
	}
}

func (w *epollWorker) runTakeoverUnpins() {
	for c := w.takeoverUnpins.Swap(nil); c != nil; {
		next := c.unpinNext
		c.unpinNext = nil
		w.runTask(c.unpinTakenOver)
		c = next
	}
}

func (w *epollWorker) handoffIPSlot(c *epollConn, req *Request) (string, bool) {
	if w.server.trustedProxies.active {
		if w.server.perIPLimiter == nil {
			return "", false
		}
		return extractIP(req.RemoteAddr), true
	}
	return c.ipKey, false
}
