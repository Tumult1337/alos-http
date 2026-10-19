//go:build linux && amd64

package core

import (
	"errors"
	"io"
)

const (
	upstreamBodyChunk   = 64 << 10
	upstreamBodyLowMark = 256 << 10
)

var errFPBodySource = errors.New("outbound: request body could not be sent")

type upstreamBody struct {
	src    io.Reader
	length int64
	want   chan struct{}
	buf    []byte

	chunk []byte
	eof   bool
	err   error

	requested bool
	waiting   bool
	sent      int64
	done      bool
}

func newUpstreamBody(req *fpRequest) *upstreamBody {
	return &upstreamBody{
		src:    req.BodySource,
		length: req.BodyLength,
		want:   make(chan struct{}, 1),
		buf:    make([]byte, upstreamBodyChunk),
	}
}

func (b *upstreamBody) chunked() bool { return b.length <= 0 }

func (b *upstreamBody) pump(l *eventLoop, ex *Exchange) {
	for {
		select {
		case <-b.want:
		case <-ex.done:
			return
		}
		n, err := io.ReadAtLeast(b.src, b.buf, 1)
		b.chunk, b.eof, b.err = b.buf[:n], err == io.EOF, nil
		if err != nil && err != io.EOF {
			b.err = err
		}
		select {
		case <-ex.done:
			return
		default:
		}
		ex.bodyReady.Store(true)
		l.notify(ex)
		if b.eof || b.err != nil {
			return
		}
	}
}

func (l *beLoop) requestBody(c *backendConn, ex *Exchange) {
	b := ex.body
	if b.requested || b.waiting {
		return
	}
	if c.wbuf.length() > upstreamBodyLowMark {
		b.waiting = true
		c.uploadsWaiting++
		return
	}
	b.requested = true
	b.want <- struct{}{}
}

func (c *backendConn) forgetUpload(ex *Exchange) {
	if b := ex.body; b != nil && b.waiting {
		b.waiting = false
		c.uploadsWaiting--
	}
}

func (l *beLoop) wakeWaitingUploads(c *backendConn) {
	if c.uploadsWaiting == 0 || c.wbuf.length() > upstreamBodyLowMark {
		return
	}
	if c.h2 != nil {
		for _, st := range c.h2.streams {
			l.wakeUpload(c, st.ex)
		}
		return
	}
	if c.cur != nil {
		l.wakeUpload(c, c.cur)
	}
}

func (l *beLoop) wakeUpload(c *backendConn, ex *Exchange) {
	if b := ex.body; b != nil && b.waiting {
		c.forgetUpload(ex)
		l.requestBody(c, ex)
	}
}

func (l *beLoop) touchBodyDeadline(ex *Exchange) {
	timeout := ex.readTimeoutNano
	if timeout <= 0 {
		timeout = l.cfg.RequestTimeout.Nanoseconds()
	}
	ex.deadline = l.nowNano() + timeout
}

func (l *beLoop) onBodyChunk(ex *Exchange) {
	ex.body.requested = false
	c := ex.bc
	if ex.finished || c == nil || c.state == connClosed {
		return
	}
	l.touchBodyDeadline(ex)
	if c.h2 != nil {
		l.h2proto.sendBodyChunk(c, ex)
		return
	}
	l.h1SendBodyChunk(c, ex)
}

func (b *upstreamBody) acceptChunk() bool {
	if b.err != nil {
		return false
	}
	b.sent += int64(len(b.chunk))
	return b.chunked() || (b.sent <= b.length && (!b.eof || b.sent == b.length))
}

func (l *beLoop) h1SendBodyChunk(c *backendConn, ex *Exchange) {
	b := ex.body
	if !b.acceptChunk() {
		l.closeConn(c, errFPBodySource)
		return
	}
	out := b.chunk
	if b.chunked() {
		l.serBuf = l.serBuf[:0]
		if len(b.chunk) > 0 {
			l.serBuf = appendH1Chunk(l.serBuf, b.chunk)
		}
		if b.eof {
			l.serBuf = append(l.serBuf, h1LastChunk...)
		}
		out = l.serBuf
	}
	if len(out) > 0 {
		if err := c.transport.wrapOut(c, out); err != nil {
			l.closeConn(c, err)
			return
		}
	}
	b.done = b.eof
	l.flushWrites(c)
	if !b.done && c.state != connClosed {
		l.requestBody(c, ex)
	}
}

func (b *upstreamBody) incomplete() bool { return b != nil && !b.done }
