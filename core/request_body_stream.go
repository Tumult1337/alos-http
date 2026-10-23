//go:build linux && amd64

package core

import (
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/turbo"
)

const bodyStreamAckThreshold = 32 << 10

var ErrBodyStreamAborted = errors.New("core: request body stream aborted")

type BodyReader struct {
	mu        sync.Mutex
	ready     *sync.Cond
	buf       []byte
	off       int
	eof       bool
	err       error
	closed    bool
	unacked   int
	ackQueued bool
	onAck     func()
	received  int64
	trailers  [][2]string

	uploadConn   *ConnectionLimiter
	uploadGlobal *GlobalLimiter

	budget     *Server
	budgetConn *atomic.Int64
	held       int64
	readLimit  int64
	limited    bool

	deadlineAt    int64
	deadlineHit   bool
	deadlineTimer *turbo.Timer
}

func newBodyReader(onAck func()) *BodyReader {
	b := &BodyReader{onAck: onAck}
	b.ready = sync.NewCond(&b.mu)
	return b
}

func (b *BodyReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b.mu.Lock()
	for b.off == len(b.buf) && !b.eof && b.err == nil && !b.closed && !b.deadlineHit {
		b.ready.Wait()
	}
	if b.limited && b.received > b.readLimit {
		b.mu.Unlock()
		return 0, ErrBodyTooLarge
	}
	if b.off == len(b.buf) {
		err := b.err
		switch {
		case err != nil:
		case b.eof || b.closed:
			err = io.EOF
		default:
			err = os.ErrDeadlineExceeded
		}
		b.mu.Unlock()
		return 0, err
	}
	n := copy(p, b.buf[b.off:])
	b.off += n
	if b.off == len(b.buf) {
		b.buf, b.off = b.buf[:0], 0
	}
	b.unacked += n
	released := b.releaseHeldLocked(int64(n))
	notify := b.claimAckLocked()
	b.mu.Unlock()
	b.budget.releaseConnBodyBytes(b.budgetConn, released)
	if b.uploadConn != nil || b.uploadGlobal != nil {
		throttleUploadBytes(b.uploadConn, b.uploadGlobal, int64(n))
	}
	if notify {
		b.onAck()
	}
	return n, nil
}

func (b *BodyReader) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	dropped := len(b.buf) - b.off
	b.unacked += dropped
	b.buf, b.off = nil, 0
	released := b.releaseHeldLocked(int64(dropped))
	b.stopDeadlineLocked()
	notify := b.claimAckLocked()
	b.mu.Unlock()
	b.budget.releaseConnBodyBytes(b.budgetConn, released)
	if notify {
		b.onAck()
	}
	return nil
}

func (b *BodyReader) setReadDeadline(t time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deadlineHit = false
	if t.IsZero() {
		b.stopDeadlineLocked()
		return
	}
	b.deadlineAt = t.UnixNano()
	wait := turbo.Until(b.deadlineAt)
	if wait <= 0 {
		b.deadlineHit = true
		b.ready.Broadcast()
		return
	}
	if b.deadlineTimer == nil {
		b.deadlineTimer = turbo.AfterFunc(wait, b.deadlineFired)
		return
	}
	b.deadlineTimer.Reset(wait)
}

func (b *BodyReader) deadlineFired() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.deadlineAt == 0 {
		return
	}
	if wait := turbo.Until(b.deadlineAt); wait > 0 {
		b.deadlineTimer.Reset(wait)
		return
	}
	b.deadlineHit = true
	b.ready.Broadcast()
}

func (b *BodyReader) stopDeadlineLocked() {
	b.deadlineAt = 0
	if b.deadlineTimer != nil {
		b.deadlineTimer.Stop()
	}
}

func (b *BodyReader) claimAckLocked() bool {
	if b.ackQueued || b.unacked == 0 {
		return false
	}
	if b.unacked < bodyStreamAckThreshold && b.off < len(b.buf) && !b.closed {
		return false
	}
	b.ackQueued = true
	return true
}

func (b *BodyReader) limitReads(n int64) {
	b.mu.Lock()
	if !b.limited || n < b.readLimit {
		b.readLimit, b.limited = n, true
	}
	b.mu.Unlock()
}

func (b *BodyReader) readLimitExceeded() bool {
	b.mu.Lock()
	exceeded := b.limited && b.received > b.readLimit
	b.mu.Unlock()
	return exceeded
}

func (b *BodyReader) push(data []byte) {
	b.pushReserved(data, 0)
}

func (b *BodyReader) chargeBudget(srv *Server, conn *atomic.Int64) {
	b.budget, b.budgetConn = srv, conn
}

func (b *BodyReader) reservePush(data []byte) bool {
	if b.budget == nil {
		b.push(data)
		return true
	}
	if !b.budget.tryReserveConnBodyBytes(b.budgetConn, len(data)) {
		return false
	}
	if !b.pushReserved(data, int64(len(data))) {
		b.budget.releaseConnBodyBytes(b.budgetConn, int64(len(data)))
	}
	return true
}

func (b *BodyReader) pushReserved(data []byte, reserved int64) bool {
	b.mu.Lock()
	b.received += int64(len(data))
	if b.closed {
		b.unacked += len(data)
		b.mu.Unlock()
		return false
	}
	if b.off > 0 && b.off >= len(b.buf)/2 {
		b.buf = b.buf[:copy(b.buf, b.buf[b.off:])]
		b.off = 0
	}
	b.buf = append(b.buf, data...)
	b.held += reserved
	b.ready.Broadcast()
	b.mu.Unlock()
	return true
}

func (b *BodyReader) releaseHeldLocked(n int64) int64 {
	n = min(n, b.held)
	b.held -= n
	return n
}

func (b *BodyReader) abort(err error) {
	b.mu.Lock()
	if !b.eof && b.err == nil {
		b.err = err
	}
	b.buf, b.off = nil, 0
	b.closed = true
	released := b.releaseHeldLocked(b.held)
	b.ready.Broadcast()
	b.mu.Unlock()
	b.budget.releaseConnBodyBytes(b.budgetConn, released)
}

func (b *BodyReader) finish(err error) {
	b.mu.Lock()
	if !b.eof && b.err == nil {
		if err != nil {
			b.err = err
		} else {
			b.eof = true
		}
	}
	b.ready.Broadcast()
	b.mu.Unlock()
}

func (b *BodyReader) finishWithTrailers(trailers [][2]string) {
	b.mu.Lock()
	if !b.eof && b.err == nil {
		b.trailers = trailers
		b.eof = true
	}
	b.ready.Broadcast()
	b.mu.Unlock()
}

func (b *BodyReader) Trailers() [][2]string {
	b.mu.Lock()
	trailers := b.trailers
	b.mu.Unlock()
	return trailers
}

func (b *BodyReader) takeAck() int {
	b.mu.Lock()
	n := b.unacked
	b.unacked = 0
	b.ackQueued = false
	b.mu.Unlock()
	return n
}

func (b *BodyReader) buffered() int {
	b.mu.Lock()
	n := len(b.buf) - b.off
	b.mu.Unlock()
	return n
}

func (b *BodyReader) receivedBytes() int64 {
	b.mu.Lock()
	n := b.received
	b.mu.Unlock()
	return n
}

func (s *Server) builtInProxyActive() bool {
	return s.proxy.Load() != nil || s.httpRouter.Load() != nil
}

func (r *Request) BodyStream() *BodyReader {
	return r.bodyStream
}
