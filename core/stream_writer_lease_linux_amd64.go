//go:build linux && amd64

package core

import "os"

type streamWriterLease struct {
	gen      uint64
	calls    int
	released bool
}

func (l *streamWriterLease) acquire() uint64 {
	l.released = false
	return l.gen
}

func (l *streamWriterLease) enterLocked(gen uint64) bool {
	if l.released || l.gen != gen {
		return false
	}
	l.calls++
	return true
}

func (l *streamWriterLease) leaveLocked() (idle bool) {
	l.calls--
	return l.released && l.calls == 0
}

func (l *streamWriterLease) releaseLocked() (idle bool) {
	l.released = true
	l.gen++
	return l.calls == 0
}

type h1StreamHandle struct {
	sw  *epollH1StreamWriter
	gen uint64
}

func (h *h1StreamHandle) enter() bool {
	h.sw.mu.Lock()
	ok := h.sw.lease.enterLocked(h.gen)
	h.sw.mu.Unlock()
	return ok
}

func (h *h1StreamHandle) leave() {
	sw := h.sw
	sw.mu.Lock()
	recycle := sw.lease.leaveLocked() && !sw.pumpQueued
	sw.mu.Unlock()
	if recycle {
		sw.recycle()
	}
}

func (h *h1StreamHandle) WriteHeader(statusCode int, headers [][2]string, contentType string) error {
	if !h.enter() {
		return ErrStreamClosed
	}
	defer h.leave()
	return h.sw.WriteHeader(statusCode, headers, contentType)
}

func (h *h1StreamHandle) WriteChunk(data []byte) error {
	if !h.enter() {
		return ErrStreamClosed
	}
	defer h.leave()
	return h.sw.WriteChunk(data)
}

func (h *h1StreamHandle) Flush() error {
	if !h.enter() {
		return ErrStreamClosed
	}
	defer h.leave()
	return h.sw.Flush()
}

func (h *h1StreamHandle) Close() error {
	if !h.enter() {
		return ErrStreamClosed
	}
	defer h.leave()
	return h.sw.Close()
}

func (h *h1StreamHandle) sendFileRange(file *os.File, start, length int64, limiter *TokenBucket) (bool, error) {
	if !h.enter() {
		return true, ErrStreamClosed
	}
	defer h.leave()
	return h.sw.sendFileRange(file, start, length, limiter)
}

func h1StreamWriterOf(sw StreamWriter) *epollH1StreamWriter {
	if h, ok := sw.(*h1StreamHandle); ok {
		return h.sw
	}
	return nil
}

type h2StreamHandle struct {
	sw  *epollH2StreamWriter
	gen uint64
}

func (h *h2StreamHandle) enter() bool {
	h.sw.mu.Lock()
	ok := h.sw.lease.enterLocked(h.gen)
	h.sw.mu.Unlock()
	return ok
}

func (h *h2StreamHandle) leave() {
	sw := h.sw
	sw.mu.Lock()
	recycle := sw.lease.leaveLocked() && !sw.pumpQueued
	sw.mu.Unlock()
	if recycle {
		sw.recycle()
	}
}

func (h *h2StreamHandle) WriteHeader(statusCode int, headers [][2]string, contentType string) error {
	if !h.enter() {
		return ErrStreamClosed
	}
	defer h.leave()
	return h.sw.WriteHeader(statusCode, headers, contentType)
}

func (h *h2StreamHandle) WriteChunk(data []byte) error {
	if !h.enter() {
		return ErrStreamClosed
	}
	defer h.leave()
	return h.sw.WriteChunk(data)
}

func (h *h2StreamHandle) Flush() error {
	if !h.enter() {
		return ErrStreamClosed
	}
	defer h.leave()
	return h.sw.Flush()
}

func (h *h2StreamHandle) Close() error {
	if !h.enter() {
		return ErrStreamClosed
	}
	defer h.leave()
	return h.sw.Close()
}

func (h *h2StreamHandle) sendFileRange(file *os.File, start, length int64, limiter *TokenBucket) (bool, error) {
	if !h.enter() {
		return true, ErrStreamClosed
	}
	defer h.leave()
	return h.sw.sendFileRange(file, start, length, limiter)
}

func h2StreamWriterOf(sw StreamWriter) *epollH2StreamWriter {
	if h, ok := sw.(*h2StreamHandle); ok {
		return h.sw
	}
	return nil
}
