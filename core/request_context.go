//go:build linux && amd64

package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrClientGone     = errors.New("core: client went away")
	ErrServerShutdown = errors.New("core: server is shutting down")
	errRequestDone    = errors.New("core: request finished")
)

var closedDoneChan = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

type reqCancel struct {
	mu    sync.Mutex
	done  chan struct{}
	err   error
	cause error
}

func (c *reqCancel) Deadline() (time.Time, bool) { return time.Time{}, false }

func (c *reqCancel) Value(any) any { return nil }

func (c *reqCancel) Done() <-chan struct{} {
	c.mu.Lock()
	if c.done == nil {
		if c.err != nil {
			c.done = closedDoneChan
		} else {
			c.done = make(chan struct{})
		}
	}
	done := c.done
	c.mu.Unlock()
	return done
}

func (c *reqCancel) Err() error {
	c.mu.Lock()
	err := c.err
	c.mu.Unlock()
	return err
}

func (c *reqCancel) cancel(cause error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = context.Canceled
		c.cause = cause
		if c.done != nil && c.done != closedDoneChan {
			close(c.done)
		}
	}
	c.mu.Unlock()
}

func (c *reqCancel) causeErr() error {
	c.mu.Lock()
	cause := c.cause
	c.mu.Unlock()
	return cause
}

type cancelSlot struct {
	p atomic.Pointer[reqCancel]
}

func (s *cancelSlot) state() *reqCancel {
	if c := s.p.Load(); c != nil {
		return c
	}
	fresh := &reqCancel{}
	if s.p.CompareAndSwap(nil, fresh) {
		return fresh
	}
	return s.p.Load()
}

func (s *cancelSlot) cancel(cause error) {
	s.state().cancel(cause)
}

func (s *cancelSlot) finish() {
	if s.p.Load() == nil {
		return
	}
	if c := s.p.Swap(nil); c != nil {
		c.cancel(errRequestDone)
	}
}

func (s *cancelSlot) cause() error {
	if c := s.p.Load(); c != nil {
		return c.causeErr()
	}
	return nil
}

func (s *cancelSlot) attach(r *Request) {
	r.cancelSrc = s
}

func (r *Request) cancelSlot() *cancelSlot {
	if r.cancelSrc == nil {
		r.cancelSrc = &cancelSlot{}
	}
	return r.cancelSrc
}

func (r *Request) cancelRequest(cause error) {
	r.cancelSlot().cancel(cause)
}

func (r *Request) finishContext() {
	if s := r.cancelSrc; s != nil {
		s.finish()
		r.cancelSrc = nil
	}
}

func (r *Request) CancelCause() error {
	if s := r.cancelSrc; s != nil {
		return s.cause()
	}
	return nil
}
