//go:build linux && amd64

package core

import (
	"io"
	"sync"
)

const (
	respPipeHighMark = 1 << 20
	respPipeLowMark  = 256 << 10
)

type respPipe struct {
	mu      sync.Mutex
	ready   *sync.Cond
	head    bool
	status  int
	headers [][2]string
	buf     []byte
	off     int
	done    bool
	err     error
	closed  bool
	paused  bool
}

func newRespPipe() *respPipe {
	p := &respPipe{}
	p.ready = sync.NewCond(&p.mu)
	return p
}

func (p *respPipe) setHead(status int, headers [][2]string) {
	p.mu.Lock()
	if !p.head {
		p.head = true
		p.status = status
		p.headers = append([][2]string(nil), headers...)
		p.ready.Broadcast()
	}
	p.mu.Unlock()
}

func (p *respPipe) push(data []byte) (full bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	if p.off > 0 && p.off >= len(p.buf)/2 {
		p.buf = p.buf[:copy(p.buf, p.buf[p.off:])]
		p.off = 0
	}
	p.buf = append(p.buf, data...)
	p.ready.Broadcast()
	if len(p.buf)-p.off >= respPipeHighMark {
		p.paused = true
		return true
	}
	return false
}

func (p *respPipe) finish(err error) {
	p.mu.Lock()
	if !p.done {
		p.done = true
		p.err = err
		p.ready.Broadcast()
	}
	p.mu.Unlock()
}

func (p *respPipe) waitHead() (int, [][2]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for !p.head && !p.done {
		p.ready.Wait()
	}
	if !p.head {
		if p.err != nil {
			return 0, nil, p.err
		}
		return 0, nil, errFPBadResponse
	}
	return p.status, p.headers, nil
}

func (p *respPipe) read(dst []byte) (n int, resume bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.off == len(p.buf) && !p.done && !p.closed {
		p.ready.Wait()
	}
	if p.off == len(p.buf) {
		if p.err != nil {
			return 0, false, p.err
		}
		return 0, false, io.EOF
	}
	n = copy(dst, p.buf[p.off:])
	p.off += n
	if p.off == len(p.buf) {
		p.buf, p.off = p.buf[:0], 0
	}
	if p.paused && len(p.buf)-p.off <= respPipeLowMark {
		p.paused = false
		resume = true
	}
	return n, resume, nil
}

func (p *respPipe) close() (abort bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.closed = true
	p.buf, p.off = nil, 0
	p.ready.Broadcast()
	return !p.done
}

type UpstreamBody struct {
	pipe *respPipe
	ex   *Exchange
	loop *eventLoop
}

func (b *UpstreamBody) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	n, resume, err := b.pipe.read(dst)
	if resume {
		b.ex.resumeWanted.Store(true)
		b.loop.notify(b.ex)
	}
	return n, err
}

func (b *UpstreamBody) Close() error {
	if b.pipe.close() {
		b.ex.abortWanted.Store(true)
		b.loop.notify(b.ex)
	}
	return nil
}

func (c *fpClient) Open(req *UpstreamRequest) (*UpstreamResponse, *UpstreamBody, error) {
	pipe := newRespPipe()
	ex, l, err := c.start(req, nil, pipe)
	if err != nil {
		return nil, nil, err
	}
	status, headers, err := pipe.waitHead()
	if err != nil {
		return nil, nil, err
	}
	return &UpstreamResponse{Status: status, Headers: headers}, &UpstreamBody{pipe: pipe, ex: ex, loop: l}, nil
}

func (l *eventLoop) resumeExchangeRead(ex *Exchange) {
	if c := ex.bc; c != nil && c.cur == ex {
		l.resumeBackendRead(c)
	}
}

func (l *eventLoop) abortExchange(ex *Exchange) {
	if ex.finished {
		return
	}
	if c := ex.bc; c != nil && c.state != connClosed {
		if c.h2 != nil {
			if st := ex.h2st; st != nil && !st.ended {
				l.h2proto.resetStream(c, st, H2ErrCancel, errFPClientClosed)
			}
			return
		}
		l.closeConn(c, errFPClientClosed)
		return
	}
	l.finish(ex, errFPClientClosed)
}

func (p *respPipe) deliverBuffered(resp *fpResponse, err error) {
	if err == nil {
		p.setHead(resp.Status, resp.Headers)
		if len(resp.Body) > 0 {
			p.push(resp.Body)
		}
	}
	p.finish(err)
}
