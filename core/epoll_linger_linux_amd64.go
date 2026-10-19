//go:build linux && amd64

package core

import (
	"time"

	"golang.org/x/sys/unix"
)

const (
	epollLingerTimeout         = time.Second
	epollShutdownLingerTimeout = 200 * time.Millisecond
	epollDrainPollMs           = 25
	epollLingerMaxBytes        = 16 << 20
	epollDiscardBufSize        = 64 << 10
)

func (c *epollConn) speaksH1() bool {
	return c.protocol == plainConnProtoH1 || (c.tls && c.phase == tlsConnPhaseApplication)
}

func (w *epollWorker) closeAfterResponse(c *epollConn) {
	if c.lingering {
		return
	}
	quiescent := c.inFlight == 0 && !c.dispatching && c.proxyEx == nil && c.tunnelBE == nil
	if quiescent && !c.sendCloseNotify() {
		c.closeAfter = true
		w.armOut(c)
		return
	}
	lingerable := (c.speaksH1() || c.speaksH2() || c.tlsAlertSent) && quiescent &&
		(w.readTO != 0 || w.writeTO != 0 || w.idleTO != 0 || w.draining)
	if !lingerable || unix.Shutdown(c.fd, unix.SHUT_WR) != nil {
		w.closeConn(c)
		return
	}
	c.lingering = true
	c.lingerLeft = epollLingerMaxBytes
	c.deadline = deadlineFrom(int64(w.lingerTimeout()))
	w.discardLingering(c)
}

func (w *epollWorker) lingerTimeout() time.Duration {
	if w.server.shuttingDown.Load() {
		return epollShutdownLingerTimeout
	}
	return epollLingerTimeout
}

func (w *epollWorker) discardLingering(c *epollConn) {
	if w.discardBuf == nil {
		w.discardBuf = make([]byte, epollDiscardBufSize)
	}
	for {
		n, err := socketRecv(c.fd, w.discardBuf)
		if n > 0 {
			w.bytesIn += uint64(n)
			c.lingerLeft -= n
			if c.lingerLeft <= 0 {
				w.closeConn(c)
				return
			}
			continue
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN {
			return
		}
		w.closeConn(c)
		return
	}
}
