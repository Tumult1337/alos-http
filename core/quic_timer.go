//go:build linux && amd64

package core

import (
	"sync"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicTimerTick      = 2 * time.Millisecond
	quicIdleCheckEvery = int64(time.Second)
)

type quicTimerHub struct {
	mu        sync.Mutex
	conns     map[*QUICConn]struct{}
	snapshot  []*QUICConn
	started   bool
	stopped   chan struct{}
	goingAway bool
}

func (h *quicTimerHub) add(qc *QUICConn, done <-chan struct{}) {
	h.mu.Lock()
	if h.conns == nil {
		h.conns = make(map[*QUICConn]struct{}, 256)
	}
	h.conns[qc] = struct{}{}
	late := h.goingAway
	start := !h.started
	if start {
		h.started = true
		h.stopped = make(chan struct{})
	}
	h.mu.Unlock()
	if late {
		qc.signalGoAway()
	}
	if start {
		go h.run(done)
	}
}

func (h *quicTimerHub) goAwayAll() {
	h.mu.Lock()
	h.goingAway = true
	conns := make([]*QUICConn, 0, len(h.conns))
	for qc := range h.conns {
		conns = append(conns, qc)
	}
	h.mu.Unlock()
	for _, qc := range conns {
		qc.signalGoAway()
	}
}

func (h *quicTimerHub) remove(qc *QUICConn) {
	h.mu.Lock()
	delete(h.conns, qc)
	h.mu.Unlock()
}

func (h *quicTimerHub) awaitStopped() {
	h.mu.Lock()
	stopped := h.stopped
	h.mu.Unlock()
	if stopped != nil {
		<-stopped
	}
}

func (h *quicTimerHub) closeAll(cause error) {
	h.mu.Lock()
	conns := make([]*QUICConn, 0, len(h.conns))
	for qc := range h.conns {
		conns = append(conns, qc)
	}
	h.mu.Unlock()
	for _, qc := range conns {
		qc.closeForShutdown(cause)
	}
}

func (h *quicTimerHub) stopIfIdleLocked() bool {
	if len(h.conns) > 0 {
		return false
	}
	close(h.stopped)
	return true
}

func (h *quicTimerHub) run(done <-chan struct{}) {
	ticker := time.NewTicker(quicTimerTick)
	defer ticker.Stop()
	var lastIdleCheck int64
	for {
		select {
		case <-done:
			done = nil
		case <-ticker.C:
		}
		now := turbo.UnixNano()
		checkIdle := now-lastIdleCheck >= quicIdleCheckEvery
		if checkIdle {
			lastIdleCheck = now
		}
		h.mu.Lock()
		if done == nil && h.stopIfIdleLocked() {
			h.mu.Unlock()
			return
		}
		h.snapshot = h.snapshot[:0]
		for qc := range h.conns {
			h.snapshot = append(h.snapshot, qc)
		}
		h.mu.Unlock()
		for _, qc := range h.snapshot {
			qc.tick(now, checkIdle)
		}
	}
}

func (qc *QUICConn) tick(now int64, checkIdle bool) {
	defer func() {
		if r := recover(); r != nil {
			qc.server.reportPanic(nil, r)
		}
	}()
	if checkIdle && (qc.idleTimeout > 0 && time.Duration(now-qc.lastActive.Load()) > qc.idleTimeout || qc.handshakeExpired(now)) {
		qc.close()
		return
	}
	if checkIdle && qc.sendStalledTooLong(now) {
		qc.resetStalledStreams(now)
	}
	if qc.probing.Load() {
		qc.checkPathProbe()
	}
	if qc.draining.Load() && qc.drained() {
		qc.closeWithAppError(h3ErrNoError, "")
		return
	}
	if !qc.timerWork.Swap(false) {
		return
	}
	qc.flushPendingAck(quicSpaceAppData)
	for _, frames := range qc.loss.ptoExpiredFrames(quicSpaceAppData) {
		qc.sendFrames(quicSpaceAppData, frames, true)
	}
	qc.writeMu.Lock()
	if len(qc.coalesceEnds) > 0 {
		qc.drainCoalescedLocked()
	}
	qc.writeMu.Unlock()
	qc.resumeCongestionBlocked()
	qc.admitWaiting()
	qc.writeMu.Lock()
	pending := len(qc.pendingAck[quicSpaceAppData]) > 0 || len(qc.coalesceEnds) > 0
	qc.writeMu.Unlock()
	if pending || qc.loss.hasSentPackets(quicSpaceAppData) {
		qc.timerWork.Store(true)
	}
}
