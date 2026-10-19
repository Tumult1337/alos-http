//go:build linux && amd64

package core

func (qc *QUICConn) signalGoAway() {
	signal := quicInboundPkt{goAway: true}
	select {
	case qc.inbound <- signal:
	default:
		go func() {
			select {
			case qc.inbound <- signal:
			case <-qc.done:
			}
		}()
	}
}

func (qc *QUICConn) beginGoAway() {
	if qc.closed.Load() {
		return
	}
	if qc.h3 == nil {
		qc.closeWithError(quicErrNoError, "server shutting down")
		return
	}
	qc.streamsMu.Lock()
	id := qc.nextBidiRemote
	qc.goAwayID = id
	qc.draining.Store(true)
	qc.streamsMu.Unlock()
	qc.h3.sendGoAway(id)
}

func (qc *QUICConn) rejectedByGoAwayLocked(id uint64) bool {
	return qc.draining.Load() && quicStreamIsBidi(id) && id >= qc.goAwayID
}

func (qc *QUICConn) refuseStream(id uint64) {
	qc.writeMu.Lock()
	qc.frameScratch = quicAppendResetStreamFrame(qc.frameScratch[:0], id, h3ErrRequestRejected, 0)
	qc.frameScratch = quicAppendStopSendingFrame(qc.frameScratch, id, h3ErrRequestRejected)
	qc.queueControlFrameLocked(qc.frameScratch)
	qc.writeMu.Unlock()
}

func (qc *QUICConn) drained() bool {
	if qc.activeReqStreams.Load() > 0 {
		return false
	}
	qc.streamsMu.Lock()
	for id := range qc.streams {
		if quicStreamIsBidi(id) {
			qc.streamsMu.Unlock()
			return false
		}
	}
	qc.streamsMu.Unlock()
	return !qc.loss.hasSentPackets(quicSpaceAppData)
}

func (qc *QUICConn) closeForShutdown(cause error) {
	qc.streamsMu.Lock()
	for _, s := range qc.streams {
		s.abortHandler(cause)
	}
	qc.streamsMu.Unlock()
	if qc.handshakeDone.Load() {
		qc.closeWithAppError(h3ErrNoError, "server shutting down")
		return
	}
	qc.close()
}
