//go:build linux && amd64

package core

import "strconv"

type h2BodyIn struct {
	reader     *BodyReader
	streamID   uint32
	recvWindow int64
	received   int64
	declared   int64
	tooLarge   bool
	tunnel     bool
	windowHeld bool
}

func (w *epollWorker) streamsH2Body(stream *H2Stream) bool {
	if w.streamBodyAbove <= 0 || w.server.builtInProxyActive() {
		return false
	}
	for i := range stream.Headers {
		if stream.Headers[i][0] == "content-length" {
			n, err := strconv.ParseInt(stream.Headers[i][1], 10, 64)
			return err != nil || n > w.streamBodyAbove
		}
	}
	return true
}

func (c *epollConn) openH2BodyIn(w *epollWorker, stream *H2Stream) *h2BodyIn {
	in := &h2BodyIn{streamID: stream.ID, recvWindow: stream.RecvWindow, declared: stream.declaredLen, tunnel: stream.wsTunnel}
	gen := c.generation
	in.reader = newBodyReader(func() {
		w.postTask(func(w *epollWorker) { c.h2BodyAcked(w, in, gen) })
	})
	in.reader.uploadConn, in.reader.uploadGlobal = c.connLimiter, w.server.globalLimiter
	in.reader.chargeBudget(w.server, &c.h2.bodyReserved)
	if c.h2BodyIn == nil {
		c.h2BodyIn = make(map[uint32]*h2BodyIn)
	}
	c.h2BodyIn[stream.ID] = in
	return in
}

func (c *epollConn) startH2BodyStream(w *epollWorker, stream *H2Stream) {
	in := stream.waitBody
	if in == nil {
		in = c.openH2BodyIn(w, stream)
	}
	stream.waitBody = nil
	stream.req.Body = nil
	stream.req.bodyStream = in.reader
}

func (c *epollConn) h2StreamBodyData(in *h2BodyIn, endStream bool, frameConsumed int, payload []byte) bool {
	in.recvWindow -= int64(frameConsumed)
	if in.recvWindow < 0 {
		c.h2ResetBodyIn(in, H2ErrFlowControl)
		return false
	}
	if !in.tooLarge && len(payload) > 0 {
		in.received += int64(len(payload))
		if in.declared >= 0 && in.received > in.declared {
			return c.rejectH2Body(in.streamID)
		}
		if !in.tunnel && c.worker.bodyTooLarge(in.received) {
			in.tooLarge = true
			in.reader.finish(ErrBodyTooLarge)
		} else if !c.h2BufferBody(in, payload) {
			return false
		}
	}
	if endStream {
		if !in.tooLarge && h2LengthMismatch(in.declared, in.received) {
			return c.rejectH2Body(in.streamID)
		}
		c.h2EndBodyIn(in, nil)
		return false
	}
	if padding := frameConsumed - len(payload); padding > 0 {
		c.writeBuf = appendH2WindowUpdateFrame(c.writeBuf, in.streamID, uint32(padding))
		in.recvWindow += int64(padding)
	}
	return false
}

func (c *epollConn) h2EndBodyIn(in *h2BodyIn, err error) {
	delete(c.h2BodyIn, in.streamID)
	if err != nil {
		in.reader.abort(err)
		return
	}
	in.reader.endWindow(in.recvWindow)
	in.reader.finish(nil)
}

func (c *epollConn) h2BufferBody(in *h2BodyIn, payload []byte) bool {
	if in.windowHeld {
		in.reader.push(payload)
		return true
	}
	if in.reader.reservePush(payload) {
		return true
	}
	c.h2ResetBodyIn(in, H2ErrRefusedStream)
	return false
}

func (c *epollConn) h2ReserveBodyWindow(stream *H2Stream) bool {
	in := stream.waitBody
	if in == nil || in.windowHeld || c.h2BodyIn[in.streamID] != in {
		return true
	}
	if !in.reader.reserveWindow(in.recvWindow) {
		c.h2.budgetBlocked = true
		return false
	}
	in.windowHeld = true
	return true
}

func (c *epollConn) h2ResetBodyIn(in *h2BodyIn, errCode uint32) {
	c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, in.streamID, errCode)
	if _, waiting := c.h2.findWaiting(in.streamID); waiting != nil {
		c.abandonH2Stream(in.streamID, ErrStreamClosed)
		return
	}
	c.h2EndBodyIn(in, ErrBodyStreamAborted)
}

func (c *epollConn) h2BodyAcked(w *epollWorker, in *h2BodyIn, gen uint32) {
	n := in.reader.takeAck()
	if n == 0 || c.generation != gen || c.fd < 0 || c.h2BodyIn[in.streamID] != in || in.tooLarge {
		return
	}
	frame := appendH2WindowUpdateFrame(w.h2FinishScratch[:0], in.streamID, uint32(n))
	c.emitH2(frame)
	w.h2FinishScratch = frame[:0]
	in.recvWindow += int64(n)
	w.markFlush(c)
}

func (c *epollConn) h2AbortBodyIn(streamID uint32) (wasOpen bool) {
	in := c.h2BodyIn[streamID]
	if in == nil {
		return false
	}
	c.h2EndBodyIn(in, ErrBodyStreamAborted)
	return true
}

func (c *epollConn) h2AbortAllBodyIn() {
	for _, in := range c.h2BodyIn {
		in.reader.abort(ErrBodyStreamAborted)
	}
	clear(c.h2BodyIn)
}

func (c *epollConn) h2CreditConnWindow(n uint32) {
	st := &c.h2
	st.pendingConnWindow += n
	if st.pendingConnWindow > H2ConnectionWindowSize/2 {
		connUpdate := st.pendingConnWindow
		st.pendingConnWindow = 0
		st.recvConnWindow += int64(connUpdate)
		c.writeBuf = appendH2WindowUpdateFrame(c.writeBuf, 0, connUpdate)
	}
}

func h2DataCarriesNoBody(frameFlags byte, payload []byte) bool {
	body, _ := h2StripPadding(frameFlags, payload)
	return len(body) == 0
}

func h2StripPadding(frameFlags byte, payload []byte) ([]byte, bool) {
	if frameFlags&H2FlagPadded == 0 {
		return payload, true
	}
	if len(payload) == 0 {
		return nil, false
	}
	padLen := int(payload[0])
	payload = payload[1:]
	if padLen > len(payload) {
		return nil, false
	}
	return payload[:len(payload)-padLen], true
}
