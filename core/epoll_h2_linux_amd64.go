//go:build linux && amd64

package core

func (c *epollConn) epollProcessH2Frames(srv *Server) int {
	st := &c.h2
	if !st.prefaceReceived {
		if c.readN-st.appBufOff < H2PrefaceLen {
			return epollActionNeedRead
		}
		st.prefaceReceived = true
		st.appBufOff += H2PrefaceLen
	}

	for {
		if len(c.writeBuf)-c.writeSent > c.worker.maxPendingWrite {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
			return epollActionCloseAfterFlush
		}
		avail := c.readN - st.appBufOff
		if avail < 9 {
			c.compactH2ReadBuffer(false)
			return epollActionNeedRead
		}
		base := st.appBufOff
		frameLen := int(c.readBuf[base])<<16 | int(c.readBuf[base+1])<<8 | int(c.readBuf[base+2])
		frameType := c.readBuf[base+3]
		frameFlags := c.readBuf[base+4]
		streamID := (uint32(c.readBuf[base+5])<<24 | uint32(c.readBuf[base+6])<<16 | uint32(c.readBuf[base+7])<<8 | uint32(c.readBuf[base+8])) & 0x7fffffff
		if frameLen > int(srv.h2MaxFrameSize()) {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return epollActionCloseAfterFlush
		}
		totalLen := 9 + frameLen
		if avail < totalLen {
			c.compactH2ReadBuffer(false)
			return epollActionNeedRead
		}
		payload := c.readBuf[base+9 : base+totalLen]

		if st.expectContinuation != 0 {
			if frameType != H2FrameContinuation || streamID != st.expectContinuation {
				c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
				return epollActionCloseAfterFlush
			}
			closeConn := c.epollH2Continuation(srv, streamID, frameFlags, payload)
			st.appBufOff += totalLen
			if closeConn {
				return epollActionCloseAfterFlush
			}
			continue
		}

		closeConn := c.epollH2Frame(srv, frameType, frameFlags, streamID, payload)
		st.appBufOff += totalLen
		if closeConn {
			return epollActionCloseAfterFlush
		}
	}
}

func (c *epollConn) epollH2Frame(srv *Server, frameType, frameFlags byte, streamID uint32, payload []byte) bool {
	st := &c.h2
	switch frameType {
	case H2FrameSettings, H2FramePing, H2FramePriority:
		if st.countCtrl() {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
			return true
		}
	case H2FrameData:
		if h2DataCarriesNoBody(frameFlags, payload) && st.countCtrl() {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
			return true
		}
	}
	switch frameType {
	case H2FrameSettings:
		if streamID != 0 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		if frameFlags&H2FlagAck != 0 {
			if len(payload) > 0 {
				c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
				return true
			}
			return false
		}
		if len(payload)%6 != 0 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return true
		}
		if !c.epollH2Settings(payload) {
			return true
		}
		c.writeBuf = appendH2SettingsAckFrame(c.writeBuf)
		return false
	case H2FrameHeaders:
		return c.epollH2Headers(srv, streamID, frameFlags, payload)
	case H2FrameContinuation:
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
		return true
	case H2FrameData:
		return c.epollH2Data(srv, streamID, frameFlags, payload)
	case H2FrameWindowUpdate:
		return c.epollH2WindowUpdate(streamID, payload)
	case H2FramePing:
		if streamID != 0 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		if len(payload) != 8 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return true
		}
		if frameFlags&H2FlagAck == 0 {
			var pingData [8]byte
			copy(pingData[:], payload)
			c.writeBuf = appendH2PingFrame(c.writeBuf, true, pingData)
		}
		return false
	case H2FrameRSTStream:
		if streamID == 0 || len(payload) != 4 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		c.abandonH2Stream(streamID, ErrClientGone)
		if st.countReset() {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
			return true
		}
		return false
	case H2FrameGoAway:
		if streamID != 0 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		if len(payload) < h2GoAwayMinPayload {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return true
		}
		st.peerGoingAway = true
		return c.h2Quiescent()
	case H2FramePriority:
		if streamID == 0 || len(payload) != 5 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		return false
	case H2FramePushPromise:
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
		return true
	default:
		return false
	}
}

func (c *epollConn) epollH2Settings(payload []byte) bool {
	st := &c.h2
	windowChanged := false
	oldWindow := st.initialWindowSize
	for i := 0; i+6 <= len(payload); i += 6 {
		id := uint16(payload[i])<<8 | uint16(payload[i+1])
		val := uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 | uint32(payload[i+4])<<8 | uint32(payload[i+5])
		switch id {
		case H2SettingMaxFrameSize:
			if val < 16384 || val > uint32(H2MaxFrameSize) {
				c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
				return false
			}
			st.maxFrameSize = val
		case H2SettingInitialWindowSize:
			if val > 2147483647 {
				c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFlowControl)
				return false
			}
			st.initialWindowSize = val
			windowChanged = true
		}
	}
	if windowChanged {
		if delta := int64(st.initialWindowSize) - int64(oldWindow); delta != 0 {
			if !c.h2ShiftStreamWindows(delta) {
				c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFlowControl)
				return false
			}
			if delta > 0 {
				c.h2ResumeSending(0)
			}
			c.h2WindowOpened(c.worker)
		}
	}
	return true
}

func (c *epollConn) epollH2Headers(srv *Server, streamID uint32, frameFlags byte, payload []byte) bool {
	st := &c.h2
	if streamID == 0 {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
		return true
	}
	if frameFlags&H2FlagPadded != 0 {
		if len(payload) == 0 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return true
		}
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		payload = payload[:len(payload)-padLen]
	}
	if frameFlags&H2FlagPriority != 0 {
		if len(payload) < 5 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return true
		}
		payload = payload[5:]
	}
	if frameFlags&H2FlagEndHeaders == 0 {
		st.expectContinuation = streamID
		st.headerEndStream = frameFlags&H2FlagEndStream != 0
		st.headerAccum = append(st.headerAccum[:0], payload...)
		return false
	}
	return c.epollH2DecodedHeaders(srv, streamID, payload, frameFlags&H2FlagEndStream != 0)
}

func (c *epollConn) epollH2Continuation(srv *Server, streamID uint32, frameFlags byte, payload []byte) bool {
	st := &c.h2
	st.headerAccum = append(st.headerAccum, payload...)
	if len(st.headerAccum) > st.decoder.maxHeaderListSize*4 {
		st.expectContinuation = 0
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
		return true
	}
	if frameFlags&H2FlagEndHeaders == 0 {
		return false
	}
	endStream := st.headerEndStream
	st.expectContinuation = 0
	return c.epollH2DecodedHeaders(srv, streamID, st.headerAccum, endStream)
}

func (c *epollConn) epollH2DecodedHeaders(srv *Server, streamID uint32, headerBlock []byte, endStream bool) bool {
	st := &c.h2
	if streamID%2 == 1 && streamID <= st.highestStreamID {
		if st.streams[streamID] != nil || c.h2BodyIn[streamID] != nil {
			return c.epollH2Trailers(srv, streamID, headerBlock, endStream)
		}
		if endStream && !c.h2StreamAwaitingResponse(streamID) {
			return c.discardH2ClosedStreamHeaders(headerBlock)
		}
	}
	if streamID%2 == 0 || streamID <= st.highestStreamID {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
		return true
	}
	st.highestStreamID = streamID
	if c.h2GoingAway {
		return c.refuseH2StreamGoingAway(streamID, headerBlock)
	}
	st.lastStreamID = streamID
	h2Fast := srv.h2RootFast.Load()
	fastRoot := h2Fast != nil && srv.httpRouter.Load() == nil

	if endStream && fastRoot && matchIndexedH2FastRootHeaderBlock(headerBlock) {
		if srv.tryAcquireRequestSlot() {
			Stats.TotalReqs.Add(1)
			Stats.RawReqs.Add(1)
			c.writeBuf = appendFastH2RootResponse(c.writeBuf, h2Fast.forConn(c.tls), streamID, int(st.maxFrameSize))
			srv.releaseRequestSlot()
			return false
		}
	}

	if endStream && fastRoot && st.decoder.MemoizedRootRequest(headerBlock) {
		if srv.tryAcquireRequestSlot() {
			Stats.TotalReqs.Add(1)
			Stats.RawReqs.Add(1)
			c.writeBuf = appendFastH2RootResponse(c.writeBuf, h2Fast.forConn(c.tls), streamID, int(st.maxFrameSize))
			srv.releaseRequestSlot()
			return false
		}
	}

	headers, meta, isRoot, err := st.decoder.DecodeRequest(st.headersBuf[:0], headerBlock)
	st.headersBuf = headers[:0]
	if err == errH2MalformedRequest {
		return c.resetMalformedH2Stream(streamID)
	}
	if err == errH2HeaderListTooLarge {
		return c.answerH2HeaderListTooLarge(srv, streamID, endStream)
	}
	if err != nil {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrCompression)
		return true
	}
	if endStream && fastRoot && isRoot {
		if srv.tryAcquireRequestSlot() {
			Stats.TotalReqs.Add(1)
			Stats.RawReqs.Add(1)
			c.writeBuf = appendFastH2RootResponse(c.writeBuf, h2Fast.forConn(c.tls), streamID, int(st.maxFrameSize))
			srv.releaseRequestSlot()
			return false
		}
	}
	if len(headers) > h2MaxRequestFields {
		return c.refuseH2Stream(streamID, H2ErrEnhanceYourCalm)
	}
	streamLimit := int(srv.h2MaxStreams())
	if st.peerGoingAway || c.h2PeerStreamsAtLimit(streamLimit) {
		return c.refuseH2Stream(streamID, H2ErrRefusedStream)
	}
	if c.h2EndedInFlight >= streamLimit {
		return c.refuseH2StreamForEndedHandlers(streamID)
	}
	if meta.method == "" || meta.path == "" {
		return c.resetMalformedH2Stream(streamID)
	}

	stream := StreamPool.Get().(*H2Stream)
	stream.Reset()
	stream.ID = streamID
	stream.Window.Store(int64(st.initialWindowSize))
	stream.RecvWindow = int64(srv.h2InitialWindow())
	stream.Method = meta.method
	stream.Path = meta.path
	stream.RawPath = meta.rawPath
	stream.Query = meta.query
	stream.Scheme = meta.scheme
	stream.Auth = meta.authority
	stream.declaredLen = meta.declaredLength()
	if meta.protocolWebSocket {
		stream.wsTunnel = true
		stream.Method = "GET"
	}
	for i := range headers {
		if name := headers[i][0]; name == "" || name[0] != ':' {
			stream.Headers = append(stream.Headers, headers[i])
		}
	}

	st.streams[streamID] = stream
	if endStream {
		if h2LengthMismatch(stream.declaredLen, 0) {
			return c.rejectH2Body(streamID)
		}
		return c.epollH2Dispatch(srv, streamID, false)
	}
	stream.State.Store(StreamOpen)
	if meta.protocolSet || c.worker.streamsH2Body(stream) {
		return c.epollH2Dispatch(srv, streamID, true)
	}
	return false
}

func (c *epollConn) resetMalformedH2Stream(streamID uint32) bool {
	return c.refuseH2Stream(streamID, H2ErrProtocol)
}

func (c *epollConn) refuseH2Stream(streamID, errCode uint32) bool {
	c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, errCode)
	return c.h2ChargeLimiter(c.h2.countReset())
}

func (c *epollConn) refuseH2StreamForEndedHandlers(streamID uint32) bool {
	c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrRefusedStream)
	return c.h2ChargeLimiter(c.h2.countCtrl())
}

func (c *epollConn) h2ChargeLimiter(tripped bool) bool {
	if tripped {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, c.h2.lastStreamID, H2ErrEnhanceYourCalm)
	}
	return tripped
}

func (c *epollConn) answerH2HeaderListTooLarge(srv *Server, streamID uint32, endStream bool) bool {
	c.writeBuf = appendH2StatusOnlyResponse(c.writeBuf, streamID, h2StatusHeaderListTooLarge, srv.config.ServerName)
	if !endStream {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrNoError)
	}
	return c.h2ChargeLimiter(c.h2.countReset())
}

func (c *epollConn) h2StreamAwaitingResponse(streamID uint32) bool {
	st := &c.h2
	return st.sending[streamID] != nil || c.h2Streaming[streamID] != nil || st.findBusy(streamID) != nil
}

func (c *epollConn) discardH2ClosedStreamHeaders(headerBlock []byte) bool {
	st := &c.h2
	fields, err := st.decoder.DecodeInto(st.headersBuf[:0], headerBlock)
	if err != nil {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrCompression)
		return true
	}
	st.headersBuf = fields[:0]
	return c.h2ChargeLimiter(st.countReset())
}

func (c *epollConn) resetH2Stream(streamID, errCode uint32) bool {
	c.abandonH2Stream(streamID, ErrStreamClosed)
	return c.refuseH2Stream(streamID, errCode)
}

func (c *epollConn) abandonH2Stream(streamID uint32, cause error) {
	st := &c.h2
	epollReleaseH2Stream(st, streamID)
	if stream := st.sending[streamID]; stream != nil {
		st.releaseSending(streamID, stream)
	}
	abandoned := st.cancelBusyStream(streamID, cause)
	if !c.h2CancelStreaming(streamID) && abandoned != nil {
		abandoned.abandonCounted = true
		c.h2EndedInFlight++
	}
	c.h2AbortBodyIn(streamID)
}

func (c *epollConn) h2UncountAbandoned(stream *H2Stream) {
	if stream.abandonCounted && c.h2EndedInFlight > 0 {
		c.h2EndedInFlight--
	}
	stream.abandonCounted = false
}

func (c *epollConn) h2PeerStreamsAtLimit(limit int) bool {
	st := &c.h2
	return len(st.streams)+len(st.sending)+c.inFlight-c.h2EndedInFlight+c.h2Draining >= limit
}

func (c *epollConn) h2Quiescent() bool {
	st := &c.h2
	return c.inFlight == 0 && len(st.streams) == 0 && len(st.sending) == 0 && len(c.h2Streaming) == 0 && len(c.h2BodyIn) == 0
}

func (c *epollConn) h2PeerLeft() bool {
	return c.h2.peerGoingAway && c.speaksH2() && c.h2Quiescent()
}

func (c *epollConn) epollH2Trailers(srv *Server, streamID uint32, headerBlock []byte, endStream bool) bool {
	st := &c.h2
	fields, err := st.decoder.DecodeInto(st.headersBuf[:0], headerBlock)
	if err != nil {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrCompression)
		return true
	}
	st.headersBuf = fields[:0]
	if h2FieldListSize(fields) > st.decoder.maxHeaderListSize {
		return c.rejectH2Body(streamID)
	}
	trailers, ok := h2TrailerFields(fields)
	stream := st.streams[streamID]
	if stream != nil && stream.State.Load() >= StreamHalfClosed {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrStreamClosed)
		return false
	}
	if !endStream || !ok {
		return c.rejectH2Body(streamID)
	}
	if stream != nil {
		if h2LengthMismatch(stream.declaredLen, int64(len(stream.Body))) {
			return c.rejectH2Body(streamID)
		}
		stream.Trailers = trailers
		stream.State.Store(StreamHalfClosed)
		return c.epollH2Dispatch(srv, streamID, false)
	}
	in := c.h2BodyIn[streamID]
	if h2LengthMismatch(in.declared, in.received) {
		return c.rejectH2Body(streamID)
	}
	delete(c.h2BodyIn, streamID)
	in.reader.finishWithTrailers(trailers)
	return false
}

func h2LengthMismatch(declared, received int64) bool {
	return declared >= 0 && declared != received
}

func (c *epollConn) rejectH2Body(streamID uint32) bool {
	st := &c.h2
	c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrProtocol)
	epollReleaseH2Stream(st, streamID)
	c.h2AbortBodyIn(streamID)
	if st.countReset() {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
		return true
	}
	return false
}

func (c *epollConn) epollH2Data(srv *Server, streamID uint32, frameFlags byte, payload []byte) bool {
	st := &c.h2
	if streamID == 0 {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
		return true
	}
	frameConsumed := len(payload)
	consumed := int64(frameConsumed)
	st.recvConnWindow -= consumed
	if st.recvConnWindow < 0 {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFlowControl)
		return true
	}
	c.h2CreditConnWindow(uint32(frameConsumed))
	payload, padOK := h2StripPadding(frameFlags, payload)

	stream := st.streams[streamID]
	if stream == nil {
		if in := c.h2BodyIn[streamID]; in != nil {
			if !padOK {
				c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrProtocol)
				c.h2EndBodyIn(in, ErrBodyStreamAborted)
				return false
			}
			return c.h2StreamBodyData(in, frameFlags&H2FlagEndStream != 0, frameConsumed, payload)
		}
		return false
	}
	if stream.State.Load() >= StreamHalfClosed {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrStreamClosed)
		return false
	}
	if !padOK {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrProtocol)
		return false
	}
	stream.RecvWindow -= consumed
	if stream.RecvWindow < 0 {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrFlowControl)
		epollReleaseH2Stream(st, streamID)
		return false
	}

	if len(payload) > 0 {
		if !srv.tryReserveConnBodyBytes(&st.bodyReserved, len(payload)) {
			c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrEnhanceYourCalm)
			epollReleaseH2Stream(st, streamID)
			return false
		}
		stream.bodyOwner = srv
		stream.bodyConn = &st.bodyReserved
		stream.bodyAccounted += int64(len(payload))
		stream.Body = append(stream.Body, payload...)
		if stream.declaredLen >= 0 && int64(len(stream.Body)) > stream.declaredLen {
			return c.rejectH2Body(streamID)
		}
	}
	if srv.requestBodyTooLarge(len(stream.Body)) {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrCancel)
		epollReleaseH2Stream(st, streamID)
		return false
	}

	consumedWindow := uint32(frameConsumed)
	if frameFlags&H2FlagEndStream == 0 {
		if consumedWindow > 0 {
			c.writeBuf = appendH2WindowUpdateFrame(c.writeBuf, streamID, consumedWindow)
			stream.RecvWindow += int64(consumedWindow)
		}
		return false
	}
	if h2LengthMismatch(stream.declaredLen, int64(len(stream.Body))) {
		return c.rejectH2Body(streamID)
	}
	stream.State.Store(StreamHalfClosed)
	return c.epollH2Dispatch(srv, streamID, false)
}

func (c *epollConn) epollH2WindowUpdate(streamID uint32, payload []byte) bool {
	st := &c.h2
	if len(payload) != 4 {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
		return true
	}
	increment := (uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])) & 0x7fffffff
	if increment == 0 {
		if streamID == 0 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		return c.resetH2Stream(streamID, H2ErrProtocol)
	}
	if streamID == 0 {
		st.connWindow += int64(increment)
		if st.connWindow > h2MaxWindowSize {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFlowControl)
			return true
		}
		c.h2ResumeSending(0)
		c.h2WindowOpened(c.worker)
		return false
	}
	if stream := st.streams[streamID]; stream != nil {
		if !h2CreditWindow(stream, increment) {
			return c.resetH2Stream(streamID, H2ErrFlowControl)
		}
		return false
	}
	if stream := st.sending[streamID]; stream != nil {
		if !h2CreditWindow(stream, increment) {
			return c.resetH2Stream(streamID, H2ErrFlowControl)
		}
		c.h2ResumeSending(streamID)
		return false
	}
	if sw := c.h2Streaming[streamID]; sw != nil {
		if !h2CreditWindow(sw.stream, increment) {
			return c.resetH2Stream(streamID, H2ErrFlowControl)
		}
		c.h2WindowOpened(c.worker)
		return false
	}
	if streamID > st.highestStreamID {
		return false
	}
	if stream := st.findBusy(streamID); stream != nil && !h2CreditWindow(stream, increment) {
		return c.resetH2Stream(streamID, H2ErrFlowControl)
	}
	return false
}

func h2CreditWindow(stream *H2Stream, increment uint32) bool {
	newWindow := stream.Window.Load() + int64(increment)
	if newWindow > h2MaxWindowSize {
		return false
	}
	stream.Window.Store(newWindow)
	return true
}

func h2ShiftWindow(stream *H2Stream, delta int64) bool {
	return stream.Window.Add(delta) <= h2MaxWindowSize
}

func (c *epollConn) h2ShiftStreamWindows(delta int64) bool {
	st := &c.h2
	ok := true
	for _, stream := range st.streams {
		ok = h2ShiftWindow(stream, delta) && ok
	}
	for _, stream := range st.sending {
		ok = h2ShiftWindow(stream, delta) && ok
	}
	for stream := st.busy; stream != nil; stream = stream.busyNext {
		ok = h2ShiftWindow(stream, delta) && ok
	}
	for _, sw := range c.h2Streaming {
		if sw.handlerDone {
			ok = h2ShiftWindow(sw.stream, delta) && ok
		}
	}
	return ok
}

func (c *epollConn) epollH2Dispatch(srv *Server, streamID uint32, streamBody bool) bool {
	st := &c.h2
	stream := st.streams[streamID]
	if stream == nil {
		return false
	}

	Stats.TotalReqs.Add(1)
	Stats.RawReqs.Add(1)
	if srv.logRequests.Load() {
		srv.logger().Info("request", "proto", "HTTP/2", "stream", stream.ID, "method", stream.Method, "path", stream.Path)
	}

	stream.req.Reset()
	stream.req.Method = stream.Method
	stream.req.Path = stream.Path
	stream.req.RawPath = stream.RawPath
	stream.req.Query = stream.Query
	stream.req.Proto = "HTTP/2"
	stream.req.Headers = append(stream.req.Headers[:0], stream.Headers...)
	stream.req.Body = stream.Body
	stream.req.trailers = stream.Trailers
	stream.req.StreamID = stream.ID
	stream.req.IsH2 = true
	stream.req.h2WebSocket = stream.wsTunnel
	stream.req.Host = stream.Auth
	stream.req.cachedHost = stream.Auth
	stream.req.headerCacheMask = headerCacheHost
	stream.req.RemoteAddr = c.remoteAddr
	stream.req.IsTLS = c.tls
	stream.req.peerCerts = c.peerCerts
	stream.req.TLSVersion = c.tlsVersion
	stream.req.server = srv
	stream.req.StreamWriter = nil
	stream.req.conn = nil
	stream.req.tlsReader = nil
	stream.req.tlsWriter = nil
	stream.req.hdrBuf = nil

	if !c.acquireIPConn(srv, &stream.req) {
		statsBlocked()
		stream.Reset()
		StreamPool.Put(stream)
		delete(st.streams, streamID)
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
		return true
	}

	stream.resp.Reset()
	stream.resp.SetSW(nil)
	stream.resp.lazyReq = &stream.req

	delete(st.streams, streamID)
	stream.asyncBusy = true
	st.linkBusy(stream)
	stream.cancel.attach(&stream.req)
	c.inFlight++

	gen := c.generation
	w := c.worker
	cc := c
	sid := streamID

	if srv.misdirectsClientAuth(c.tlsCertEntry, stream.req.Host) {
		stream.resp.Status(421).String("Misdirected Request")
		c.finishH2Dispatch(w, gen, sid, stream)
		return false
	}

	// A proxied stream is driven in this loop. Previously it parked a goroutine
	// on the backend, which also meant per-domain timeouts were ignored because
	// the blocking path used one process-global upstream client.
	if pe, ds := srv.matchProxyTarget(&stream.req); ds != nil && !srv.proxyNeedsDispatch(pe, &stream.req) {
		{
			start := w.beginProxyH2(pe, ds, c, stream, streamID)
			if start == proxyStartPending {
				return false
			}
			if start == proxyStartServed {
				c.finishH2Dispatch(w, gen, sid, stream)
				return false
			}
		}
	}

	stream.dispatchGen = gen
	stream.req.swFactory = c
	stream.req.h2Stream = stream
	if streamBody {
		c.startH2BodyStream(w, stream)
	}
	w.spawned++
	w.handlers.run(func() {
		defer func() {
			if r := recover(); r != nil {
				srv.reportPanic(&stream.req, r)
				stream.resp.Reset()
				stream.resp.Status(500).String("Internal Server Error")
			}
			stream.req.awaitH2Tunnel()
			w.postTask(func(w *epollWorker) { cc.finishH2Dispatch(w, gen, sid, stream) })
		}()
		if srv.fastDispatch.Load() {
			promoteRequestStrings(&stream.req)
			handler := srv.Router.Lookup(stream.req.Method, stream.req.Path, &stream.req)
			handler(&stream.req, &stream.resp)
		} else {
			srv.dispatch(&stream.req, &stream.resp)
		}
	})
	return false
}

func (c *epollConn) finishH2Dispatch(w *epollWorker, gen uint32, streamID uint32, stream *H2Stream) {
	c.h2.unlinkBusy(stream)
	stream.req.finishContext()
	if c.inFlight > 0 {
		c.inFlight--
	}
	sw, _ := stream.resp.sw.(*epollH2StreamWriter)
	if c.generation != gen || c.fd < 0 {
		stream.asyncBusy = false
		if sw != nil {
			sw.fail(ErrStreamClosed)
			c.h2UncountEndedEarly(sw)
			sw.release()
		}
		stream.Reset()
		StreamPool.Put(stream)
		if c.fd < 0 && c.inFlight == 0 {
			w.pool.put(c)
		}
		return
	}
	stream.asyncBusy = false
	c.h2UncountAbandoned(stream)
	bodyOpen := c.h2AbortBodyIn(streamID)
	if sw != nil {
		stream.resp.sw = nil
		if stream.abandoned {
			sw.fail(ErrStreamClosed)
		}
		if sw.headerReady {
			c.h2FinishStreamed(w, stream, sw)
			return
		}
		c.h2DropUnusedWriter(sw)
	}
	if stream.abandoned {
		stream.Reset()
		StreamPool.Put(stream)
		w.markFlush(c)
		return
	}
	st := &c.h2
	resp := &stream.resp
	if stream.req.hijacked || resp.IsStreamed() {
		resp.Reset()
		resp.Status(500).String("Streaming/Hijack unsupported in epoll HTTP/2 backend")
	}
	if w.server.config.MaxWriteSize > 0 && int64(resp.transmittedBodyLen()) > w.server.config.MaxWriteSize {
		resp.Reset()
		resp.Status(500).String("Response Too Large")
	}

	stream.respHeadersSent = false
	stream.respOff = 0
	if c.h2EmitWindowed(w, stream, streamID) {
		stream.Reset()
		StreamPool.Put(stream)
		if bodyOpen {
			c.emitH2Reset(w, streamID, H2ErrNoError)
		}
	} else {
		st.sending[streamID] = stream
		c.h2SettleParked(w, streamID, stream)
	}
	w.markFlush(c)
}

func (c *epollConn) emitH2Reset(w *epollWorker, streamID, errCode uint32) {
	rst := appendH2RSTStreamFrame(w.h2FinishScratch[:0], streamID, errCode)
	c.emitH2(rst)
	w.h2FinishScratch = rst[:0]
}

func (c *epollConn) h2OutputBacklog() int {
	if c.inTLSFrameDrain {
		return len(c.writeBuf)
	}
	return len(c.writeBuf) - c.writeSent
}

func (c *epollConn) h2EmitWindowed(w *epollWorker, stream *H2Stream, streamID uint32) bool {
	budget := h2StreamSocketHighMark - c.h2OutputBacklog()
	if c.sealsH2Output() {
		plain, done := c.h2AppendWindowed(w.h2FinishScratch[:0], stream, streamID, budget)
		w.h2FinishScratch = plain[:0]
		if len(plain) > 0 {
			c.writeBuf = c.sealTLSAppData(c.writeBuf, plain)
		}
		return done
	}
	var done bool
	c.writeBuf, done = c.h2AppendWindowed(c.writeBuf, stream, streamID, budget)
	return done
}

func (c *epollConn) h2SettleParked(w *epollWorker, streamID uint32, stream *H2Stream) {
	st := &c.h2
	stall := 0
	if stream.Window.Load() <= 0 || st.connWindow <= 0 {
		stall = len(stream.resp.transmittedBodyBytes()) - stream.respOff
	}
	st.sendingBytes += int64(stall - stream.stallBytes)
	stream.stallBytes = stall
	if stall > 0 && st.sendingBytes > int64(w.maxPendingWrite) {
		c.emitH2Reset(w, streamID, H2ErrEnhanceYourCalm)
		st.releaseSending(streamID, stream)
	}
}

func (c *epollConn) h2AppendWindowed(dst []byte, stream *H2Stream, streamID uint32, budget int) ([]byte, bool) {
	st := &c.h2
	resp := &stream.resp
	body := resp.transmittedBodyBytes()
	limit := len(dst) + budget
	if !stream.respHeadersSent {
		if c.tls {
			addAltSvcHeader(resp, c.worker.server)
		}
		dst = appendH2ResponseHeadersFrame(dst, streamID, resp, len(body) == 0)
		stream.respHeadersSent = true
	}
	frameLimit := int(st.maxFrameSize)
	if frameLimit <= 0 {
		frameLimit = H2DefaultMaxFrameSize
	}
	for stream.respOff < len(body) && len(dst) < limit {
		avail := stream.Window.Load()
		if st.connWindow < avail {
			avail = st.connWindow
		}
		if avail <= 0 {
			break
		}
		n := len(body) - stream.respOff
		if int64(n) > avail {
			n = int(avail)
		}
		if n > frameLimit {
			n = frameLimit
		}
		end := stream.respOff+n == len(body)
		flags := byte(0)
		if end {
			flags = H2FlagEndStream
		}
		dst = appendH2Frame(dst, H2FrameData, flags, streamID, body[stream.respOff:stream.respOff+n])
		stream.respOff += n
		st.connWindow -= int64(n)
		stream.Window.Add(-int64(n))
	}
	return dst, stream.respOff >= len(body)
}

func (c *epollConn) h2ResumeSending(streamID uint32) {
	st := &c.h2
	if streamID != 0 {
		if stream := st.sending[streamID]; stream != nil {
			c.h2ResumeStream(streamID, stream)
		}
		return
	}
	for id, stream := range st.sending {
		c.h2ResumeStream(id, stream)
	}
}

func (c *epollConn) h2ResumeStream(streamID uint32, stream *H2Stream) {
	w := c.worker
	if c.h2EmitWindowed(w, stream, streamID) {
		c.h2.releaseSending(streamID, stream)
		return
	}
	c.h2SettleParked(w, streamID, stream)
}

func (c *epollConn) h2PumpBuffered() bool {
	if len(c.h2.sending) != 0 {
		before := len(c.writeBuf)
		c.h2ResumeSending(0)
		return len(c.writeBuf) > before
	}
	if c.h2PeerLeft() {
		c.closeAfter = true
	}
	return false
}

func epollReleaseH2Stream(st *tlsWorkerH2State, streamID uint32) {
	stream := st.streams[streamID]
	if stream == nil {
		return
	}
	delete(st.streams, streamID)
	stream.Reset()
	StreamPool.Put(stream)
}

func matchIndexedH2FastRootHeaderBlock(headerBlock []byte) bool {
	if len(headerBlock) != 3 {
		return false
	}
	var seen uint8
	for i := range headerBlock {
		switch headerBlock[i] {
		case 0x82:
			seen |= 1
		case 0x84:
			seen |= 2
		case 0x87:
			seen |= 4
		default:
			return false
		}
	}
	return seen == 7
}
