//go:build linux && amd64

package core

func (c *epollConn) sealTLSAppData(dst, plain []byte) []byte {
	if c.tls12 != nil {
		return buildTLS12AppDataRecords(dst, c.tls12.writer, plain)
	}
	if c.appWriter.keyWornOut() {
		dst = c.renewWriteKey(dst)
	}
	return buildTLSAppDataRecords(dst, c.appWriter, plain)
}

func (c *epollConn) sealTLSAppDataParts(dst, head, body []byte) []byte {
	if c.tls12 != nil {
		return buildTLS12AppDataRecordsParts(dst, c.tls12.writer, head, body)
	}
	if c.appWriter.keyWornOut() {
		dst = c.renewWriteKey(dst)
	}
	return buildTLSAppDataRecordsParts(dst, c.appWriter, head, body)
}

func (c *epollConn) renewWriteKey(dst []byte) []byte {
	dst, renewed := appendKeyUpdateRecord(dst, c.appWriter)
	if !renewed {
		c.closeAfter = true
	}
	return dst
}

func (c *epollConn) sealsH2Output() bool { return c.tls && !c.inTLSFrameDrain }

func (c *epollConn) emitH2(frames []byte) {
	if c.sealsH2Output() {
		c.writeBuf = c.sealTLSAppData(c.writeBuf, frames)
		return
	}
	c.writeBuf = append(c.writeBuf, frames...)
}

func (c *epollConn) epollTLSEncryptResponse(srv *Server, plain []byte) {
	c.writeBuf = c.sealTLSAppData(c.writeBuf, plain)
}

func (c *epollConn) epollTLSApplicationH2(srv *Server) int {
	for {
		action, gotData := c.epollTLSDecryptToApp(srv)
		if action == epollActionNeedRead || action == epollActionCloseAfterFlush {
			if act := c.epollTLSH2Drain(srv); act == epollActionCloseAfterFlush {
				return act
			}
			return action
		}
		if !gotData {
			return epollActionNeedRead
		}
		if act := c.epollTLSH2Drain(srv); act == epollActionCloseAfterFlush {
			return act
		}
	}
}

func (c *epollConn) epollTLSH2Drain(srv *Server) int {
	if c.appBufOff >= len(c.appBuf) && len(c.appBuf) == 0 {
		return epollTLSContinue
	}
	savedWrite := c.writeBuf
	c.writeBuf = c.plainBuf[:0]
	c.inTLSFrameDrain = true
	action := c.epollProcessH2FramesTLS(srv)
	c.inTLSFrameDrain = false
	plain := c.writeBuf
	c.plainBuf = plain[:0]
	c.writeBuf = savedWrite
	if len(plain) > 0 {
		c.epollTLSEncryptResponse(srv, plain)
	}
	if c.appBufOff > 0 {
		c.compactApp(c.appBufOff)
		c.appBufOff = 0
		c.h2.appBufOff = 0
	}
	if action == epollActionCloseAfterFlush {
		return epollActionCloseAfterFlush
	}
	return epollTLSContinue
}
