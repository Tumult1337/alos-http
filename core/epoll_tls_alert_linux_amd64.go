//go:build linux && amd64

package core

import "crypto/hmac"

func appendPlainAlert(dst []byte, desc tlsAlert) []byte {
	body := [2]byte{tlsAlertLevelFatal, byte(desc)}
	return AppendRecord(dst, tlsRecAlert, body[:])
}

func appendTLS13Alert(dst []byte, w *TrafficAEAD, level byte, desc tlsAlert) []byte {
	inner := [3]byte{level, byte(desc), tlsRecAlert}
	return appendTLSInnerRecord(dst, w, inner[:])
}

func appendTLS12Alert(dst []byte, w *tls12AEAD, level byte, desc tlsAlert) []byte {
	hdr := len(dst)
	prefix := w.recordPrefixLen()
	dst = ensureTailCap(dst, prefix+2+w.aead.Overhead())
	dst = append(dst[:hdr+prefix], level, byte(desc))
	return w.sealInPlace(dst, hdr, tlsRecAlert)
}

func (c *epollConn) serverWritesPlaintext() bool {
	switch c.phase {
	case tlsConnPhaseClientHello:
		return true
	case tlsConnPhase12ClientFinish:
		return !c.tls12.serverCCSSent
	}
	return false
}

func (c *epollConn) failTLS(desc tlsAlert) int {
	switch {
	case c.serverWritesPlaintext():
		c.writeBuf = appendPlainAlert(c.writeBuf, desc)
	case c.tls12 != nil:
		c.writeBuf = appendTLS12Alert(c.writeBuf, c.tls12.writer, tlsAlertLevelFatal, desc)
	case c.appWriter != nil:
		c.writeBuf = appendTLS13Alert(c.writeBuf, c.appWriter, tlsAlertLevelFatal, desc)
	default:
		return epollActionCloseAfterFlush
	}
	c.tlsAlertSent = true
	return epollActionCloseAfterFlush
}

func (c *epollConn) sendCloseNotify() bool {
	if !c.tls || c.tlsAlertSent || c.fd < 0 || (c.phase != tlsConnPhaseApplication && c.phase != tlsConnPhaseH2Native) {
		return true
	}
	var rec []byte
	if c.tls12 != nil {
		rec = appendTLS12Alert(c.writeBuf[:0], c.tls12.writer, tlsAlertLevelWarning, alertCloseNotify)
	} else {
		rec = appendTLS13Alert(c.writeBuf[:0], c.appWriter, tlsAlertLevelWarning, alertCloseNotify)
	}
	n, _ := socketSend(c.fd, rec)
	sent := max(n, 0)
	c.worker.bytesOut += uint64(sent)
	c.tlsAlertSent = true
	if sent == len(rec) {
		c.writeBuf, c.writeSent = rec[:0], 0
		return true
	}
	c.writeBuf, c.writeSent = rec, sent
	return false
}

func (c *epollConn) closeNotifyIsFinalH1Record() bool {
	return c.tls && c.closeAfter && !c.tlsAlertSent && !c.lingering && c.fd >= 0 && c.phase == tlsConnPhaseApplication &&
		c.inFlight == 0 && !c.dispatching && c.proxyEx == nil && c.pausedBackend == nil && c.tunnelBE == nil &&
		len(c.bodyOut) == 0 && c.h1Body == nil && c.h1Stream == nil && c.ws == nil && c.wsPending == nil &&
		!c.takeoverPinned && !c.takeoverParked
}

func (c *epollConn) coalesceCloseNotify() {
	if !c.closeNotifyIsFinalH1Record() {
		return
	}
	if c.tls12 != nil {
		c.writeBuf = appendTLS12Alert(c.writeBuf, c.tls12.writer, tlsAlertLevelWarning, alertCloseNotify)
	} else {
		c.writeBuf = appendTLS13Alert(c.writeBuf, c.appWriter, tlsAlertLevelWarning, alertCloseNotify)
	}
	c.tlsAlertSent = true
}

func (c *epollConn) failUnexpectedRecord(ct byte) int {
	if ct == tlsRecAlert {
		return epollActionCloseAfterFlush
	}
	return c.failTLS(alertUnexpectedMessage)
}

func (c *epollConn) checkFinishedMessage(msg, expected []byte) (int, bool) {
	if len(msg) < tlsHandshakeHeaderLen {
		return c.failTLS(alertDecodeError), false
	}
	if msg[0] != tlsHSFinished {
		return c.failTLS(alertUnexpectedMessage), false
	}
	if int(msg[1])<<16|int(msg[2])<<8|int(msg[3]) != len(msg)-tlsHandshakeHeaderLen {
		return c.failTLS(alertDecodeError), false
	}
	if !hmac.Equal(msg[tlsHandshakeHeaderLen:], expected) {
		return c.failTLS(alertDecryptError), false
	}
	return 0, true
}
