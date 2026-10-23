//go:build linux && amd64

package core

// Once a backend answers 101 the exchange stops being a request/response pair
// and becomes a byte tunnel. Both sockets already live in this worker's epoll
// set, so the tunnel runs in the event loop with no goroutines and no hijack:
// client bytes go straight into the backend's write buffer and back again.

// beginTunnel completes an upgrade by relaying the 101 to the client and
// cross-linking the two connections. It reports false when the tunnel cannot be
// established, which leaves the caller to fail the exchange.
func (w *epollWorker) beginTunnel(c *backendConn, p *h1Parser) bool {
	ex := c.cur
	if ex == nil {
		return false
	}
	px := proxyExchangeOf(ex)
	cc := px.c
	if cc == nil || px.h2Stream != nil || cc.generation != px.cGen || cc.fd < 0 {
		return false
	}

	scratch := appendTunnelResponseHead(w.beScratch[:0], p.hdr)
	w.beScratch = scratch[:0]
	w.clientAppend(cc, scratch)

	c.cur = nil
	ex.finished = true
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
		px.ds.outlier.recordSuccess(px.b)
		px.b = nil
	}
	cc.proxyEx = nil
	cc.dispatching = false
	cc.releaseH1BodyBudget()
	if cc.inFlight > 0 {
		cc.inFlight--
	}
	w.pxPut(px)

	cc.protocol = plainConnProtoTunnel
	cc.tunnelBE = c
	c.tunnelClient = cc
	cc.deadline = deadlineFrom(w.idleTO)
	c.idleDeadline = fpNoDeadline

	w.flush(cc)
	// Anything already buffered on either side belongs to the tunnel.
	if rest := c.rbuf.unread(); len(rest) > 0 {
		w.tunnelToClient(c, rest)
		c.rbuf.consume(len(rest))
	}
	if cc.fd >= 0 && cc.readN > cc.h1Off {
		w.tunnelToBackend(cc)
	}
	return true
}

func appendTunnelResponseHead(dst []byte, hdr [][2][]byte) []byte {
	dst = append(dst, "HTTP/1.1 101 "...)
	dst = append(dst, statusText(101)...)
	dst = append(dst, '\r', '\n')
	for _, h := range hdr {
		if headerNameIsBytes(h[0], "content-length") {
			continue
		}
		dst = append(dst, h[0]...)
		dst = append(dst, ':', ' ')
		dst = append(dst, h[1]...)
		dst = append(dst, '\r', '\n')
	}
	return append(dst, '\r', '\n')
}

// tunnelToClient relays backend bytes to the client, pausing the backend read
// side when the client falls behind.
func (w *epollWorker) tunnelToClient(c *backendConn, data []byte) {
	cc := c.tunnelClient
	if cc == nil || cc.fd < 0 {
		w.be.closeConn(c, errFPClientClosed)
		return
	}
	w.clientAppend(cc, data)
	w.flush(cc)
	if cc.fd >= 0 && !cc.outArmed {
		cc.deadline = deadlineFrom(w.idleTO)
	}
	if cc.fd >= 0 && len(cc.writeBuf)-cc.writeSent > proxyStreamHighWater && cc.pausedBackend == nil {
		cc.pausedBackend = c
		w.be.pauseBackendRead(c)
	}
}

// tunnelToBackend relays whatever the client has buffered to the backend.
func (w *epollWorker) tunnelToBackend(cc *epollConn) {
	c := cc.tunnelBE
	if c == nil || c.state == connClosed {
		cc.closeAfter = true
		return
	}
	if cc.readN > cc.h1Off {
		c.wbuf.write(cc.readBuf[cc.h1Off:cc.readN])
		cc.readN = 0
		cc.h1Off = 0
		w.be.flushWrites(c)
	}
	if c.state != connClosed && c.wbuf.length() > proxyStreamHighWater {
		cc.tunnelPaused = true
	}
}

func (w *epollWorker) resumeTunnelIfDrained(c *backendConn) {
	cc := c.tunnelClient
	if cc == nil || !cc.tunnelPaused || cc.fd < 0 || c.wbuf.length() > proxyStreamLowWater {
		return
	}
	cc.tunnelPaused = false
	if cc.readPending {
		w.readable(cc, false)
	}
}

// closeTunnelPeer tears down the client half when the backend end goes away.
func (w *epollWorker) closeTunnelPeer(c *backendConn) {
	cc := c.tunnelClient
	c.tunnelClient = nil
	if cc == nil {
		return
	}
	cc.tunnelBE = nil
	cc.pausedBackend = nil
	cc.tunnelPaused = false
	if cc.fd >= 0 {
		cc.closeAfter = true
		w.flush(cc)
	}
}

// closeTunnelFromClient drops the backend half when the client disconnects.
func (w *epollWorker) closeTunnelFromClient(cc *epollConn) {
	c := cc.tunnelBE
	cc.tunnelBE = nil
	cc.pausedBackend = nil
	cc.tunnelPaused = false
	if c == nil {
		return
	}
	c.tunnelClient = nil
	if c.state != connClosed {
		w.be.closeConn(c, errFPClientClosed)
	}
}
