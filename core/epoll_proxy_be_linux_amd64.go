//go:build linux && amd64

package core

import (
	"golang.org/x/sys/unix"
)

// The epoll worker owns the client socket of every connection it accepts. It
// also hosts a beLoop bound to its own epoll fd, so the backend socket of a
// proxied request lives in the same event loop as the client it answers. One
// thread then drives the whole exchange with no cross-loop handoff.

// initBackendLoop binds the worker's backend engine to the worker's own epoll
// fd. Loop counts are meaningless here because the worker is the loop, so only
// the pool and timeout settings are filled in.
func (w *epollWorker) initBackendLoop() {
	w.beCfg.Loops = 1
	w.beCfg.LoopsPerOrigin = 1
	w.beCfg.fill(1)
	w.be.init(w.epfd, &w.beCfg, w)
	w.be.panicReporter = w.server
}

// backendEvent dispatches an epoll event that carries the backend class tag.
func (w *epollWorker) backendEvent(fd int, evs uint32) {
	if fd < 0 || fd >= len(w.be.conns) {
		return
	}
	c := w.be.conns[fd]
	if c == nil || c.state == connClosed || w.be.staleInBatch(c) {
		return
	}
	if evs&unix.EPOLLERR != 0 {
		err := socketError(c.fd)
		if err == nil {
			err = errFPConnClosed
		}
		if c.state == connConnecting {
			err = errFPDialFailed
		}
		w.be.closeConn(c, err)
		return
	}
	if c.state == connConnecting && evs&(unix.EPOLLOUT|unix.EPOLLHUP) != 0 {
		w.be.onConnConnected(c)
		if c.state == connClosed {
			return
		}
	}
	if evs&(unix.EPOLLIN|unix.EPOLLRDHUP|unix.EPOLLHUP) != 0 {
		w.be.readableUntil(c, evs&(unix.EPOLLRDHUP|unix.EPOLLHUP) != 0)
		if c.state == connClosed {
			return
		}
	}
	if evs&unix.EPOLLOUT != 0 && c.wbuf.length() > 0 {
		w.be.flushWrites(c)
		w.resumeTunnelIfDrained(c)
	}
}

// resumeRelayIfDrained re-arms a backend read side that was disarmed because
// this client could not keep up with a relayed response.
func (w *epollWorker) resumeRelayIfDrained(c *epollConn) {
	bc := c.pausedBackend
	if bc == nil {
		return
	}
	if len(c.writeBuf)-c.writeSent > proxyStreamLowWater {
		return
	}
	c.pausedBackend = nil
	if bc.state != connClosed {
		w.be.resumeBackendRead(bc)
	}
}

// abortProxyExchange drops an in-flight exchange when its client goes away, so
// the backend socket is not left relaying into a closed connection.
func (w *epollWorker) abortProxyExchange(c *epollConn) {
	px := c.proxyEx
	if px == nil {
		return
	}
	c.proxyEx = nil
	if px.h2Stream != nil {
		w.abortProxyStream(px)
	} else if c.inFlight > 0 {
		c.inFlight--
	}
	px.c = nil
	if bc := c.pausedBackend; bc != nil {
		c.pausedBackend = nil
		if bc.state != connClosed {
			w.be.resumeBackendRead(bc)
		}
	}
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
		px.b = nil
	}
	if bc := px.Exchange.bc; bc != nil && bc.cur == &px.Exchange {
		w.be.closeConn(bc, errFPClientClosed)
		return
	}
	w.pxPut(px)
}

func (w *epollWorker) exPut(ex *Exchange) {
	req := ex.req
	*req = fpRequest{}
	*ex = Exchange{req: req}
	ex.pnext = w.exFree
	w.exFree = ex
}

// onForwardDone only fires for exchanges carrying an inConn, which belong to
// the standalone event loop. Worker-hosted exchanges never set one.

// exchangeDone delivers a fully buffered upstream response to the client. It is
// the terminal callback for exchanges that carry neither an inConn nor a done
// channel, which is exactly those created by beginProxy.
func (w *epollWorker) exchangeDone(ex *Exchange) {
	px := proxyExchangeOf(ex)
	if px.w != w {
		w.exPut(ex)
		return
	}
	if px.starting {
		return
	}
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
	}
	if px.refusal.status != 0 {
		px.b = nil
		w.proxyRefuse(px, px.refusal)
		return
	}
	if ex.err != nil {
		if px.h2Stream != nil {
			w.proxyRetryOrFailH2(px, ex.err)
		} else {
			w.proxyRetryOrFail(px, ex.err)
		}
		return
	}
	if px.streaming {
		w.proxyEndStream(px)
		return
	}
	body := ex.resp.Body
	if px.h2Streamed {
		body = px.h2Body
	}
	status, headers, hooked, hookOK := w.applyResponseHook(px, ex.resp.Status, ex.resp.headers())
	if !hookOK {
		px.b = nil
		w.proxyRefuse(px, proxyRefusedHookFailed)
		return
	}
	if px.cache != nil {
		w.proxyMaybeCache(px, status, headers, body, hooked)
	}
	if px.b != nil {
		px.ds.outlier.recordStatus(px.b, ex.resp.Status)
		px.b = nil
	}
	if px.h2Stream != nil {
		w.finishProxyStream(px, status, headers, body, "")
		return
	}
	w.proxyFinishClient(px, status, headers, body, "")
}

// shouldStreamResponse keeps small, known-length responses buffered so a failed
// attempt can still be retried and the cache has a body to store. Anything
// larger, or of unknown length, is relayed as it arrives.
func (w *epollWorker) shouldStreamResponse(c *backendConn, contentLen int64) bool {
	if c.cur == nil {
		return false
	}
	px := proxyExchangeOf(c.cur)
	if px.h2Stream != nil {
		return w.admitH2Response(px, contentLen)
	}
	// A response of unknown length has to be relayed; there is no way to know
	// whether it would ever fit anywhere.
	if contentLen < 0 {
		return true
	}
	// A cacheable response that the cache would accept is buffered so it can
	// actually be stored. Without this a CDN silently stops caching everything
	// above the buffering threshold, which is the opposite of what it wants.
	if px.mayCache && contentLen <= px.cache.maxCacheableSize() {
		return false
	}
	return contentLen > proxyBufferedResponseLimit
}

// beginStreamResponse emits the response head and switches the exchange to
// relaying body bytes straight into the client's write buffer.
func (w *epollWorker) beginStreamResponse(c *backendConn, p *h1Parser, contentLen int64) {
	ex := c.cur
	if ex == nil {
		return
	}
	px := proxyExchangeOf(ex)
	if px.h2Stream != nil {
		if r := px.refusal; r.status != 0 {
			w.refuseResponse(c, px, r)
		}
		return
	}
	cc := px.c
	if cc == nil || cc.generation != px.cGen || cc.fd < 0 {
		return
	}
	status, headers, _, hookOK := w.applyResponseHook(px, p.status, respHeaders{raw: p.hdr})
	if !hookOK {
		w.refuseResponse(c, px, proxyRefusedHookFailed)
		return
	}

	if !cc.tls {
		cc.writeBuf = appendProxyStreamHead(cc.writeBuf, status, headers, contentLen, px.keepClient)
	} else {
		scratch := w.beScratch[:0]
		scratch = appendProxyStreamHead(scratch, status, headers, contentLen, px.keepClient)
		w.beScratch = scratch[:0]
		cc.writeBuf = cc.sealTLSAppData(cc.writeBuf, scratch)
	}

	px.streaming = true
	px.streamChunked = contentLen < 0
	px.headersOut = true
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
		px.ds.outlier.recordStatus(px.b, p.status)
		px.b = nil
	}
	w.flush(cc)
}

// streamResponseChunk relays one body chunk and applies backpressure: when the
// client falls behind, the backend read side is disarmed until it catches up.
func (w *epollWorker) streamResponseChunk(c *backendConn, data []byte) {
	ex := c.cur
	if ex == nil {
		return
	}
	px := proxyExchangeOf(ex)
	if px.h2Stream != nil {
		w.bufferH2Chunk(c, px, data)
		return
	}
	cc := px.c
	if cc == nil || cc.generation != px.cGen || cc.fd < 0 {
		w.be.closeConn(c, errFPClientClosed)
		return
	}
	if px.streamChunked {
		scratch := w.beScratch[:0]
		scratch = appendChunkFrame(scratch, data)
		w.beScratch = scratch[:0]
		w.clientAppend(cc, scratch)
	} else {
		w.clientAppend(cc, data)
	}
	w.flush(cc)
	if cc.fd >= 0 && len(cc.writeBuf)-cc.writeSent > proxyStreamHighWater && cc.pausedBackend == nil {
		cc.pausedBackend = c
		w.be.pauseBackendRead(c)
	}
}

// endStreamResponse is the completion callback for a streamed response.
func (w *epollWorker) endStreamResponse(ex *Exchange) {
	px := proxyExchangeOf(ex)
	if px.h2Stream != nil {
		w.exchangeDone(ex)
		return
	}
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
		px.b = nil
	}
	w.proxyEndStream(px)
}

func (w *epollWorker) proxyEndStream(px *proxyExchange) {
	cc := px.c
	if cc == nil || cc.generation != px.cGen || cc.fd < 0 {
		w.pxPut(px)
		return
	}
	if px.streamChunked {
		w.clientAppend(cc, []byte("0\r\n\r\n"))
	}
	cc.proxyEx = nil
	cc.dispatching = false
	cc.releaseH1BodyBudget()
	if cc.inFlight > 0 {
		cc.inFlight--
	}
	if cc.pausedBackend != nil {
		cc.pausedBackend = nil
	}
	if !px.keepClient {
		cc.closeAfter = true
	}
	w.pxPut(px)
	w.proxyResume(cc)
}

// applyResponseHook lets OnResponse observe and rewrite a live upstream
// response, which previously only ran for cache hits.
func (w *epollWorker) applyResponseHook(px *proxyExchange, status int, headers respHeaders) (int, respHeaders, *ProxyResponse, bool) {
	var onResponse ProxyResponseFunc
	if px.pe != nil {
		onResponse = px.pe.responseHook()
	}
	if onResponse == nil {
		return status, headers, nil, true
	}
	// A hook is handed real strings and may keep or rewrite them, so its result
	// travels onwards in string form.
	hook := &proxyHookResponse{}
	pr := &hook.ProxyResponse
	pr.Domain = px.ds.config.Domain
	pr.Backend = px.backendAddr()
	pr.ClientAddr = px.clientAddr
	pr.Method = px.method
	pr.Path = px.path
	pr.StatusCode = status
	pr.Headers = append(hook.headers[:0], w.headerStrings(headers)...)
	if !w.guardUserHook(nil, func() { onResponse(pr) }) {
		return status, headers, nil, false
	}
	return pr.StatusCode, respHeaders{str: pr.Headers}, pr, true
}

func (w *epollWorker) proxyRefuse(px *proxyExchange, r proxyRefusal) {
	if px.h2Stream != nil {
		w.finishProxyStream(px, r.status, respHeaders{}, []byte(r.msg), "")
		return
	}
	w.proxyFinishClient(px, r.status, respHeaders{}, []byte(r.msg), "text/plain; charset=utf-8")
}

func (px *proxyExchange) backendAddr() string {
	if px.b == nil {
		return ""
	}
	return px.b.Addr
}
