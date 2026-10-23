//go:build linux && amd64

package core

// HTTP/2 inbound proxying runs in the worker loop like the HTTP/1.1 path, so a
// proxied stream no longer parks a goroutine on the backend.
//
// The response stays buffered rather than being relayed frame by frame. That is
// not a shortcut taken here: the HTTP/2 backend has never supported streamed
// responses (finishH2Dispatch rejects resp.IsStreamed with a 500), and it
// already frames a completed response out under flow control with its own
// stalling. Buffering therefore matches the existing capability exactly, and the
// window logic in h2AppendWindowed continues to own backpressure toward the
// client.

// beginProxyH2 serves an HTTP/2 stream from the proxy engine inside the event
// loop. It returns proxyStartServed when stream.resp already holds the answer
// (cache hit or an error), or proxyStartPending when a backend exchange is in
// flight and will finish the stream later.
func (w *epollWorker) beginProxyH2(pe *ProxyEngine, ds *domainState, c *epollConn, stream *H2Stream, streamID uint32) int {
	req := &stream.req
	host := stripPort(req.Host)
	cacheableMethod := req.Method == "GET" || req.Method == "HEAD"
	reqCacheOK := false
	cachePath := ""

	admission, outcome := w.admitProxyRequest(req, &stream.resp)
	if outcome != proxyAdmitted {
		return outcome.startResult()
	}
	if pe.hasHooks() {
		promoteRequestStrings(req)
	}

	cache := pe.activeCache()
	if cache != nil && cacheableMethod {
		reqCacheOK = proxyCacheRequestAllowed(req)
		cachePath = proxyRequestTarget(req)
		if entry, hit := cache.GetFP(req.Method, host, cachePath, reqCacheOK); hit {
			admission.release(w.server)
			w.serveProxyCacheHit(pe, ds, cache, entry, req, &stream.resp)
			return proxyStartServed
		}
	}

	if len(ds.backends) == 0 {
		admission.release(w.server)
		proxyRefusedNoBackend.answer(&stream.resp)
		return proxyStartServed
	}

	px := w.pxGet()
	px.admission = admission
	px.w = w
	px.c = c
	px.cGen = c.generation
	px.pe = pe
	px.ds = ds
	px.method = req.Method
	px.path = req.Path
	px.clientAddr = req.RemoteAddr
	px.mayCache = cache != nil && cacheableMethod && (reqCacheOK || pe.responseHook() != nil)
	px.reqCacheOK = reqCacheOK
	px.cacheHost = host
	px.cacheKey = cachePath
	px.cacheGen = cache.purgeGeneration()
	px.cache = cache
	// HTTP/2 has no per-request connection reuse decision; the stream ends and
	// the connection carries on.
	px.keepClient = true
	px.h2Stream = stream
	px.h2StreamID = streamID
	for len(px.tried) < len(ds.backends) {
		px.tried = append(px.tried, false)
	}

	if r := w.proxyAttempt(px); r.status != 0 {
		w.proxyFailStream(px, r.status, r.msg)
		return proxyStartServed
	}
	return proxyStartPending
}

// proxyFailStream answers the stream with an error and releases the exchange.
func (w *epollWorker) proxyFailStream(px *proxyExchange, status int, msg string) {
	if stream := px.h2Stream; stream != nil {
		stream.resp.Reset()
		stream.resp.Status(status).String(msg)
	}
	w.pxPut(px)
}

// proxyRetryOrFailH2 fails over to another backend, or gives up and answers the
// stream. An HTTP/2 response is buffered, so a retry is always possible.
func (w *epollWorker) proxyRetryOrFailH2(px *proxyExchange, err error) {
	w.proxyRecordFailure(px, err)
	if px.h2Stream == nil {
		w.pxPut(px)
		return
	}
	if r := w.proxyRetry(px, err); r.status != 0 {
		w.proxyRefuse(px, r)
	}
}

// finishProxyStream fills the stream's response and hands it to the HTTP/2
// framing path, which applies flow control on the way out.
func (w *epollWorker) finishProxyStream(px *proxyExchange, status int, headers respHeaders, body []byte, contentType string) {
	stream := px.h2Stream
	c := px.c
	streamID := px.h2StreamID
	gen := px.cGen
	// SetHeader stores strings, so this path materialises before pxPut releases
	// the exchange.
	hdrs := w.headerStrings(headers)
	w.pxPut(px)

	if stream == nil {
		return
	}
	stream.resp.Reset()
	stream.resp.Status(status)
	// Bytes sets ContentType to application/octet-stream, so the body goes in
	// first and the real content type is applied afterwards.
	stream.resp.Bytes(body)
	upstreamType := contentType
	for _, h := range hdrs {
		if isHopByHopStr(h[0]) || headerNameIs(h[0], "content-length") {
			continue
		}
		if headerNameIs(h[0], "content-type") {
			if upstreamType == "" {
				upstreamType = h[1]
			}
			continue
		}
		stream.resp.SetHeader(h[0], h[1])
	}
	if upstreamType != "" {
		stream.resp.ContentType = upstreamType
	}

	if c == nil {
		return
	}
	alive := c.generation == gen && c.fd >= 0
	c.finishH2Dispatch(w, gen, streamID, stream)
	if !alive {
		return
	}
	// finishH2Dispatch only marks the connection for flushing, and flushPending
	// runs solely when a task was posted. The goroutine path always posted one;
	// this path posts nothing, so the write has to be issued here or the framed
	// response sits in the buffer until unrelated activity happens to drain it.
	w.flush(c)
}

// abortProxyStream releases a stream-bound exchange whose connection died.
func (w *epollWorker) abortProxyStream(px *proxyExchange) {
	px.h2Stream = nil
	px.c = nil
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
		px.b = nil
	}
}

var (
	proxyH2ConnBufferBudget   int64 = 64 << 20
	proxyH2ServerBufferBudget int64 = 512 << 20
)

var (
	proxyRefusedBufferFull = proxyRefusal{503, "Proxy response buffer exhausted"}
	proxyRefusedTooLarge   = proxyRefusal{502, "Upstream response too large"}
)

func (w *epollWorker) admitH2Response(px *proxyExchange, contentLen int64) bool {
	px.h2Expected = contentLen
	switch {
	case contentLen > int64(w.beCfg.MaxResponseBody):
		px.refusal = proxyRefusedTooLarge
	case contentLen >= 0 && !px.reserveResponseBuffer(contentLen):
		px.refusal = proxyRefusedBufferFull
	case contentLen >= 0 && (contentLen <= proxyBufferedResponseLimit ||
		px.mayCache && contentLen <= px.cache.maxCacheableSize()):
		return false
	}
	px.h2Streamed = true
	return true
}

func (w *epollWorker) bufferH2Chunk(c *backendConn, px *proxyExchange, data []byte) {
	if px.h2Expected < 0 {
		if len(px.h2Body)+len(data) > w.beCfg.MaxResponseBody {
			w.refuseResponse(c, px, proxyRefusedTooLarge)
			return
		}
		if !px.reserveResponseBuffer(int64(len(data))) {
			w.refuseResponse(c, px, proxyRefusedBufferFull)
			return
		}
	}
	px.h2Body = append(px.h2Body, data...)
}

func (w *epollWorker) refuseResponse(c *backendConn, px *proxyExchange, r proxyRefusal) {
	px.refusal = r
	w.be.closeConn(c, errFPClientClosed)
}

func (px *proxyExchange) reserveResponseBuffer(n int64) bool {
	c := px.c
	if c.h2ProxyBuffered+n > proxyH2ConnBufferBudget {
		return false
	}
	if px.pe.h2Buffered.Add(n) > proxyH2ServerBufferBudget {
		px.pe.h2Buffered.Add(-n)
		return false
	}
	c.h2ProxyBuffered += n
	px.h2Reserved += n
	return true
}

func (px *proxyExchange) discardH2Buffer() {
	px.h2Body = px.h2Body[:0]
	px.h2Expected = 0
	px.refusal = proxyRefusal{}
	px.h2Streamed = false
	if px.h2Reserved == 0 {
		return
	}
	if px.c != nil {
		px.c.h2ProxyBuffered -= px.h2Reserved
	}
	px.pe.h2Buffered.Add(-px.h2Reserved)
	px.h2Reserved = 0
}
