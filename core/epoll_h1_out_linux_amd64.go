//go:build linux && amd64

package core

import (
	"strconv"
	"sync"
)

const (
	h1ProgressiveBodyThreshold = 512 << 10
	h1OutSocketHighMark        = 1 << 20
	h1StreamPendingCap         = 256 << 10
	h1StreamPendingKeep        = 2 * h1StreamPendingCap
	h1NoContentLength          = -1
)

var epollH1StreamWriterPool sync.Pool

func init() { epollH1StreamWriterPool.New = newEpollH1StreamWriter }

func newEpollH1StreamWriter() any {
	sw := &epollH1StreamWriter{contentLength: h1NoContentLength}
	sw.space = sync.NewCond(&sw.mu)
	sw.pumpFn = func(w *epollWorker) { sw.c.h1StreamPumpTask(w, sw) }
	return sw
}

type epollH1StreamWriter struct {
	mu     sync.Mutex
	space  *sync.Cond
	pumpFn func(*epollWorker)

	c          *epollConn
	w          *epollWorker
	gen        uint32
	method     string
	serverName string
	altSvc     *altSvcHeader
	reqClose   bool
	limiter    *ConnectionLimiter
	global     *GlobalLimiter
	maxWrite   int64
	written    int64
	cors       streamCORSHead

	headerCalled  bool
	suppressBody  bool
	chunked       bool
	contentLength int64
	bodyBytes     int64
	mustClose     bool

	pending     []byte
	pendingOff  int
	headerReady bool
	ended       bool
	finished    bool
	handlerDone bool
	pumpQueued  bool
	err         error
}

func (c *epollConn) newStreamWriter(req *Request) StreamWriter {
	if req.h2Stream != nil {
		return c.newH2StreamWriter(req)
	}
	return c.newH1StreamWriter(req)
}

func (c *epollConn) newH1StreamWriter(req *Request) StreamWriter {
	srv := c.worker.server
	sw := epollH1StreamWriterPool.Get().(*epollH1StreamWriter)
	sw.c, sw.w, sw.gen = c, c.worker, c.h1DispatchGen
	sw.method = req.Method
	sw.serverName = srv.config.ServerName
	sw.altSvc = srv.altSvcFor(req.IsTLS)
	sw.reqClose = c.h1DispatchClose
	sw.limiter, sw.global = c.connLimiter, srv.globalLimiter
	sw.maxWrite = srv.config.MaxWriteSize
	sw.cors.bind(req)
	return sw
}

func (sw *epollH1StreamWriter) WriteHeader(statusCode int, headers [][2]string, contentType string) error {
	if sw.headerCalled {
		return nil
	}
	sw.headerCalled = true
	headers = sw.cors.withCORS(headers)
	sw.suppressBody, _ = responseBodyDisposition(sw.method, statusCode)
	sw.chunked, _ = classifyH1StreamHeaders(headers)
	declared, connClose := scanH1StreamHeaders(headers)
	if sw.suppressBody {
		sw.chunked = false
	} else if !sw.chunked {
		sw.contentLength = declared
	}
	sw.mustClose = connClose || (!sw.suppressBody && !sw.chunked && sw.contentLength == h1NoContentLength)

	sw.mu.Lock()
	sw.pending = appendH1StreamHead(sw.pending, statusCode, headers, contentType, sw.chunked, sw.reqClose || sw.mustClose, sw.serverName, sw.altSvc)
	sw.headerReady = true
	err := sw.err
	queue := sw.claimPumpLocked()
	sw.mu.Unlock()
	if queue {
		sw.w.postTask(sw.pumpFn)
	}
	return err
}

func scanH1StreamHeaders(headers [][2]string) (contentLength int64, connClose bool) {
	contentLength = h1NoContentLength
	for i := range headers {
		switch {
		case EqualFoldASCII(headers[i][0], "content-length"):
			if n, err := strconv.ParseInt(headers[i][1], 10, 64); err == nil && n >= 0 {
				contentLength = n
			}
		case EqualFoldASCII(headers[i][0], "connection"):
			connClose = EqualFoldASCII(headers[i][1], "close")
		}
	}
	return contentLength, connClose
}

func (sw *epollH1StreamWriter) WriteChunk(data []byte) error {
	if !sw.headerCalled {
		return ErrStreamClosed
	}
	if sw.suppressBody {
		return nil
	}
	if sw.maxWrite > 0 {
		sw.written += int64(len(data))
		if sw.written > sw.maxWrite {
			sw.mustClose = true
			return ErrBodyTooLarge
		}
	}
	if sw.contentLength != h1NoContentLength && sw.bodyBytes+int64(len(data)) > sw.contentLength {
		sw.mustClose = true
		return ErrBodyTooLarge
	}
	sw.bodyBytes += int64(len(data))
	if sw.limiter != nil {
		sw.limiter.ThrottleDownload(int64(len(data)))
	}
	if sw.global != nil && sw.global.Download != nil {
		sw.global.Download.Wait(int64(len(data)))
	}
	for len(data) > 0 {
		sw.mu.Lock()
		for sw.err == nil && !sw.ended && sw.bufferedLocked() >= h1StreamPendingCap {
			sw.space.Wait()
		}
		if sw.err != nil {
			err := sw.err
			sw.mu.Unlock()
			return err
		}
		if sw.ended {
			sw.mu.Unlock()
			return ErrStreamClosed
		}
		n := min(len(data), h1StreamPendingCap-sw.bufferedLocked())
		if sw.chunked {
			sw.pending = appendH1Chunk(sw.pending, data[:n])
		} else {
			sw.pending = append(sw.pending, data[:n]...)
		}
		data = data[n:]
		queue := sw.claimPumpLocked()
		sw.mu.Unlock()
		if queue {
			sw.w.postTask(sw.pumpFn)
		}
	}
	return nil
}

func (sw *epollH1StreamWriter) Flush() error {
	sw.mu.Lock()
	err := sw.err
	queue := sw.claimPumpLocked()
	sw.mu.Unlock()
	if queue {
		sw.w.postTask(sw.pumpFn)
	}
	return err
}

func (sw *epollH1StreamWriter) Close() error {
	sw.mu.Lock()
	err := sw.endLocked()
	queue := sw.claimPumpLocked()
	sw.mu.Unlock()
	if queue {
		sw.w.postTask(sw.pumpFn)
	}
	return err
}

func (sw *epollH1StreamWriter) endLocked() error {
	if !sw.ended {
		sw.ended = true
		if sw.chunked && sw.headerReady {
			sw.pending = append(sw.pending, h1LastChunk...)
		}
	}
	return sw.err
}

func (sw *epollH1StreamWriter) bufferedLocked() int { return len(sw.pending) - sw.pendingOff }

func (sw *epollH1StreamWriter) claimPumpLocked() bool {
	if sw.pumpQueued || sw.finished {
		return false
	}
	sw.pumpQueued = true
	return true
}

func (sw *epollH1StreamWriter) framingComplete() bool {
	return sw.contentLength == h1NoContentLength || sw.bodyBytes == sw.contentLength
}

func (sw *epollH1StreamWriter) fail(err error) {
	sw.mu.Lock()
	if sw.err == nil {
		sw.err = err
	}
	sw.finished = true
	sw.space.Broadcast()
	sw.mu.Unlock()
}

func (sw *epollH1StreamWriter) release() {
	sw.c, sw.w, sw.gen = nil, nil, 0
	sw.method, sw.serverName, sw.altSvc = "", "", nil
	sw.reqClose = false
	sw.limiter, sw.global = nil, nil
	sw.maxWrite, sw.written = 0, 0
	sw.cors.reset()
	sw.headerCalled, sw.suppressBody, sw.chunked, sw.mustClose = false, false, false, false
	sw.contentLength, sw.bodyBytes = h1NoContentLength, 0
	if cap(sw.pending) > h1StreamPendingKeep {
		sw.pending = nil
	} else {
		sw.pending = sw.pending[:0]
	}
	sw.pendingOff = 0
	sw.headerReady, sw.ended, sw.finished, sw.handlerDone, sw.pumpQueued = false, false, false, false, false
	sw.err = nil
	epollH1StreamWriterPool.Put(sw)
}

func (c *epollConn) h1StreamPumpTask(w *epollWorker, sw *epollH1StreamWriter) {
	sw.mu.Lock()
	sw.pumpQueued = false
	sw.mu.Unlock()
	if c.generation != sw.gen || c.fd < 0 {
		sw.fail(ErrStreamClosed)
		return
	}
	c.h1Stream = sw
	c.h1PumpOut(w)
	w.markFlush(c)
}

func (c *epollConn) emitH1(data []byte) {
	if c.tls {
		c.writeBuf = c.sealTLSAppData(c.writeBuf, data)
		return
	}
	c.writeBuf = append(c.writeBuf, data...)
}

func (c *epollConn) h1OutRoom() int {
	return h1OutSocketHighMark - (len(c.writeBuf) - c.writeSent)
}

func (c *epollConn) h1PumpOut(w *epollWorker) bool {
	before := len(c.writeBuf)
	switch {
	case c.h1Body != nil:
		c.h1PumpBody()
	case c.h1Stream != nil:
		c.h1PumpStream(c.h1Stream)
	default:
		return false
	}
	if c.h1OutComplete {
		c.h1OutComplete = false
		c.h1FinishOut(w)
	}
	return len(c.writeBuf) > before
}

func (c *epollConn) h1PumpBody() {
	room := c.h1OutRoom()
	if room <= 0 {
		return
	}
	n := min(room, len(c.h1Body)-c.h1BodyOff)
	c.emitH1(c.h1Body[c.h1BodyOff : c.h1BodyOff+n])
	c.h1BodyOff += n
	if c.h1BodyOff == len(c.h1Body) {
		c.h1Body, c.h1BodyOff = nil, 0
		c.h1OutComplete = true
	}
}

func (c *epollConn) h1PumpStream(sw *epollH1StreamWriter) {
	sw.mu.Lock()
	if sw.finished {
		sw.mu.Unlock()
		return
	}
	if room := c.h1OutRoom(); room > 0 && sw.bufferedLocked() > 0 {
		n := min(room, sw.bufferedLocked())
		c.emitH1(sw.pending[sw.pendingOff : sw.pendingOff+n])
		sw.pendingOff += n
	}
	switch {
	case sw.bufferedLocked() == 0:
		sw.pending, sw.pendingOff = sw.pending[:0], 0
	case sw.pendingOff > len(sw.pending)/2:
		rest := copy(sw.pending, sw.pending[sw.pendingOff:])
		sw.pending, sw.pendingOff = sw.pending[:rest], 0
	}
	done := sw.handlerDone && sw.ended && sw.bufferedLocked() == 0
	if done {
		sw.finished = true
	}
	sw.space.Broadcast()
	sw.mu.Unlock()
	if done {
		c.h1OutComplete = true
	}
}

func (c *epollConn) h1FinishOut(w *epollWorker) {
	keepAlive := c.h1OutKeepAlive
	if sw := c.h1Stream; sw != nil {
		c.h1Stream = nil
		sw.release()
	}
	c.dispatching = false
	if keepAlive {
		c.h1ResumeDue = true
	} else {
		c.closeAfter = true
	}
	w.markFlush(c)
}

func (c *epollConn) h1LargeBody() bool {
	return c.resp.transmittedBodyLen() > h1ProgressiveBodyThreshold
}

func (c *epollConn) h1StartProgressiveBody(w *epollWorker, keepAlive bool) {
	if c.tls {
		addAltSvcHeader(&c.resp, w.server)
		head := appendPlainResponseMode(&c.resp, c.plainBuf[:0], keepAlive, false)
		c.writeBuf = c.sealTLSAppData(c.writeBuf, head)
		c.plainBuf = head[:0]
	} else {
		c.writeBuf = appendPlainResponseMode(&c.resp, c.writeBuf, keepAlive, false)
	}
	c.dispatching = true
	c.h1Body, c.h1BodyOff = c.resp.transmittedBodyBytes(), 0
	c.h1OutKeepAlive = keepAlive
	c.h1PumpOut(w)
	w.markFlush(c)
}

func (c *epollConn) h1FinishStreamed(w *epollWorker, sw *epollH1StreamWriter, keepAlive bool) {
	sw.mu.Lock()
	sw.handlerDone = true
	_ = sw.endLocked()
	sw.mu.Unlock()
	c.dispatching = true
	c.h1Stream = sw
	c.h1OutKeepAlive = keepAlive && !sw.reqClose && !sw.mustClose && sw.framingComplete()
	c.h1PumpOut(w)
	w.markFlush(c)
}

func (c *epollConn) h1AbortOut() {
	if sw := c.h1Stream; sw != nil {
		c.h1Stream = nil
		sw.fail(ErrStreamClosed)
		if sw.handlerDone {
			sw.release()
		}
	}
	c.h1Body, c.h1BodyOff = nil, 0
	c.h1OutKeepAlive, c.h1OutComplete, c.h1ResumeDue = false, false, false
}
