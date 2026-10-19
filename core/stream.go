//go:build linux && amd64

package core

import (
	"net"
)

func classifyH1StreamHeaders(headers [][2]string) (bool, bool) {
	chunked := true
	hasConnection := false
	for i := range headers {
		if EqualFoldASCII(headers[i][0], "connection") {
			hasConnection = true
			continue
		}
		if EqualFoldASCII(headers[i][0], "transfer-encoding") {
			chunked = EqualFoldASCII(headers[i][1], "chunked")
			continue
		}
		if EqualFoldASCII(headers[i][0], "content-length") {
			chunked = false
		}
	}
	return chunked, hasConnection
}

func appendH1StreamHead(buf []byte, statusCode int, headers [][2]string, contentType string, chunked, closeAfter bool, serverName string, altSvc *altSvcHeader) []byte {
	buf = appendStatusLine(buf, statusCode)
	if contentType != "" {
		buf = appendContentTypeHeader(buf, contentType)
	}
	if chunked {
		buf = append(buf, "Transfer-Encoding: chunked\r\n"...)
	}
	hasConnection := false
	hasServer := false
	for i := range headers {
		if EqualFoldASCII(headers[i][0], "connection") {
			hasConnection = true
		}
		if EqualFoldASCII(headers[i][0], "server") {
			hasServer = true
		}
		if altSvc != nil && EqualFoldASCII(headers[i][0], altSvcHeaderName) {
			altSvc = nil
		}
		buf = append(buf, headers[i][0]...)
		buf = append(buf, ':', ' ')
		buf = append(buf, headers[i][1]...)
		buf = append(buf, '\r', '\n')
	}
	if !hasConnection {
		if closeAfter {
			buf = append(buf, "Connection: close\r\n"...)
		} else {
			buf = append(buf, "Connection: keep-alive\r\n"...)
		}
	}
	if !hasServer {
		buf = append(buf, "Server: "...)
		buf = append(buf, serverName...)
		buf = append(buf, '\r', '\n')
	}
	if altSvc != nil {
		buf = append(buf, altSvc.h1...)
	}
	return append(buf, '\r', '\n')
}

const h1LastChunk = "0\r\n\r\n"

func appendH1Chunk(buf, data []byte) []byte {
	var sizeBuf [16]byte
	buf = append(buf, appendHex(sizeBuf[:0], int64(len(data)))...)
	buf = append(buf, '\r', '\n')
	buf = append(buf, data...)
	return append(buf, '\r', '\n')
}

func releaseStreamWriter(sw StreamWriter) {
	switch writer := sw.(type) {
	case *H1StreamWriter:
		H1StreamWriterPool.Put(writer)
	case *PlainH1StreamWriter:
		PlainH1StreamWriterPool.Put(writer)
	}
}

func bindRequestToStreamWriter(sw StreamWriter, req *Request) {
	switch writer := sw.(type) {
	case *H1StreamWriter:
		writer.method = req.Method
		writer.suppressBody = false
		writer.cors.bind(req)
	case *PlainH1StreamWriter:
		writer.method = req.Method
		writer.suppressBody = false
		writer.cors.bind(req)
	}
}

const corsMaxResponseHeaders = 7

type streamCORSPolicy struct {
	engine *CORSEngine
	snap   *corsSnapshot
}

type streamCORSHead struct {
	policy streamCORSPolicy
	origin string
}

func (h *streamCORSHead) bind(req *Request) {
	if req.streamCORS.snap != nil {
		h.capture(req)
	}
}

func (h *streamCORSHead) capture(req *Request) {
	h.policy = req.streamCORS
	h.origin = req.Header("origin")
}

func (h *streamCORSHead) reset() {
	if h.policy.snap != nil {
		*h = streamCORSHead{}
	}
}

func (h *streamCORSHead) withCORS(headers [][2]string) [][2]string {
	if h.policy.snap == nil {
		return headers
	}
	return h.mergeInto(headers)
}

func (h *streamCORSHead) mergeInto(headers [][2]string) [][2]string {
	head := Response{Headers: make([][2]string, len(headers), len(headers)+corsMaxResponseHeaders)}
	copy(head.Headers, headers)
	originOnly := Request{cachedOrigin: h.origin, headerCacheMask: headerCacheOrigin}
	h.policy.engine.applyCORS(h.policy.snap, &originOnly, &head)
	return head.Headers
}

// H1StreamWriter writes an HTTP/1.1 response over an encrypted (TLS)
// connection, using chunked Transfer-Encoding unless the response declares
// Content-Length or has no body. It implements StreamWriter.
type H1StreamWriter struct {
	conn         net.Conn
	writer       *TrafficAEAD
	limiter      *ConnectionLimiter
	global       *GlobalLimiter
	method       string
	serverName   string
	altSvc       *altSvcHeader
	written      int64
	maxWrite     int64
	headersSent  bool
	chunked      bool
	suppressBody bool
	closeAfter   bool
	cors         streamCORSHead
}

// WriteHeader writes the HTTP/1.1 status line and headers, selecting chunked
// Transfer-Encoding unless a Content-Length header is present or the response
// has no body. Later calls are no-ops.
func (w *H1StreamWriter) WriteHeader(statusCode int, headers [][2]string, contentType string) error {
	if w.headersSent {
		return nil
	}
	w.headersSent = true
	headers = w.cors.withCORS(headers)
	w.suppressBody, _ = responseBodyDisposition(w.method, statusCode)
	w.chunked, _ = classifyH1StreamHeaders(headers)
	if w.suppressBody {
		w.chunked = false
	}

	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]

	buf = appendH1StreamHead(buf, statusCode, headers, contentType, w.chunked, w.closeAfter, w.serverName, w.altSvc)

	err := w.writeEncrypted(buf)
	*bp = buf
	putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
	return err
}

// WriteChunk writes data to the client, chunk-encoding it when the response
// uses chunked Transfer-Encoding or writing it directly when Content-Length
// was set. It applies any configured download rate limit and returns
// ErrBodyTooLarge if a maximum response size was set and is exceeded.
func (w *H1StreamWriter) WriteChunk(data []byte) error {
	if !w.headersSent {
		return ErrStreamClosed
	}
	if w.suppressBody {
		return nil
	}
	if w.maxWrite > 0 {
		w.written += int64(len(data))
		if w.written > w.maxWrite {
			return ErrBodyTooLarge
		}
	}

	if w.limiter != nil {
		w.limiter.ThrottleDownload(int64(len(data)))
	}
	if w.global != nil && w.global.Download != nil {
		w.global.Download.Wait(int64(len(data)))
	}

	if !w.chunked {
		return w.writeEncrypted(data)
	}

	bp := MediumBufPool.Get().(*[]byte)
	buf := appendH1Chunk((*bp)[:0], data)

	err := w.writeEncrypted(buf)
	*bp = buf[:0]
	MediumBufPool.Put(bp)
	return err
}

// Flush is a no-op; H1StreamWriter has no internal buffering to flush.
func (w *H1StreamWriter) Flush() error {
	return nil
}

// Close writes the terminating zero-length chunk when the response is
// chunked; it is a no-op for Content-Length responses or bodiless responses.
func (w *H1StreamWriter) Close() error {
	if w.suppressBody || !w.chunked {
		return nil
	}
	return w.writeEncrypted([]byte("0\r\n\r\n"))
}

func (w *H1StreamWriter) writeEncrypted(data []byte) error {
	return WriteAppData(w.conn, w.writer, data)
}

// PlainH1StreamWriter writes an HTTP/1.1 response over a plaintext
// (non-TLS) connection, using the same Content-Length/chunked selection as
// H1StreamWriter. It implements StreamWriter.
type PlainH1StreamWriter struct {
	conn         net.Conn
	limiter      *ConnectionLimiter
	global       *GlobalLimiter
	method       string
	serverName   string
	written      int64
	maxWrite     int64
	headersSent  bool
	chunked      bool
	suppressBody bool
	closeAfter   bool
	cors         streamCORSHead
}

// WriteHeader writes the HTTP/1.1 status line and headers, selecting chunked
// Transfer-Encoding unless a Content-Length header is present or the response
// has no body. Later calls are no-ops.
func (w *PlainH1StreamWriter) WriteHeader(statusCode int, headers [][2]string, contentType string) error {
	if w.headersSent {
		return nil
	}
	w.headersSent = true
	headers = w.cors.withCORS(headers)
	w.suppressBody, _ = responseBodyDisposition(w.method, statusCode)
	w.chunked, _ = classifyH1StreamHeaders(headers)
	if w.suppressBody {
		w.chunked = false
	}

	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]

	buf = appendH1StreamHead(buf, statusCode, headers, contentType, w.chunked, w.closeAfter, w.serverName, nil)

	err := writeFull(w.conn, buf)
	*bp = buf
	putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
	return err
}

// WriteChunk writes data to the client, chunk-encoding it when the response
// uses chunked Transfer-Encoding or writing it directly when Content-Length
// was set. It applies any configured download rate limit and returns
// ErrBodyTooLarge if a maximum response size was set and is exceeded.
func (w *PlainH1StreamWriter) WriteChunk(data []byte) error {
	if !w.headersSent {
		return ErrStreamClosed
	}
	if w.suppressBody {
		return nil
	}
	if w.maxWrite > 0 {
		w.written += int64(len(data))
		if w.written > w.maxWrite {
			return ErrBodyTooLarge
		}
	}

	if w.limiter != nil {
		w.limiter.ThrottleDownload(int64(len(data)))
	}
	if w.global != nil && w.global.Download != nil {
		w.global.Download.Wait(int64(len(data)))
	}

	if !w.chunked {
		return writeFull(w.conn, data)
	}

	bp := MediumBufPool.Get().(*[]byte)
	buf := appendH1Chunk((*bp)[:0], data)

	err := writeFull(w.conn, buf)
	*bp = buf[:0]
	MediumBufPool.Put(bp)
	return err
}

// Flush is a no-op; PlainH1StreamWriter has no internal buffering to flush.
func (w *PlainH1StreamWriter) Flush() error {
	return nil
}

// Close writes the terminating zero-length chunk when the response is
// chunked; it is a no-op for Content-Length responses or bodiless responses.
func (w *PlainH1StreamWriter) Close() error {
	if w.suppressBody || !w.chunked {
		return nil
	}
	return writeFull(w.conn, []byte("0\r\n\r\n"))
}
