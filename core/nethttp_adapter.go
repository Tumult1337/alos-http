//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
)

const netHTTPSniffLen = 512

var errNetHTTPHijack = errors.New("core: Hijack is not supported through WrapHTTPHandler")

func WrapHTTPHandler(h http.Handler) HandlerFunc {
	return func(req *Request, resp *Response) {
		hr, err := newNetHTTPRequest(req)
		if err != nil {
			resp.Status(400).String("Bad Request")
			return
		}
		w := &netHTTPResponseWriter{resp: resp, header: make(http.Header)}
		h.ServeHTTP(w, hr)
		w.finish()
	}
}

func netHTTPTarget(req *Request) string {
	if req.RawPath != "" {
		return req.RawPath
	}
	if req.Query != "" {
		return req.Path + "?" + req.Query
	}
	return req.Path
}

func newNetHTTPRequest(req *Request) (*http.Request, error) {
	var body io.Reader = http.NoBody
	contentLength := int64(len(req.Body))
	switch {
	case req.BodyStream() != nil:
		body = req.BodyStream()
		contentLength = -1
		if cl, err := strconv.ParseInt(req.Header("content-length"), 10, 64); err == nil {
			contentLength = cl
		}
	case len(req.Body) > 0:
		body = bytes.NewReader(req.Body)
	}
	target := netHTTPTarget(req)
	hr, err := http.NewRequestWithContext(req.Context(), req.Method, target, body)
	if err != nil {
		return nil, err
	}
	hr.ContentLength = contentLength
	hr.RequestURI = target
	hr.Host = req.Host
	hr.RemoteAddr = req.RemoteAddr
	switch {
	case req.IsH2:
		hr.Proto, hr.ProtoMajor, hr.ProtoMinor = "HTTP/2.0", 2, 0
	default:
		if major, minor, ok := http.ParseHTTPVersion(req.Proto); ok {
			hr.Proto, hr.ProtoMajor, hr.ProtoMinor = req.Proto, major, minor
		}
	}
	hr.Header = make(http.Header, len(req.Headers))
	for _, h := range req.Headers {
		if EqualFoldASCII(h[0], "host") {
			continue
		}
		key := http.CanonicalHeaderKey(h[0])
		hr.Header[key] = append(hr.Header[key], h[1])
	}
	if req.IsTLS {
		hr.TLS = &tls.ConnectionState{Version: req.TLSVersion, HandshakeComplete: true, PeerCertificates: req.TLSPeerCertificates()}
	}
	return hr, nil
}

type netHTTPResponseWriter struct {
	resp        *Response
	header      http.Header
	status      int
	wroteHeader bool
	body        []byte
	sw          StreamWriter
	err         error
}

func (w *netHTTPResponseWriter) Header() http.Header { return w.header }

func (w *netHTTPResponseWriter) WriteHeader(code int) {
	if w.wroteHeader || code < 200 {
		return
	}
	w.wroteHeader = true
	w.status = code
}

func (w *netHTTPResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.sw != nil {
		if err := w.sw.WriteChunk(p); err != nil {
			w.err = err
			return 0, err
		}
		return len(p), nil
	}
	w.body = append(w.body, p...)
	return len(p), nil
}

func (w *netHTTPResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.err != nil {
		return
	}
	if w.sw == nil {
		sw := w.resp.EnsureStreamWriter()
		if sw == nil {
			return
		}
		contentType, headers := w.responseHeaders()
		if err := sw.WriteHeader(w.status, headers, contentType); err != nil {
			w.err = err
			return
		}
		w.resp.SetStreamer(sw)
		w.sw = sw
		if len(w.body) > 0 {
			if err := sw.WriteChunk(w.body); err != nil {
				w.err = err
				return
			}
			w.body = nil
		}
	}
	if err := w.sw.Flush(); err != nil {
		w.err = err
	}
}

func (w *netHTTPResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errNetHTTPHijack
}

func (w *netHTTPResponseWriter) responseHeaders() (string, [][2]string) {
	contentType := w.header.Get("Content-Type")
	if _, set := w.header["Content-Type"]; !set && len(w.body) > 0 {
		contentType = http.DetectContentType(w.body[:min(len(w.body), netHTTPSniffLen)])
	}
	headers := make([][2]string, 0, len(w.header))
	for key, values := range w.header {
		if key == "Content-Type" || key == "Content-Length" || isHopByHopFold(key) {
			continue
		}
		for _, v := range values {
			headers = append(headers, [2]string{sanitizeHeaderValue(key), sanitizeHeaderValue(v)})
		}
	}
	return sanitizeHeaderValue(contentType), headers
}

func (w *netHTTPResponseWriter) finish() {
	if w.sw != nil {
		return
	}
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	contentType, headers := w.responseHeaders()
	w.resp.Status(w.status)
	w.resp.Headers = append(w.resp.Headers, headers...)
	w.resp.SetBody(w.body)
	w.resp.ContentType = contentType
}
