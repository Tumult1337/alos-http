//go:build linux && amd64

package core

import (
	"bytes"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/guno1928/turbo"
)

const httpDateLineLen = len("Date: ") + len(http.TimeFormat) + len("\r\n")

type httpDateLine struct {
	expiresMono int64
	line        [httpDateLineLen]byte
	ok200       [len(plainContentTypePresets)][]byte
}

var currentDateLine atomic.Pointer[httpDateLine]

var plainContentTypePresets = [...][]byte{nil, ctPrefixJSON, ctPrefixTextPlain, ctPrefixTextHTML, ctPrefixOctet}

func plainContentTypePreset(contentType string) int {
	switch contentType {
	case "":
		return 0
	case "application/json; charset=utf-8":
		return 1
	case "text/plain; charset=utf-8":
		return 2
	case "text/html; charset=utf-8":
		return 3
	case "application/octet-stream":
		return 4
	}
	return -1
}

func newHTTPDateLine(unixNano, mono int64) *httpDateLine {
	sec := unixNano / int64(time.Second)
	d := &httpDateLine{expiresMono: mono + int64(time.Second) - unixNano%int64(time.Second)}
	b := append(d.line[:0], dateHeaderPrefix...)
	b = time.Unix(sec, 0).UTC().AppendFormat(b, http.TimeFormat)
	_ = append(b, '\r', '\n')
	head := append(append([]byte(nil), statusLines[http.StatusOK]...), d.line[:]...)
	for i, ct := range plainContentTypePresets {
		d.ok200[i] = append(head[:len(head):len(head)], ct...)
	}
	return d
}

const dateHeaderPrefix = "Date: "

func currentHTTPDate() *httpDateLine {
	d := currentDateLine.Load()
	if d == nil || turbo.Now() >= d.expiresMono {
		d = refreshHTTPDateLine()
	}
	return d
}

func currentHTTPDateLine() *[httpDateLineLen]byte {
	return &currentHTTPDate().line
}

//go:noinline
func refreshHTTPDateLine() *httpDateLine {
	mono := turbo.Now()
	d := newHTTPDateLine(turbo.UnixNano(), mono)
	currentDateLine.Store(d)
	return d
}

func appendDateUnlessSet(dst []byte, headers [][2]string) []byte {
	if len(headers) != 0 && headersHaveFold(headers, "Date") {
		return dst
	}
	return append(dst, currentHTTPDateLine()[:]...)
}

func appendH1HeaderFields(dst []byte, headers [][2]string) []byte {
	for i := range headers {
		dst = append(dst, headers[i][0]...)
		dst = append(dst, ':', ' ')
		dst = append(dst, headers[i][1]...)
		dst = append(dst, '\r', '\n')
	}
	return dst
}

func appendMemoizedResponse(dst, memo []byte) []byte {
	base := len(dst)
	dst = append(dst, memo...)
	refreshMemoizedDate(dst[base:])
	return dst
}

func refreshMemoizedDate(response []byte) {
	at := bytes.IndexByte(response, '\n') + 1
	if at == 0 || len(response)-at < httpDateLineLen {
		return
	}
	line := response[at : at+httpDateLineLen]
	if string(line[:len(dateHeaderPrefix)]) != dateHeaderPrefix || string(line[httpDateLineLen-2:]) != "\r\n" {
		return
	}
	copy(line, currentHTTPDateLine()[:])
}

var statusLines [600][]byte

var smallCL [256][]byte

func init() {
	codes := map[int]string{
		200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 206: "Partial Content",
		301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
		400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
		405: "Method Not Allowed", 408: "Request Timeout", 412: "Precondition Failed", 413: "Payload Too Large",
		416: "Range Not Satisfiable", 426: "Upgrade Required", 429: "Too Many Requests", 431: "Request Header Fields Too Large",
		500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
	}
	for code, text := range codes {
		line := make([]byte, 0, 48)
		line = append(line, "HTTP/1.1 "...)
		line = appendUint(line, int64(code))
		line = append(line, ' ')
		line = append(line, text...)
		line = append(line, '\r', '\n')
		statusLines[code] = line
	}
	for i := 0; i < 256; i++ {
		b := make([]byte, 0, 32)
		b = append(b, "Content-Length: "...)
		b = appendUint(b, int64(i))
		b = append(b, '\r', '\n')
		smallCL[i] = b
	}
}

func appendStatusLine(buf []byte, code int) []byte {
	if code > 0 && code < len(statusLines) && statusLines[code] != nil {
		return append(buf, statusLines[code]...)
	}
	buf = append(buf, "HTTP/1.1 "...)
	buf = appendUint(buf, int64(code))
	buf = append(buf, ' ')
	buf = append(buf, StatusText(code)...)
	buf = append(buf, '\r', '\n')
	return buf
}

var (
	ctPrefixTextPlain = []byte("Content-Type: text/plain; charset=utf-8\r\n")
	ctPrefixTextHTML  = []byte("Content-Type: text/html; charset=utf-8\r\n")
	ctPrefixJSON      = []byte("Content-Type: application/json; charset=utf-8\r\n")
	ctPrefixOctet     = []byte("Content-Type: application/octet-stream\r\n")
	connKeepAlive     = []byte("Connection: keep-alive\r\nServer: ALOS\r\n")
	connClose         = []byte("Connection: close\r\nServer: ALOS\r\n")
)

func appendContentTypeHeader(dst []byte, contentType string) []byte {
	dst = append(dst, "Content-Type: "...)
	dst = appendHeaderValueStripped(dst, contentType)
	return append(dst, '\r', '\n')
}

func appendHeaderValueStripped(dst []byte, value string) []byte {
	if !containsLineBreak(value, lineBreakCRLFNUL) {
		return append(dst, value...)
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c != '\r' && c != '\n' && c != 0 {
			dst = append(dst, c)
		}
	}
	return dst
}

func ctPrefixLookup(ct string) []byte {
	switch len(ct) {
	case 25:
		if ct == "text/plain; charset=utf-8" {
			return ctPrefixTextPlain
		}
	case 24:
		if ct == "text/html; charset=utf-8" {
			return ctPrefixTextHTML
		}
		if ct == "application/octet-stream" {
			return ctPrefixOctet
		}
	case 31:
		if ct == "application/json; charset=utf-8" {
			return ctPrefixJSON
		}
	}
	return nil
}

// BuildH1Response serializes resp into a complete HTTP/1.1 response (status
// line, headers, and body) using a buffer drawn from LargeBufPool. It
// returns the built bytes along with the pool slot backing them; the caller
// is responsible for resetting and returning the slot to LargeBufPool.
func BuildH1Response(resp *Response) ([]byte, *[]byte) {
	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	headerBodyLen := resp.headerContentLength()

	buf = appendStatusLine(buf, resp.StatusCode)
	buf = appendDateUnlessSet(buf, resp.Headers)

	if resp.ContentType != "" {
		if pre := ctPrefixLookup(resp.ContentType); pre != nil {
			buf = append(buf, pre...)
		} else {
			buf = appendContentTypeHeader(buf, resp.ContentType)
		}
	}

	if headerBodyLen >= 0 {
		buf = append(buf, "Content-Length: "...)
		buf = appendUint(buf, int64(headerBodyLen))
		buf = append(buf, '\r', '\n')
	}

	buf = appendH1HeaderFields(buf, resp.Headers)

	ka, _ := serverConnHeaders(resp)
	buf = append(buf, ka...)
	buf = append(buf, '\r', '\n')
	buf = resp.appendTransmittedBody(buf)

	*bp = buf
	return buf, bp
}

// WriteH1Response encrypts and writes resp to conn as an HTTP/1.1 response
// over the given TLS record writer. Responses small enough to fit in a
// single TLS record are assembled and encrypted directly for minimal
// overhead; larger responses fall back to BuildH1Response followed by
// WriteAppData.
func WriteH1Response(conn net.Conn, writer *TrafficAEAD, resp *Response) error {
	const maxInner = MaxRecordPayload - 1
	body := resp.transmittedBodyBytes()
	bodyLen := len(body)
	headerBodyLen := resp.headerContentLength()
	if bodyLen+256 > maxInner {
		respData, respBP := BuildH1Response(resp)
		err := WriteAppData(conn, writer, respData)
		*respBP = (*respBP)
		putBoxedBufCapped(&LargeBufPool, respBP, largeBufPoolMaxCap)
		return err
	}
	ibp := WriteBufPool.Get().(*[]byte)
	inner := (*ibp)[:0]
	inner = appendStatusLine(inner, resp.StatusCode)
	inner = appendDateUnlessSet(inner, resp.Headers)
	if resp.ContentType != "" {
		if pre := ctPrefixLookup(resp.ContentType); pre != nil {
			inner = append(inner, pre...)
		} else {
			inner = appendContentTypeHeader(inner, resp.ContentType)
		}
	}
	if headerBodyLen >= 0 {
		inner = append(inner, "Content-Length: "...)
		inner = appendUint(inner, int64(headerBodyLen))
		inner = append(inner, '\r', '\n')
	}
	inner = appendH1HeaderFields(inner, resp.Headers)
	ka, _ := serverConnHeaders(resp)
	inner = append(inner, ka...)
	inner = append(inner, '\r', '\n')
	inner = append(inner, body...)
	if len(inner) > maxInner {
		*ibp = (*ibp)[:0]
		WriteBufPool.Put(ibp)
		respData, respBP := BuildH1Response(resp)
		err := WriteAppData(conn, writer, respData)
		*respBP = (*respBP)
		putBoxedBufCapped(&LargeBufPool, respBP, largeBufPoolMaxCap)
		return err
	}
	inner = append(inner, 0x17)
	overhead := writer.Overhead()
	ciphertextLen := len(inner) + overhead
	obp := LargeBufPool.Get().(*[]byte)
	var out []byte
	if cap(*obp) >= 5+ciphertextLen {
		out = (*obp)[:0]
	} else {
		out = make([]byte, 0, 5+ciphertextLen)
	}
	out = append(out, 0x17, 0x03, 0x03, byte(ciphertextLen>>8), byte(ciphertextLen))
	out = writer.EncryptAppend(out, inner)
	err := writeFull(conn, out)
	*ibp = (*ibp)[:0]
	WriteBufPool.Put(ibp)
	*obp = out
	putBoxedBufCapped(&LargeBufPool, obp, largeBufPoolMaxCap)
	return err
}
