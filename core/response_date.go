//go:build linux && amd64

package core

import (
	"bytes"
	"sync/atomic"
)

var lastResponseHTTPDate atomic.Pointer[httpDateEntry]

func responseHTTPDate(unix int64) string { return cachedHTTPDate(&lastResponseHTTPDate, unix) }

type responseDateSpan struct {
	start int
	end   int
}

func currentDateUnix() int64 { return CoarseNanotime() / 1_000_000_000 }

func responseDateValueAt(status int, headers [][2]string, unix int64) string {
	if status < 200 || status >= 600 || headersHaveFold(headers, "date") {
		return ""
	}
	return responseHTTPDate(unix)
}

func responseDateValue(status int, headers [][2]string) string {
	return responseDateValueAt(status, headers, currentDateUnix())
}

func appendH1Date(dst []byte, date string) ([]byte, responseDateSpan) {
	if date == "" {
		return dst, responseDateSpan{}
	}
	span := responseDateSpan{start: len(dst)}
	dst = append(dst, "Date: "...)
	dst = append(dst, date...)
	dst = append(dst, '\r', '\n')
	span.end = len(dst)
	return dst, span
}

func appendH1ResponseDate(dst []byte, status int, headers [][2]string) []byte {
	dst, _ = appendH1Date(dst, responseDateValue(status, headers))
	return dst
}

func appendProxyDate(dst []byte, status int, headers respHeaders) []byte {
	if status < 200 || status >= 600 {
		return dst
	}
	for index := 0; index < headers.count(); index++ {
		if headers.nameIs(index, "date") {
			return dst
		}
	}
	dst, _ = appendH1Date(dst, responseHTTPDate(currentDateUnix()))
	return dst
}

func (s *Server) responseDateUnix() int64 {
	if s.dateNow != nil {
		return s.dateNow()
	}
	return currentDateUnix()
}

func replaceResponseDate(wire []byte, span responseDateSpan, replacement []byte) ([]byte, responseDateSpan) {
	out := make([]byte, 0, len(wire)-(span.end-span.start)+len(replacement))
	out = append(out, wire[:span.start]...)
	out = append(out, replacement...)
	updated := responseDateSpan{start: span.start, end: len(out)}
	return append(out, wire[span.end:]...), updated
}

func (s *Server) currentPlainRootDate(fast *plainRootFastResponse) *plainRootFastResponse {
	unix := s.responseDateUnix()
	if fast == nil || fast.keepDate.end == 0 || fast.dateUnix == unix {
		return fast
	}
	s.rootFastMu.Lock()
	defer s.rootFastMu.Unlock()
	fast = s.plainRootFast.Load()
	unix = s.responseDateUnix()
	if fast == nil || fast.keepDate.end == 0 || fast.dateUnix == unix {
		return fast
	}
	line, _ := appendH1Date(nil, responseHTTPDate(unix))
	updated := *fast
	updated.getKeepAlive, updated.keepDate = replaceResponseDate(fast.getKeepAlive, fast.keepDate, line)
	updated.getClose, updated.closeDate = replaceResponseDate(fast.getClose, fast.closeDate, line)
	updated.getKeepAliveTLS = append(bytes.Clone(updated.getKeepAlive), 0x17)
	updated.getCloseTLS = append(bytes.Clone(updated.getClose), 0x17)
	updated.tlsKeepAlive, updated.tlsClose = nil, nil
	updated.dateUnix = unix
	current := s.attachPlainAltSvc(&updated)
	s.plainRootFast.Store(current)
	return current
}

func (s *Server) currentH2RootDate(fast *h2RootFastResponse) *h2RootFastResponse {
	unix := s.responseDateUnix()
	if fast == nil || fast.date.end == 0 || fast.dateUnix == unix {
		return fast
	}
	s.rootFastMu.Lock()
	defer s.rootFastMu.Unlock()
	fast = s.h2RootFast.Load()
	unix = s.responseDateUnix()
	if fast == nil || fast.date.end == 0 || fast.dateUnix == unix {
		return fast
	}
	enc := HpackEncoder{}
	enc.EncodeHeaderFold("date", responseHTTPDate(unix))
	header, span := replaceResponseDate(fast.headerPayload, fast.date, enc.Buf)
	updated := newH2RootFastResponse(header, fast.body)
	updated.date, updated.dateUnix = span, unix
	updated.handlerAltSvc = fast.handlerAltSvc
	current := s.attachAltSvc(updated)
	s.h2RootFast.Store(current)
	return current
}

func (p *h1Parser) addReceiptDate() {
	for _, header := range p.hdr {
		if headerNameIsBytes(header[0], "date") {
			return
		}
	}
	p.receiptDateBuf = append(p.receiptDateBuf[:0], "date"...)
	nameEnd := len(p.receiptDateBuf)
	p.receiptDateBuf = append(p.receiptDateBuf, responseHTTPDate(currentDateUnix())...)
	p.hdr = append(p.hdr, [2][]byte{p.receiptDateBuf[:nameEnd], p.receiptDateBuf[nameEnd:]})
}

func responseHeaderValue(name, value []byte) string {
	entry := lastResponseHTTPDate.Load()
	if string(name) == "date" && entry != nil && bytes.Equal(value, []byte(entry.text)) {
		return entry.text
	}
	return string(value)
}
