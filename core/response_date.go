//go:build linux && amd64

package core

import (
	"bytes"
	"sync/atomic"
)

var lastResponseHTTPDate atomic.Pointer[httpDateEntry]

func responseHTTPDate(unix int64) string { return cachedHTTPDate(&lastResponseHTTPDate, unix) }

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

func appendH1Date(dst []byte, date string) []byte {
	dst = append(dst, "Date: "...)
	dst = append(dst, date...)
	return append(dst, '\r', '\n')
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
	return appendH1Date(dst, responseHTTPDate(currentDateUnix()))
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
