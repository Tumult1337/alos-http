//go:build linux && amd64

package core

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/guno1928/turbo"
)

const (
	hpackStaticDate = 33
	h2DateValueLen  = len(http.TimeFormat)
)

type h2DateField struct {
	unix int64
	enc  []byte
}

var (
	h2DateFieldPrefix = appendH2DateFieldPrefix(nil)
	currentH2Date     atomic.Pointer[h2DateField]
)

func appendH2DateFieldPrefix(dst []byte) []byte {
	enc := HpackEncoder{Buf: dst}
	enc.EncodeInt(0x00, 4, hpackStaticDate)
	enc.EncodeInt(0x00, 7, uint64(h2DateValueLen))
	return enc.Buf
}

func newH2DateField(unix int64) *h2DateField {
	enc := appendH2DateFieldPrefix(make([]byte, 0, len(h2DateFieldPrefix)+h2DateValueLen))
	return &h2DateField{unix: unix, enc: time.Unix(unix, 0).UTC().AppendFormat(enc, http.TimeFormat)}
}

func currentH2DateField() []byte {
	return loadH2DateField().enc
}

func loadH2DateField() *h2DateField {
	now := turbo.Unix()
	f := currentH2Date.Load()
	if f == nil || f.unix != now {
		f = newH2DateField(now)
		currentH2Date.Store(f)
	}
	return f
}

func h2StatusFieldLen(block []byte) int {
	if len(block) == 0 {
		return 0
	}
	if block[0]&0x80 != 0 || len(block) < 2 {
		return 1
	}
	return 2 + int(block[1]&0x7f)
}

func refreshH2DateField(headerBlock []byte) {
	at := h2StatusFieldLen(headerBlock)
	field := currentH2DateField()
	if len(headerBlock)-at < len(field) || string(headerBlock[at:at+len(h2DateFieldPrefix)]) != string(h2DateFieldPrefix) {
		return
	}
	copy(headerBlock[at:at+len(field)], field)
}

func encodeH2ResponseHeaders(enc *HpackEncoder, statusCode int, contentType string, contentLength int64, headers [][2]string, serverName string) {
	encodeH2ResponseHeadersDated(enc, nil, nil, statusCode, contentType, contentLength, headers, serverName)
}

func encodeH2ResponseHeadersIndexed(enc *HpackEncoder, tbl *hpackEncTable, statusCode int, contentType string, contentLength int64, headers [][2]string, serverName string) {
	if tbl == nil || tbl.pendingUpdate || !tbl.headMemoReady(headers) {
		encodeH2ResponseHeadersDated(enc, tbl, nil, statusCode, contentType, contentLength, headers, serverName)
		return
	}
	date := loadH2DateField()
	if m := tbl.headMemo; m != nil && m.matches(tbl.gen, date, statusCode, contentType, contentLength, headers, serverName) {
		m.probation = false
		enc.Buf = append(enc.Buf, m.block...)
		return
	}
	encodeH2ResponseHeadersRemembered(enc, tbl, date, statusCode, contentType, contentLength, headers, serverName)
}

func encodeH2ResponseHeadersDated(enc *HpackEncoder, tbl *hpackEncTable, dateField *h2DateField, statusCode int, contentType string, contentLength int64, headers [][2]string, serverName string) {
	if tbl != nil {
		tbl.beginBlock(enc)
	}
	enc.EncodeStatus(statusCode)
	if !headersHaveFold(headers, "date") {
		if dateField == nil {
			dateField = loadH2DateField()
		}
		date := dateField.enc
		if tbl == nil {
			enc.Buf = append(enc.Buf, date...)
		} else {
			tbl.encodeField(enc, hpackStaticDate, "date", UnsafeString(date[len(h2DateFieldPrefix):]))
		}
	}

	wroteContentType := false
	wroteContentLength := false
	wroteServer := false

	if contentType != "" {
		encodeH2StaticField(enc, tbl, hpackStaticContentType, "content-type", contentType)
		wroteContentType = true
	}
	if contentLength >= 0 {
		var clBuf [20]byte
		clStr := appendUint(clBuf[:0], contentLength)
		enc.EncodeInt(0x00, 4, hpackStaticContentLength)
		enc.EncodeString(UnsafeString(clStr))
		wroteContentLength = true
	}

	for i := range headers {
		name, value := headers[i][0], headers[i][1]
		if name == "" || name[0] == ':' || isConnectionSpecificResponseField(name) {
			continue
		}
		switch {
		case EqualFoldASCII(name, "content-type"):
			if !wroteContentType {
				wroteContentType = true
				encodeH2StaticField(enc, tbl, hpackStaticContentType, "content-type", value)
			}
		case EqualFoldASCII(name, "content-length"):
			if !wroteContentLength {
				wroteContentLength = true
				enc.EncodeHeaderFold(name, value)
			}
		case EqualFoldASCII(name, "server"):
			if !wroteServer {
				wroteServer = true
				encodeH2StaticField(enc, tbl, hpackStaticServer, "server", value)
			}
		default:
			encodeH2CustomField(enc, tbl, name, value)
		}
	}

	if !wroteServer {
		encodeH2StaticField(enc, tbl, hpackStaticServer, "server", serverName)
	}
}

func encodeH2StaticField(enc *HpackEncoder, tbl *hpackEncTable, staticIdx int, lowerName, value string) {
	if tbl == nil {
		enc.encodeStaticFieldCached(staticIdx, value)
		return
	}
	tbl.encodeField(enc, staticIdx, lowerName, value)
}

func encodeH2CustomField(enc *HpackEncoder, tbl *hpackEncTable, name, value string) {
	if tbl != nil {
		if lower, ok := h2IndexableResponseField(name); ok {
			tbl.encodeField(enc, hpackFindStaticNameFold(lower), lower, value)
			return
		}
	}
	enc.EncodeHeaderFold(name, value)
}
