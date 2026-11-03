//go:build linux && amd64

package core

import (
	"net/http"
)

const (
	hpackStaticDate = 33
	h2DateValueLen  = len(http.TimeFormat)
)

var h2DateFieldPrefix = appendH2DateFieldPrefix(nil)

func appendH2DateFieldPrefix(dst []byte) []byte {
	enc := HpackEncoder{Buf: dst}
	enc.EncodeInt(0x00, 4, hpackStaticDate)
	enc.EncodeInt(0x00, 7, uint64(h2DateValueLen))
	return enc.Buf
}

func currentH2DateField() []byte {
	return currentHTTPDate().h2
}

func encodeH2ResponseHeaders(enc *HpackEncoder, statusCode int, contentType string, contentLength int64, headers [][2]string, serverName string) {
	encodeH2ResponseHeadersDated(enc, nil, nil, statusCode, contentType, contentLength, headers, serverName)
}

func encodeH2ResponseHeadersIndexed(enc *HpackEncoder, tbl *hpackEncTable, statusCode int, contentType string, contentLength int64, headers [][2]string, serverName string) {
	if tbl == nil || tbl.pendingUpdate || !tbl.headMemoReady(headers) {
		encodeH2ResponseHeadersDated(enc, tbl, nil, statusCode, contentType, contentLength, headers, serverName)
		return
	}
	date := currentHTTPDate()
	if m := tbl.headMemo; m != nil && m.matches(tbl.gen, date, statusCode, contentType, contentLength, headers, serverName) {
		m.probation = false
		enc.Buf = append(enc.Buf, m.block...)
		return
	}
	encodeH2ResponseHeadersRemembered(enc, tbl, date, statusCode, contentType, contentLength, headers, serverName)
}

func encodeH2ResponseHeadersDated(enc *HpackEncoder, tbl *hpackEncTable, dateField *httpDateLine, statusCode int, contentType string, contentLength int64, headers [][2]string, serverName string) {
	if tbl != nil {
		tbl.beginBlock(enc)
	}
	enc.EncodeStatus(statusCode)
	if dateEligible(statusCode, headers) {
		if dateField == nil {
			dateField = currentHTTPDate()
		}
		date := dateField.h2
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
