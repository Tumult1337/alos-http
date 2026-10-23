//go:build linux && amd64

package core

import (
	"bytes"
	"net/http"
)

func plainOKHead(resp *Response) []byte {
	if preset := plainContentTypePreset(resp.ContentType); preset >= 0 && (len(resp.Headers) == 0 || !headersHaveFold(resp.Headers, "Date")) {
		return currentHTTPDate().ok200[preset]
	}
	return nil
}

func appendPlainResponseMode(resp *Response, dst []byte, keepAlive bool, includeBody bool) []byte {
	var head []byte
	if resp.StatusCode == http.StatusOK {
		head = plainOKHead(resp)
	}
	if head != nil {
		dst = append(dst, head...)
	} else {
		dst = appendStatusLine(dst, resp.StatusCode)
		dst = appendDateUnlessSet(dst, resp.StatusCode, resp.Headers)
		if resp.ContentType != "" {
			switch resp.ContentType {
			case "application/json; charset=utf-8":
				dst = append(dst, ctPrefixJSON...)
			case "text/plain; charset=utf-8":
				dst = append(dst, ctPrefixTextPlain...)
			case "text/html; charset=utf-8":
				dst = append(dst, ctPrefixTextHTML...)
			case "application/octet-stream":
				dst = append(dst, ctPrefixOctet...)
			default:
				dst = append(dst, "Content-Type: "...)
				dst = appendHeaderValueStripped(dst, resp.ContentType)
				dst = append(dst, '\r', '\n')
			}
		}
	}

	method := ""
	if resp.lazyReq != nil {
		method = resp.lazyReq.Method
	}
	suppressBody, omitContentLength := responseBodyDisposition(method, resp.StatusCode)
	if !omitContentLength {
		bodyLen := resp.BodyLen()
		if bodyLen < 256 {
			dst = append(dst, smallCL[bodyLen]...)
		} else {
			dst = append(dst, "Content-Length: "...)
			dst = appendUint(dst, int64(bodyLen))
			dst = append(dst, '\r', '\n')
		}
	}

	dst = appendH1HeaderFields(dst, resp.Headers)
	dst = append(dst, serverConnHeadTail(resp, keepAlive)...)
	if includeBody && !suppressBody {
		dst = resp.appendBody(growIOBuf(dst, resp.BodyLen()))
	}
	return dst
}

func growPlainReadBuffer(buf []byte, minFree, maxRead int) ([]byte, bool) {
	if cap(buf)-len(buf) >= minFree {
		return buf, true
	}
	unread := len(buf)
	newCap := cap(buf)*2 + minFree
	minCap := unread + minFree
	if newCap < minCap {
		newCap = minCap
	}
	if newCap < 4096 {
		newCap = 4096
	}
	if maxRead > 0 && newCap > maxRead {
		newCap = maxRead
	}
	if newCap < minCap {
		return nil, false
	}
	newBuf := make([]byte, unread, newCap)
	copy(newBuf, buf)
	return newBuf, true
}

func connectionOptions(value []byte) (closeRequested, keepAliveRequested bool) {
	switch {
	case asciiEqualFoldBytes(value, "keep-alive"):
		return false, true
	case asciiEqualFoldBytes(value, "close"):
		return true, false
	}
	return connectionOptionList(UnsafeString(value))
}

func connectionOptionList(options string) (closeRequested, keepAliveRequested bool) {
	return containsTokenFold(options, "close"), containsTokenFold(options, "keep-alive")
}

func asciiEqualFoldBytes(line []byte, value string) bool {
	if len(line) != len(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		if asciiLower[line[i]] != asciiLower[value[i]] {
			return false
		}
	}
	return true
}

// ParseH1RequestHead parses the HTTP/1.x request line and header block in
// data into req. It returns the length of the parsed header block, the
// Content-Length value (if any consistent value was present), whether the
// connection should close, whether Transfer-Encoding was malformed or
// chunked, whether the header block exceeded maxHeaderBytes or
// maxHeaderCount, and whether a complete head was found.
var h1TokenChar = func() [256]bool {
	var t [256]bool
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
	}
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = true
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for _, c := range []byte("!#$%&'*+-.^_`|~") {
		t[c] = true
	}
	return t
}()

func isH1Token(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !h1TokenChar[c] {
			return false
		}
	}
	return true
}

func validH1Version(v []byte) bool {
	return len(v) == 8 && v[0] == 'H' && v[1] == 'T' && v[2] == 'T' && v[3] == 'P' &&
		v[4] == '/' && v[5] == '1' && v[6] == '.' && (v[7] == '0' || v[7] == '1')
}

func ParseH1RequestHead(data []byte, req *Request, maxHeaderBytes, maxHeaderCount int) (headerEnd int, contentLength int, hasContentLength bool, closeConn bool, badTransferEncoding bool, chunkedEncoding bool, tooLarge bool, ok bool) {
	headerEnd, contentLength, hasContentLength, closeConn, reject, chunkedEncoding, tooLarge, ok := parseH1RequestHead(data, req, maxHeaderBytes, maxHeaderCount)
	return headerEnd, contentLength, hasContentLength, closeConn, reject != h1RejectNone, chunkedEncoding, tooLarge, ok
}

func parseH1RequestHead(data []byte, req *Request, maxHeaderBytes, maxHeaderCount int) (headerEnd int, contentLength int, hasContentLength bool, closeConn bool, reject h1RejectReason, chunkedEncoding bool, tooLarge bool, ok bool) {
	maxBytes := maxHeaderBytes
	if maxBytes <= 0 {
		maxBytes = 8192
	}
	maxCount := maxHeaderCount
	if maxCount <= 0 {
		maxCount = 128
	}

	idx, bad := classifyFirstSpecial(data, firstH1Special(data))
	if bad {
		return 0, 0, false, false, h1RejectRequestLine, false, false, true
	}
	if idx < 0 {
		if len(data) > maxBytes {
			return 0, 0, false, false, h1RejectNone, false, true, false
		}
		return 0, 0, false, false, h1RejectNone, false, false, false
	}

	rl := data[:idx]
	sp1 := bytes.IndexByte(rl, ' ')
	if sp1 < 0 {
		return 0, 0, false, false, h1RejectRequestLine, false, false, true
	}
	sp2 := bytes.IndexByte(rl[sp1+1:], ' ')
	if sp2 <= 0 {
		return 0, 0, false, false, h1RejectRequestLine, false, false, true
	}
	sp2 += sp1 + 1

	if !validH1Version(rl[sp2+1:]) {
		return 0, 0, false, false, h1RejectRequestLine, false, false, true
	}
	http10 := rl[sp2+8] == '0'
	if http10 {
		req.Proto = internedHTTP10
	} else {
		req.Proto = internedHTTP11
	}
	keepAliveRequested := false

	methodBytes := rl[:sp1]
	if !isH1Token(methodBytes) {
		return 0, 0, false, false, h1RejectRequestLine, false, false, true
	}
	switch string(methodBytes) {
	case internedGET:
		req.Method = internedGET
	case internedPOST:
		req.Method = internedPOST
	case internedPUT:
		req.Method = internedPUT
	case internedDELETE:
		req.Method = internedDELETE
	case internedPATCH:
		req.Method = internedPATCH
	case internedHEAD:
		req.Method = internedHEAD
	case internedOPTIONS:
		req.Method = internedOPTIONS
	default:
		req.Method = string(methodBytes)
	}

	rawURI := UnsafeString(rl[sp1+1 : sp2])
	var absoluteHost, target string
	absoluteForm := false
	if len(rawURI) > 0 && rawURI[0] != '/' {
		absoluteHost, target, absoluteForm = splitAbsoluteForm(rawURI)
	}
	if absoluteForm {
		if absoluteHost == "" || !ValidateHost(absoluteHost) {
			return 0, 0, false, false, h1RejectHost, false, false, true
		}
		rawURI = target
	}
	pathPart, query := splitPathQuery(rawURI)
	req.Path = sanitizeSplitPath(pathPart)
	req.Query = query
	req.RawPath = rawURI

	badTransferEncoding := false
	hostCount := 0
	for pos := idx + 2; pos < len(data); {
		if pos > maxBytes {
			return 0, 0, false, false, h1RejectNone, false, true, false
		}
		remaining := data[pos:]
		var special, nameEnd int
		hostSafe := false
		if len(remaining) < h1ScalarScanMax {
			special, nameEnd, hostSafe = h1HeaderLineScalar(remaining)
		} else {
			special, nameEnd = h1HeaderLineSpecials(remaining)
		}
		lineEndOff, bad := classifyFirstSpecial(remaining, special)
		if bad {
			return 0, 0, false, false, h1RejectCTL, false, false, true
		}
		if lineEndOff < 0 {
			if len(data) > maxBytes {
				return 0, 0, false, false, h1RejectNone, false, true, false
			}
			return 0, 0, false, false, h1RejectNone, false, false, false
		}
		nl := pos + lineEndOff
		if nl == pos {
			if badTransferEncoding || chunkedEncoding && (hasContentLength || http10) {
				return 0, 0, false, false, h1RejectTransferEncoding, false, false, true
			}
			if hostCount > 1 || hostCount == 0 && !http10 {
				return 0, 0, false, false, h1RejectHost, false, false, true
			}
			if http10 {
				req.expect = h1ExpectNone
			}
			if absoluteForm {
				req.Host = absoluteHost
				req.cachedHost = absoluteHost
				req.headerCacheMask |= headerCacheHost
			}
			if http10 && !keepAliveRequested {
				closeConn = true
			}
			req.aliasesReadBuf = true
			return nl + 2, contentLength, hasContentLength, closeConn, h1RejectNone, chunkedEncoding, false, true
		}

		line := data[pos:nl]
		if !validH1Colon(line, nameEnd) {
			return 0, 0, false, false, h1HeaderLineReject(line), false, false, true
		}
		colon := nameEnd
		name := UnsafeString(line[:colon])
		val := trimOWS(line[colon+1:])
		valStr := UnsafeString(val)
		req.Headers = append(req.Headers, [2]string{name, valStr})
		if len(req.Headers) > maxCount {
			return nl + 2, contentLength, hasContentLength, closeConn, h1RejectNone, chunkedEncoding, true, false
		}

		switch colon {
		case 4:
			if (name[0] == 'H' || name[0] == 'h') && EqualFoldASCII(name, "Host") {
				hostCount++
				if !hostSafe && !ValidateHost(valStr) {
					return 0, 0, false, false, h1RejectHost, false, false, true
				}
				req.Host = valStr
				req.cachedHost = valStr
				req.headerCacheMask |= headerCacheHost
			}
		case 6:
			if (name[0] == 'O' || name[0] == 'o') && EqualFoldASCII(name, "Origin") {
				req.cachedOrigin = valStr
				req.headerCacheMask |= headerCacheOrigin
			} else if (name[0] == 'E' || name[0] == 'e') && EqualFoldASCII(name, "Expect") {
				req.expect = classifyExpect(req.expect, val)
			}
		case 7:
			if (name[0] == 'U' || name[0] == 'u') && EqualFoldASCII(name, "Upgrade") {
				req.cachedUpgrade = valStr
				req.headerCacheMask |= headerCacheUpgrade
			}
		case 9:
			if (name[0] == 'X' || name[0] == 'x') && EqualFoldASCII(name, "X-Real-IP") {
				req.cachedXRI = valStr
				req.headerCacheMask |= headerCacheXRealIP
			}
		case 10:
			if (name[0] == 'C' || name[0] == 'c') && EqualFoldASCII(name, "Connection") {
				req.cachedConn = valStr
				req.headerCacheMask |= headerCacheConnection
				closeRequested, keepAliveListed := connectionOptions(val)
				closeConn = closeConn || closeRequested
				keepAliveRequested = keepAliveRequested || keepAliveListed
			}
		case 13:
			if (name[0] == 'A' || name[0] == 'a') && EqualFoldASCII(name, "Authorization") {
				req.cachedAuth = valStr
				req.headerCacheMask |= headerCacheAuthorization
			}
		case 14:
			if (name[0] == 'C' || name[0] == 'c') && EqualFoldASCII(name, "Content-Length") {
				req.cachedCL = valStr
				req.headerCacheMask |= headerCacheContentLength
				parsedCL, parsedOK := parseUint(valStr)
				if hasContentLength {
					if !parsedOK || contentLength < 0 || parsedCL != contentLength {
						contentLength = -1
					}
				} else {
					hasContentLength = true
					if parsedOK {
						contentLength = parsedCL
					} else {
						contentLength = -1
					}
				}
			}
		case 15:
			if (name[0] == 'A' || name[0] == 'a') && EqualFoldASCII(name, "Accept-Encoding") {
				req.cachedAE = valStr
				req.headerCacheMask |= headerCacheAcceptEncoding
			} else if (name[0] == 'X' || name[0] == 'x') && EqualFoldASCII(name, "X-Forwarded-For") {
				req.cachedXFF = valStr
				req.headerCacheMask |= headerCacheXForwardedFor
			}
		case 17:
			if (name[0] == 'T' || name[0] == 't') && EqualFoldASCII(name, "Transfer-Encoding") {
				req.cachedTE = valStr
				req.headerCacheMask |= headerCacheTransferEncoding
				if EqualFoldASCII(valStr, "chunked") {
					chunkedEncoding = true
				} else {
					badTransferEncoding = true
				}
			} else if (name[0] == 'S' || name[0] == 's') && EqualFoldASCII(name, "Sec-WebSocket-Key") {
				req.cachedWSKey = valStr
				req.headerCacheMask |= headerCacheWSKey
			}
		case 21:
			if (name[0] == 'S' || name[0] == 's') && EqualFoldASCII(name, "Sec-WebSocket-Version") {
				req.cachedWSVer = valStr
				req.headerCacheMask |= headerCacheWSVersion
			}
		}

		pos = nl + 2
	}

	return 0, 0, false, false, h1RejectNone, false, false, false
}

func appendPlainResponse(resp *Response, dst []byte) []byte {
	return appendPlainResponseMode(resp, dst, true, true)
}

func appendPlainResponseClose(resp *Response, dst []byte) []byte {
	return appendPlainResponseMode(resp, dst, false, true)
}

func appendPlainResponseHeaders(resp *Response, dst []byte) []byte {
	return appendPlainResponseMode(resp, dst, true, false)
}
