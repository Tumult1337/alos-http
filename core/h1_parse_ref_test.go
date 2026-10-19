//go:build linux && amd64

package core

import "bytes"

func refConnectionHasOption(value []byte, option string) bool {
	for _, element := range bytes.Split(value, []byte{','}) {
		if refASCIIEqualFold(bytes.Trim(element, " \t"), option) {
			return true
		}
	}
	return false
}

func refASCIIEqualFold(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func parseH1RequestHeadRef(data []byte, req *Request, maxHeaderBytes, maxHeaderCount int) (headerEnd int, contentLength int, hasContentLength bool, closeConn bool, reject h1RejectReason, chunkedEncoding bool, tooLarge bool, ok bool) {
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
		req.Proto = "HTTP/1.0"
	} else {
		req.Proto = "HTTP/1.1"
	}
	keepAliveRequested := false

	methodBytes := rl[:sp1]
	if !isH1Token(methodBytes) {
		return 0, 0, false, false, h1RejectRequestLine, false, false, true
	}
	switch string(methodBytes) {
	case "GET":
		req.Method = "GET"
	case "POST":
		req.Method = "POST"
	case "PUT":
		req.Method = "PUT"
	case "DELETE":
		req.Method = "DELETE"
	case "PATCH":
		req.Method = "PATCH"
	case "HEAD":
		req.Method = "HEAD"
	case "OPTIONS":
		req.Method = "OPTIONS"
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
		special, nameEnd, hostSafe := h1HeaderLineScan(remaining)
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
				closeConn = closeConn || refConnectionHasOption(val, "close")
				keepAliveRequested = keepAliveRequested || refConnectionHasOption(val, "keep-alive")
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
