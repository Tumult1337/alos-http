//go:build linux && amd64

package core

func parsePlainFastRootRequestRef(buf []byte, lineLen int, maxHeaderBytes int) (consumed int, keepAlive bool, ok bool, needRead bool) {
	headerEnd := findHeaderTerminatorBytes(buf, lineLen)
	if headerEnd < 0 {
		if len(buf) > maxHeaderBytes {
			return 0, false, false, false
		}
		return 0, false, false, true
	}
	keepAlive = true
	hosts := 0
	for offset := lineLen; offset < headerEnd-2; {
		rest := buf[offset:headerEnd]
		special, nameEnd := h1HeaderLineSpecials(rest)
		n, bad := classifyFirstSpecial(rest, special)
		if bad || n <= 0 {
			return 0, false, false, false
		}
		line := rest[:n]
		if !validH1Colon(line, nameEnd) {
			return 0, false, false, false
		}
		colon := nameEnd
		value := trimOWS(line[colon+1:])
		switch {
		case colon == len("host") && asciiEqualFoldBytes(line[:colon], "host"):
			hosts++
			if !ValidateHost(UnsafeString(value)) {
				return 0, false, false, false
			}
		case colon == len("connection") && asciiEqualFoldBytes(line[:colon], "connection"):
			if containsTokenFold(UnsafeString(value), "close") {
				keepAlive = false
			}
		case colon == len("content-length") && asciiEqualFoldBytes(line[:colon], "content-length"),
			colon == len("transfer-encoding") && asciiEqualFoldBytes(line[:colon], "transfer-encoding"),
			colon == len("expect") && asciiEqualFoldBytes(line[:colon], "expect"):
			return 0, false, false, false
		}
		offset += n + 2
	}
	if hosts != 1 {
		return 0, false, false, false
	}
	return headerEnd, keepAlive, true, false
}
