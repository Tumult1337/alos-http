//go:build linux && amd64

package core

import "bytes"

func parseMultipartInMem(body []byte, boundary string) (map[string][]string, map[string][]FileHeader, error) {
	values := make(map[string][]string)
	files := make(map[string][]FileHeader)
	dash := []byte("--" + boundary)
	delim := []byte("\r\n--" + boundary)
	pos := 0
	for {
		if _, _, valid := multipartBoundaryLine(body[pos:], dash); valid {
			break
		}
		next := bytes.Index(body[pos:], delim)
		if next < 0 {
			return values, files, errMultipartMalformed
		}
		pos += next + 2
	}
	for parts := 0; ; parts++ {
		consumed, final, valid := multipartBoundaryLine(body[pos:], dash)
		if !valid {
			return values, files, errMultipartMalformed
		}
		if final {
			return values, files, nil
		}
		pos += consumed
		if parts == maxMultipartParts {
			return values, files, errMultipartTooManyParts
		}
		var block []byte
		if bytes.HasPrefix(body[pos:], []byte("\r\n")) {
			pos += 2
		} else {
			limit := min(len(body), pos+maxMultipartHeaderBytes+4)
			end := bytes.Index(body[pos:limit], []byte("\r\n\r\n"))
			if end < 0 {
				return values, files, errMultipartMalformed
			}
			block = body[pos : pos+end]
			pos += end + 4
		}
		next := 0
		for search := pos; ; {
			found := bytes.Index(body[search:], delim)
			if found < 0 {
				return values, files, errMultipartMalformed
			}
			next = search + found - pos
			candidate := body[pos+next+2:]
			if _, _, valid := multipartBoundaryLine(candidate, dash); valid {
				break
			}
			suffix := candidate[len(dash):]
			if len(suffix) == 0 || suffix[0] == ' ' || suffix[0] == '\t' || suffix[0] == '\r' || suffix[0] == '\n' || bytes.HasPrefix(suffix, []byte("--")) {
				return values, files, errMultipartMalformed
			}
			search = pos + next + 2
		}
		content := body[pos : pos+next]
		header, ok := parseMultipartHeaderLines(block)
		if !ok {
			return values, files, errMultipartMalformed
		}
		part, ok := interpretMultipartHeader(header)
		if !ok {
			return values, files, errMultipartMalformed
		}
		switch {
		case part.name == "":
		case part.hasFilename:
			addMultipartFile(files, part, FileHeader{Size: int64(len(content)), Data: content})
		default:
			addMultipartValue(values, part, content)
		}
		pos += next + 2
	}
}

func multipartBoundaryLine(body, dash []byte) (int, bool, bool) {
	if !bytes.HasPrefix(body, dash) {
		return 0, false, false
	}
	pos := len(dash)
	final := bytes.HasPrefix(body[pos:], []byte("--"))
	if final {
		pos += 2
	}
	for pos < len(body) && (body[pos] == ' ' || body[pos] == '\t') {
		pos++
	}
	if final && pos == len(body) {
		return pos, true, true
	}
	if !bytes.HasPrefix(body[pos:], []byte("\r\n")) {
		return 0, false, false
	}
	return pos + 2, final, true
}
