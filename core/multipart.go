//go:build linux && amd64

package core

import "bytes"

func parseMultipartInMem(body []byte, boundary string) (map[string][]string, map[string][]FileHeader, error) {
	values := make(map[string][]string)
	files := make(map[string][]FileHeader)
	dash := []byte("--" + boundary)
	delim := []byte("\r\n--" + boundary)
	pos := 0
	if !bytes.HasPrefix(body, dash) {
		i := bytes.Index(body, delim)
		if i < 0 {
			return values, files, errMultipartMalformed
		}
		pos = i + 2
	}
	for parts := 0; ; parts++ {
		pos += len(dash)
		if bytes.HasPrefix(body[pos:], []byte("--")) {
			return values, files, nil
		}
		for pos < len(body) && (body[pos] == ' ' || body[pos] == '\t') {
			pos++
		}
		if !bytes.HasPrefix(body[pos:], []byte("\r\n")) {
			return values, files, errMultipartMalformed
		}
		pos += 2
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
		next := bytes.Index(body[pos:], delim)
		if next < 0 {
			return values, files, errMultipartMalformed
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
