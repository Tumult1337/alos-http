//go:build linux && amd64

package core

import "errors"

const chunkedFramingLineMax = 4096

var errChunkedMalformed = errors.New("core: malformed chunked request body")

const (
	chunkedAwaitSize = iota
	chunkedInData
	chunkedAwaitDataEnd
	chunkedInTrailer
	chunkedDone
)

type chunkedDecoder struct {
	state           uint8
	captureTrailers bool
	left            int64
	trailerBytes    int
	trailers        [][2]string
}

func parseChunkSizeLine(line []byte) (int64, bool) {
	if len(line) == 0 || line[len(line)-1] != '\r' {
		return 0, false
	}
	line = line[:len(line)-1]
	digits := 0
	for digits < len(line) && hexValid[line[digits]] {
		digits++
	}
	size, ok := parseHex64Bytes(line[:digits])
	if !ok || !validChunkExtensions(line[digits:]) {
		return 0, false
	}
	return size, true
}

func validChunkExtensions(ext []byte) bool {
	for i := 0; i < len(ext); {
		i = skipBWS(ext, i)
		if i >= len(ext) || ext[i] != ';' {
			return false
		}
		i = skipBWS(ext, i+1)
		nameEnd := skipToken(ext, i)
		if nameEnd == i {
			return false
		}
		i = nameEnd
		if eq := skipBWS(ext, nameEnd); eq < len(ext) && ext[eq] == '=' {
			if i = skipChunkExtValue(ext, skipBWS(ext, eq+1)); i < 0 {
				return false
			}
		}
	}
	return true
}

func skipBWS(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	return i
}

func skipToken(b []byte, i int) int {
	for i < len(b) && h1TokenChar[b[i]] {
		i++
	}
	return i
}

func skipChunkExtValue(b []byte, i int) int {
	if i >= len(b) || b[i] != '"' {
		if end := skipToken(b, i); end > i {
			return end
		}
		return -1
	}
	for j := i + 1; j < len(b); j++ {
		switch c := b[j]; {
		case c == '"':
			return j + 1
		case c == '\\':
			j++
			if j >= len(b) || !quotedPairByte(b[j]) {
				return -1
			}
		case !qdtextByte(c):
			return -1
		}
	}
	return -1
}

func qdtextByte(c byte) bool {
	return c == '\t' || c == ' ' || c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) || c >= 0x80
}

func quotedPairByte(c byte) bool {
	return c == '\t' || (c >= ' ' && c <= 0x7e) || c >= 0x80
}

func (d *chunkedDecoder) done() bool { return d.state == chunkedDone }

func (d *chunkedDecoder) next(src []byte) (consumed int, data []byte, err error) {
	switch d.state {
	case chunkedInData:
		n := min(int64(len(src)), d.left)
		d.left -= n
		if d.left == 0 {
			d.state = chunkedAwaitDataEnd
		}
		return int(n), src[:n], nil
	case chunkedAwaitDataEnd:
		if len(src) < 2 {
			return 0, nil, nil
		}
		if src[0] != '\r' || src[1] != '\n' {
			return 0, nil, errChunkedMalformed
		}
		d.state = chunkedAwaitSize
		return 2, nil, nil
	case chunkedDone:
		return 0, nil, nil
	}
	nl := indexByteFrom(src[:min(len(src), chunkedFramingLineMax)], '\n', 0)
	if nl < 0 {
		if len(src) >= chunkedFramingLineMax {
			return 0, nil, errChunkedMalformed
		}
		return 0, nil, nil
	}
	if d.state == chunkedInTrailer {
		d.trailerBytes += nl + 1
		if d.trailerBytes > chunkedFramingLineMax {
			return 0, nil, errChunkedMalformed
		}
		if nl == 1 && src[0] == '\r' {
			d.state = chunkedDone
			return nl + 1, nil, nil
		}
		name, value, ok := splitTrailerLine(src[:nl+1])
		if !ok {
			return 0, nil, errChunkedMalformed
		}
		if d.captureTrailers {
			d.trailers = appendTrailerField(d.trailers, string(name), string(value))
		}
		return nl + 1, nil, nil
	}
	size, ok := parseChunkSizeLine(src[:nl])
	if !ok {
		return 0, nil, errChunkedMalformed
	}
	if size == 0 {
		d.state = chunkedInTrailer
	} else {
		d.state, d.left = chunkedInData, size
	}
	return nl + 1, nil, nil
}
