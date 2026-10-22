//go:build linux && amd64

package core

import (
	"io"
	"strings"
	"sync"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/molecule-man/go-brrr"
)

type encodingType uint8

const (
	encodingNone encodingType = iota
	encodingGzip
	encodingDeflate
	encodingBrotli
)

type encodingSet uint8

const (
	offerGzip    encodingSet = 1 << encodingGzip
	offerDeflate encodingSet = 1 << encodingDeflate
	offerBrotli  encodingSet = 1 << encodingBrotli

	offerAllEncodings = offerBrotli | offerGzip | offerDeflate
)

const (
	qvalueMax              = 1000
	qvalueUnset            = -1
	defaultBrotliLevel     = 4
	acceptEncodingWildcard = encodingNone
)

var contentEncodingNames = [...]string{
	encodingGzip:    "gzip",
	encodingDeflate: "deflate",
	encodingBrotli:  "br",
}

type streamCompressor interface {
	Reset(dst io.Writer)
	Write(p []byte) (int, error)
	Close() error
}

type pooledEncoder struct {
	out bytesWriter
	zw  streamCompressor
	br  *brrr.Writer
}

var encoderPools [encodingBrotli + 1][brrr.BestCompression + 1]sync.Pool

func init() {
	for level := 1; level <= flate.BestCompression; level++ {
		encoderPools[encodingGzip][level].New = func() any {
			e := &pooledEncoder{}
			e.zw, _ = gzip.NewWriterLevel(&e.out, level)
			return e
		}
		encoderPools[encodingDeflate][level].New = func() any {
			e := &pooledEncoder{}
			e.zw, _ = flate.NewWriter(&e.out, level)
			return e
		}
	}
	for level := range encoderPools[encodingBrotli] {
		encoderPools[encodingBrotli][level].New = func() any {
			e := &pooledEncoder{}
			e.br, _ = brrr.NewWriter(&e.out, level)
			e.zw = e.br
			return e
		}
	}
}

func (e *pooledEncoder) appendCompressed(dst, body []byte) []byte {
	e.out.buf = dst
	if e.br != nil {
		e.br.ResetWithSizeHint(&e.out, uint(len(body)))
	} else {
		e.zw.Reset(&e.out)
	}
	_, _ = e.zw.Write(body)
	_ = e.zw.Close()
	dst = e.out.buf
	e.out.buf = nil
	return dst
}

func negotiateEncoding(accept string, offered encodingSet) encodingType {
	if accept == "" || offered == 0 {
		return encodingNone
	}
	brotliWeight, gzipWeight, deflateWeight, wildcardWeight := int16(qvalueUnset), int16(qvalueUnset), int16(qvalueUnset), int16(qvalueUnset)
	for i := 0; i < len(accept); i++ {
		for i < len(accept) && isOWS(accept[i]) {
			i++
		}
		start := i
		for i < len(accept) && accept[i] != ',' && accept[i] != ';' {
			i++
		}
		codingEnd := i
		for codingEnd > start && isOWS(accept[codingEnd-1]) {
			codingEnd--
		}
		weight := int16(qvalueMax)
		if i < len(accept) && accept[i] == ';' {
			paramsStart := i + 1
			for i < len(accept) && accept[i] != ',' {
				i++
			}
			weight = acceptWeight(accept[paramsStart:i])
		}
		switch coding := accept[start:codingEnd]; len(coding) {
		case 1:
			if coding[0] == '*' {
				wildcardWeight = weight
			}
		case 2:
			if coding[0]|asciiCaseBit == 'b' && coding[1]|asciiCaseBit == 'r' {
				brotliWeight = weight
			}
		case 4:
			if isGzipToken(coding) {
				gzipWeight = weight
			}
		case 6:
			if coding[0]|asciiCaseBit == 'x' && coding[1] == '-' && isGzipToken(coding[2:]) {
				gzipWeight = weight
			}
		case 7:
			if isDeflateToken(coding) {
				deflateWeight = weight
			}
		}
	}
	best, bestWeight := encodingNone, int16(0)
	if offered&offerBrotli != 0 {
		best, bestWeight = preferEncoding(best, bestWeight, encodingBrotli, brotliWeight, wildcardWeight)
	}
	if offered&offerGzip != 0 {
		best, bestWeight = preferEncoding(best, bestWeight, encodingGzip, gzipWeight, wildcardWeight)
	}
	if offered&offerDeflate != 0 {
		best, _ = preferEncoding(best, bestWeight, encodingDeflate, deflateWeight, wildcardWeight)
	}
	return best
}

func preferEncoding(best encodingType, bestWeight int16, enc encodingType, weight, wildcardWeight int16) (encodingType, int16) {
	if weight == qvalueUnset {
		weight = wildcardWeight
	}
	if weight > bestWeight {
		return enc, weight
	}
	return best, bestWeight
}

func isOWS(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func isDeflateToken(s string) bool {
	return s[0]|asciiCaseBit == 'd' && s[1]|asciiCaseBit == 'e' && s[2]|asciiCaseBit == 'f' && s[3]|asciiCaseBit == 'l' &&
		s[4]|asciiCaseBit == 'a' && s[5]|asciiCaseBit == 't' && s[6]|asciiCaseBit == 'e'
}

func isGzipToken(s string) bool {
	return s[0]|asciiCaseBit == 'g' && s[1]|asciiCaseBit == 'z' && s[2]|asciiCaseBit == 'i' && s[3]|asciiCaseBit == 'p'
}

func acceptWeight(params string) int16 {
	for i := 0; i < len(params); i++ {
		for i < len(params) && isOWS(params[i]) {
			i++
		}
		start := i
		for i < len(params) && params[i] != ';' {
			i++
		}
		if i-start >= 2 && params[start]|asciiCaseBit == 'q' && params[start+1] == '=' {
			end := i
			for end > start+2 && isOWS(params[end-1]) {
				end--
			}
			return parseQValue(params[start+2 : end])
		}
	}
	return qvalueMax
}

func parseQValue(s string) int16 {
	if len(s) == 0 || len(s) > len("1.000") || (s[0] != '0' && s[0] != '1') {
		return 0
	}
	whole := int16(s[0]-'0') * qvalueMax
	if len(s) == 1 {
		return whole
	}
	if s[1] != '.' {
		return 0
	}
	frac, scale := int16(0), int16(qvalueMax/10)
	for i := 2; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		frac += int16(c-'0') * scale
		scale /= 10
	}
	if whole == qvalueMax && frac != 0 {
		return 0
	}
	return whole + frac
}

func normalizeBrotliLevel(level int) int {
	if level < 1 || level > brrr.BestCompression {
		return defaultBrotliLevel
	}
	return level
}

func appendCompressed(dst, body []byte, enc encodingType, level int) []byte {
	pool := &encoderPools[enc][level]
	e, ok := pool.Get().(*pooledEncoder)
	if !ok {
		return dst
	}
	dst = e.appendCompressed(dst, body)
	pool.Put(e)
	return dst
}

func varyCoversAcceptEncoding(headers [][2]string) bool {
	return varyCovers(headers, "accept-encoding")
}

func varyCovers(headers [][2]string, field string) bool {
	for i := range headers {
		if !EqualFoldASCII(headers[i][0], "vary") {
			continue
		}
		for rest := headers[i][1]; rest != ""; {
			var listed string
			listed, rest, _ = strings.Cut(rest, ",")
			listed = trimASCIISpace(listed)
			if listed == "*" || EqualFoldASCII(listed, field) {
				return true
			}
		}
	}
	return false
}

func addVaryAcceptEncoding(resp *Response) {
	addVaryField(resp, "Accept-Encoding")
}

func addVaryField(resp *Response, field string) {
	if len(resp.Headers) == 0 || !varyCovers(resp.Headers, field) {
		resp.Headers = append(resp.Headers, [2]string{"Vary", field})
	}
}
