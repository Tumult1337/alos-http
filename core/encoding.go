//go:build linux && amd64

package core

import (
	"bytes"
	"io"
	"math/bits"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
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
	brotliWindowSlack      = 16
	brotliMinWindowBits    = 10
	brotliMaxWindowBits    = 22
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

type acceptEncodingWeights struct {
	brotli, gzip, deflate, wildcard int16
}

func (w *acceptEncodingWeights) accepts(weight int16) bool {
	if weight == qvalueUnset {
		weight = w.wildcard
	}
	return weight > 0
}

func negotiateEncoding(accept string, offered encodingSet) encodingType {
	if accept == "" || offered == 0 {
		return encodingNone
	}
	w := parseAcceptEncoding(accept)
	best, bestWeight := encodingNone, int16(0)
	if offered&offerBrotli != 0 {
		best, bestWeight = preferEncoding(best, bestWeight, encodingBrotli, w.brotli, w.wildcard)
	}
	if offered&offerGzip != 0 {
		best, bestWeight = preferEncoding(best, bestWeight, encodingGzip, w.gzip, w.wildcard)
	}
	if offered&offerDeflate != 0 {
		best, _ = preferEncoding(best, bestWeight, encodingDeflate, w.deflate, w.wildcard)
	}
	return best
}

func parseAcceptEncoding(accept string) acceptEncodingWeights {
	w := acceptEncodingWeights{brotli: qvalueUnset, gzip: qvalueUnset, deflate: qvalueUnset, wildcard: qvalueUnset}
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
				w.wildcard = weight
			}
		case 2:
			if coding[0]|asciiCaseBit == 'b' && coding[1]|asciiCaseBit == 'r' {
				w.brotli = weight
			}
		case 4:
			if isGzipToken(coding) {
				w.gzip = weight
			}
		case 6:
			if coding[0]|asciiCaseBit == 'x' && coding[1] == '-' && isGzipToken(coding[2:]) {
				w.gzip = weight
			}
		case 7:
			if isDeflateToken(coding) {
				w.deflate = weight
			}
		}
	}
	return w
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

func brotliWindowFor(size int) int {
	return min(max(bits.Len(uint(size+brotliWindowSlack)), brotliMinWindowBits), brotliMaxWindowBits)
}

func compressOnce(body []byte, enc encodingType, level int) []byte {
	if enc != encodingBrotli {
		return compressedCopy(body, enc, level)
	}
	var out bytesWriter
	w := brotli.NewWriterOptions(&out, brotli.WriterOptions{Quality: level, LGWin: brotliWindowFor(len(body))})
	if _, err := w.Write(body); err != nil {
		return nil
	}
	if w.Close() != nil || len(out.buf) == 0 || len(out.buf) >= len(body) {
		return nil
	}
	return bytes.Clone(out.buf)
}

func compressedCopy(body []byte, enc encodingType, level int) []byte {
	bp := LargeBufPool.Get().(*[]byte)
	buf := appendCompressed((*bp)[:0], body, enc, level)
	var out []byte
	if len(buf) > 0 && len(buf) < len(body) {
		out = make([]byte, len(buf))
		copy(out, buf)
	}
	*bp = buf
	putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
	return out
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
