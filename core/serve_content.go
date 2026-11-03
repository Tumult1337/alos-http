//go:build linux && amd64

package core

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type rangeOutcome uint8

const (
	rangeIgnored rangeOutcome = iota
	rangeSatisfiable
	rangeUnsatisfiable
)

type preconditionResult uint8

const (
	preconditionPass preconditionResult = iota
	preconditionNotModified
	preconditionFailed
)

const (
	byteRangeUnit       = "bytes"
	maxRangeIntDigits   = 18
	contentRangePrefix  = "bytes "
	unsatisfiablePrefix = "bytes */"
)

type contentValidators struct {
	etag         string
	lastModified string
	modUnix      int64
}

type httpDateEntry struct {
	unix int64
	text string
}

var lastHTTPDate atomic.Pointer[httpDateEntry]

func httpDate(unix int64) string {
	return cachedHTTPDate(&lastHTTPDate, unix)
}

func cachedHTTPDate(cache *atomic.Pointer[httpDateEntry], unix int64) string {
	if e := cache.Load(); e != nil && e.unix == unix {
		return e.text
	}
	text := time.Unix(unix, 0).UTC().Format(http.TimeFormat)
	cache.Store(&httpDateEntry{unix: unix, text: text})
	return text
}

func fileValidators(fi os.FileInfo) contentValidators {
	mod := fi.ModTime()
	var buf [40]byte
	tag := append(buf[:0], '"')
	tag = strconv.AppendUint(tag, uint64(mod.UnixNano()), 16)
	tag = append(tag, '-')
	tag = strconv.AppendUint(tag, uint64(fi.Size()), 16)
	tag = append(tag, '"')
	return contentValidators{etag: string(tag), lastModified: httpDate(mod.Unix()), modUnix: mod.Unix()}
}

func isETagChar(c byte) bool {
	return c == 0x21 || (c >= 0x23 && c != 0x7f)
}

func scanETag(s string) (tag string, weak bool, rest string, ok bool) {
	if strings.HasPrefix(s, "W/") {
		weak = true
		s = s[2:]
	}
	if len(s) < 2 || s[0] != '"' {
		return "", false, "", false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			return s[:i+1], weak, s[i+1:], true
		}
		if !isETagChar(c) {
			return "", false, "", false
		}
	}
	return "", false, "", false
}

func skipListSeparators(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == ',') {
		s = s[1:]
	}
	return s
}

func etagListContains(list, current string, strong bool) bool {
	for {
		list = skipListSeparators(list)
		if list == "" {
			return false
		}
		if list[0] == '*' {
			rest := trimASCIISpace(list[1:])
			return rest == "" || rest[0] == ','
		}
		tag, weak, rest, ok := scanETag(list)
		if !ok {
			return false
		}
		if tag == current && !(strong && weak) {
			return true
		}
		list = rest
	}
}

func etagHeaderMatches(req *Request, name, current string, strong bool) (present, matched bool) {
	for i := range req.Headers {
		if !EqualFoldASCII(req.Headers[i][0], name) {
			continue
		}
		present = true
		if etagListContains(req.Headers[i][1], current, strong) {
			return true, true
		}
	}
	return present, false
}

func headerUnixDate(req *Request, name string, v *contentValidators) (int64, bool) {
	value := req.Header(name)
	if value == "" {
		return 0, false
	}
	if value == v.lastModified {
		return v.modUnix, true
	}
	t, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	return t.Unix(), true
}

func evaluatePreconditions(req *Request, v *contentValidators) preconditionResult {
	safeMethod := req.Method == "GET" || req.Method == "HEAD"
	if present, matched := etagHeaderMatches(req, "If-Match", v.etag, true); present {
		if !matched {
			return preconditionFailed
		}
	} else if since, ok := headerUnixDate(req, "If-Unmodified-Since", v); ok && v.modUnix > since {
		return preconditionFailed
	}
	if present, matched := etagHeaderMatches(req, "If-None-Match", v.etag, false); present {
		if matched {
			if safeMethod {
				return preconditionNotModified
			}
			return preconditionFailed
		}
	} else if safeMethod {
		if since, ok := headerUnixDate(req, "If-Modified-Since", v); ok && v.modUnix <= since {
			return preconditionNotModified
		}
	}
	return preconditionPass
}

func ifRangeAllows(req *Request, v *contentValidators) bool {
	cond := req.Header("If-Range")
	if cond == "" {
		return true
	}
	if cond[0] == '"' || strings.HasPrefix(cond, "W/") {
		tag, weak, rest, ok := scanETag(cond)
		return ok && !weak && trimASCIISpace(rest) == "" && tag == v.etag
	}
	unix, ok := headerUnixDate(req, "If-Range", v)
	return ok && unix == v.modUnix
}

func parseRangeInt(s string) (int64, bool) {
	if s == "" || len(s) > maxRangeIntDigits {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}

func parseByteRange(header string, size int64) (start, length int64, outcome rangeOutcome) {
	eq := strings.IndexByte(header, '=')
	if eq < 0 || !EqualFoldASCII(header[:eq], byteRangeUnit) {
		return 0, 0, rangeIgnored
	}
	spec := trimASCIISpace(header[eq+1:])
	if spec == "" || strings.IndexByte(spec, ',') >= 0 {
		return 0, 0, rangeIgnored
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return 0, 0, rangeIgnored
	}
	firstText, lastText := spec[:dash], spec[dash+1:]
	if firstText == "" {
		suffix, ok := parseRangeInt(lastText)
		if !ok {
			return 0, 0, rangeIgnored
		}
		if suffix == 0 || size == 0 {
			return 0, 0, rangeUnsatisfiable
		}
		if suffix > size {
			suffix = size
		}
		return size - suffix, suffix, rangeSatisfiable
	}
	first, ok := parseRangeInt(firstText)
	if !ok {
		return 0, 0, rangeIgnored
	}
	last := size - 1
	if lastText != "" {
		requested, ok := parseRangeInt(lastText)
		if !ok || requested < first {
			return 0, 0, rangeIgnored
		}
		if requested < last {
			last = requested
		}
	}
	if first >= size {
		return 0, 0, rangeUnsatisfiable
	}
	return first, last - first + 1, rangeSatisfiable
}

func formatContentRange(start, length, size int64) string {
	var buf [64]byte
	b := append(buf[:0], contentRangePrefix...)
	b = strconv.AppendInt(b, start, 10)
	b = append(b, '-')
	b = strconv.AppendInt(b, start+length-1, 10)
	b = append(b, '/')
	b = strconv.AppendInt(b, size, 10)
	return string(b)
}

func (cfg *sendFileConfig) limiter() *TokenBucket {
	if cfg == nil || cfg.rateLimit <= 0 {
		return nil
	}
	burst := cfg.burstSize
	if burst <= 0 {
		burst = cfg.rateLimit
	}
	return NewTokenBucket(cfg.rateLimit, burst)
}

func (r *Response) serveContent(req *Request, f *os.File, fi os.FileInfo, contentType string, cfg *sendFileConfig) error {
	v := fileValidators(fi)
	size := fi.Size()
	status, start, length := 200, int64(0), size
	contentRange := ""
	method := ""
	if req != nil {
		method = req.Method
		switch evaluatePreconditions(req, &v) {
		case preconditionNotModified:
			r.SetHeader("ETag", v.etag).SetHeader("Last-Modified", v.lastModified).Status(304)
			return nil
		case preconditionFailed:
			r.Status(412).String("Precondition Failed")
			return nil
		}
		if spec := req.Header("Range"); spec != "" && method == "GET" && ifRangeAllows(req, &v) {
			rangeStart, rangeLength, outcome := parseByteRange(spec, size)
			switch outcome {
			case rangeUnsatisfiable:
				r.SetHeader("Content-Range", unsatisfiablePrefix+strconv.FormatInt(size, 10)).Status(416).String("Range Not Satisfiable")
				return nil
			case rangeSatisfiable:
				status, start, length = 206, rangeStart, rangeLength
				contentRange = formatContentRange(rangeStart, rangeLength, size)
			}
		}
	}

	hdrs := make([][2]string, 0, 6)
	hdrs = append(hdrs, [2]string{"accept-ranges", byteRangeUnit}, [2]string{"etag", v.etag}, [2]string{"last-modified", v.lastModified})
	if contentRange != "" {
		hdrs = append(hdrs, [2]string{"content-range", contentRange})
	}
	if cfg != nil && cfg.attachment != "" {
		hdrs = append(hdrs, [2]string{
			"content-disposition",
			"attachment; filename=\"" + sanitizeFilename(cfg.attachment) + "\"",
		})
	}
	hdrs = append(hdrs, [2]string{"content-length", strconv.FormatInt(length, 10)})

	sw := r.ensureSW()
	if sw == nil {
		return r.sendFileBuffered(f, start, length, status, contentType, hdrs)
	}
	if err := sw.WriteHeader(status, hdrs, contentType); err != nil {
		return err
	}
	r.SetStreamer(sw)
	if method == "HEAD" {
		return sw.Close()
	}
	return streamFileRange(sw, f, start, length, cfg.limiter())
}

func streamFileRange(sw StreamWriter, f *os.File, start, length int64, limiter *TokenBucket) error {
	if sent, err := trySendFileFastPath(sw, f, start, length, limiter); sent {
		if err != nil {
			return err
		}
		return sw.Close()
	}

	bp := FileReadBufPool.Get().(*[]byte)
	buf := *bp
	defer FileReadBufPool.Put(bp)

	pos, end := start, start+length
	for pos < end {
		chunk := buf
		if remaining := end - pos; remaining < int64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		n, readErr := f.ReadAt(chunk, pos)
		if n > 0 {
			if limiter != nil {
				limiter.Wait(int64(n))
			}
			if writeErr := sw.WriteChunk(chunk[:n]); writeErr != nil {
				return writeErr
			}
			pos += int64(n)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && pos >= end {
				break
			}
			if errors.Is(readErr, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return readErr
		}
	}
	return sw.Close()
}
