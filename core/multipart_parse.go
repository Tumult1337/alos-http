//go:build linux && amd64

package core

import (
	"bytes"
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	maxMultipartParts       = 1000
	maxMultipartHeaderBytes = 8 << 10
	maxUploadFilenameBytes  = 255
	maxMultipartBoundary    = 70
	defaultUploadType       = "application/octet-stream"
	mimeTSpecials           = `()<>@,;:\"/[]?=`
)

var (
	errMultipartMalformed    = errors.New("core: malformed multipart body")
	errMultipartTooManyParts = errors.New("core: too many multipart parts")
)

type multipartPart struct {
	name        string
	filename    string
	hasFilename bool
	contentType string
	header      [][2]string
}

func multipartBoundary(contentType string) string {
	semi := strings.IndexByte(contentType, ';')
	if semi < 0 || !EqualFoldASCII(trimASCIISpace(contentType[:semi]), "multipart/form-data") {
		return ""
	}
	var boundary string
	forEachHeaderParam(contentType[semi+1:], func(key, value string) {
		if EqualFoldASCII(key, "boundary") {
			boundary = value
		}
	})
	if len(boundary) == 0 || len(boundary) > maxMultipartBoundary {
		return ""
	}
	return boundary
}

func forEachHeaderParam(params string, fn func(key, value string)) {
	for len(params) > 0 {
		params = strings.TrimLeft(params, " \t;")
		eq := strings.IndexByte(params, '=')
		if eq <= 0 {
			return
		}
		key := trimASCIISpace(params[:eq])
		rest := strings.TrimLeft(params[eq+1:], " \t")
		var value string
		if len(rest) > 0 && rest[0] == '"' {
			value, rest = unquoteParam(rest)
		} else {
			end := strings.IndexByte(rest, ';')
			if end < 0 {
				end = len(rest)
			}
			value, rest = trimASCIISpace(rest[:end]), rest[end:]
		}
		fn(key, value)
		params = rest
	}
}

func unquoteParam(s string) (value, rest string) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return b.String(), s[i+1:]
		case '\\':
			if i+1 < len(s) && strings.IndexByte(mimeTSpecials, s[i+1]) >= 0 {
				i++
			}
		}
		b.WriteByte(s[i])
	}
	return b.String(), ""
}

func parseContentDisposition(value string) (name, filename string, hasFilename, ok bool) {
	kind, params, _ := strings.Cut(value, ";")
	if !EqualFoldASCII(trimASCIISpace(kind), "form-data") {
		return "", "", false, false
	}
	var extended string
	hasExtended := false
	forEachHeaderParam(params, func(key, v string) {
		switch {
		case EqualFoldASCII(key, "name"):
			name = v
		case EqualFoldASCII(key, "filename"):
			filename, hasFilename = v, true
		case EqualFoldASCII(key, "filename*"):
			if decoded, valid := decodeRFC8187(v); valid {
				extended, hasExtended = decoded, true
			}
		}
	})
	if hasExtended {
		filename, hasFilename = extended, true
	}
	return name, filename, hasFilename, true
}

func decodeRFC8187(v string) (string, bool) {
	charset, rest, found := strings.Cut(v, "'")
	if !found || !EqualFoldASCII(charset, "utf-8") {
		return "", false
	}
	_, encoded, found := strings.Cut(rest, "'")
	if !found {
		return "", false
	}
	out := make([]byte, 0, len(encoded))
	for i := 0; i < len(encoded); i++ {
		c := encoded[i]
		if c != '%' {
			out = append(out, c)
			continue
		}
		if i+2 >= len(encoded) {
			return "", false
		}
		hi, lo := unhex(encoded[i+1]), unhex(encoded[i+2])
		if hi < 0 || lo < 0 {
			return "", false
		}
		out = append(out, byte(hi<<4|lo))
		i += 2
	}
	if !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func sanitizeUploadFilename(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	clean := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		if c := name[i]; c >= 0x20 && c != 0x7f {
			clean = append(clean, c)
		}
	}
	if len(clean) > maxUploadFilenameBytes {
		cut := maxUploadFilenameBytes
		for cut > 0 && !utf8.RuneStart(clean[cut]) {
			cut--
		}
		clean = clean[:cut]
	}
	if s := string(clean); s != "." && s != ".." {
		return s
	}
	return ""
}

func parseMultipartHeaderLines(block []byte) ([][2]string, bool) {
	var header [][2]string
	for len(block) > 0 {
		line := block
		if i := bytes.Index(block, []byte("\r\n")); i >= 0 {
			line, block = block[:i], block[i+2:]
		} else {
			block = nil
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !isH1Token(line[:colon]) || firstH1Special(line) >= 0 {
			return nil, false
		}
		header = append(header, [2]string{string(line[:colon]), string(trimOWS(line[colon+1:]))})
	}
	return header, true
}

func interpretMultipartHeader(header [][2]string) (multipartPart, bool) {
	part := multipartPart{header: header}
	for _, h := range header {
		switch {
		case EqualFoldASCII(h[0], "content-disposition"):
			name, filename, hasFilename, ok := parseContentDisposition(h[1])
			if !ok {
				return part, false
			}
			part.name, part.filename, part.hasFilename = name, sanitizeUploadFilename(filename), hasFilename
		case EqualFoldASCII(h[0], "content-type"):
			part.contentType = h[1]
		}
	}
	if part.hasFilename && part.contentType == "" {
		part.contentType = defaultUploadType
	}
	return part, true
}

func addMultipartValue(values map[string][]string, part multipartPart, data []byte) {
	values[part.name] = append(values[part.name], string(data))
}

func addMultipartFile(files map[string][]FileHeader, part multipartPart, fh FileHeader) {
	fh.Filename, fh.ContentType, fh.Header = part.filename, part.contentType, part.header
	files[part.name] = append(files[part.name], fh)
}
