//go:build linux && amd64

package core

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/textproto"
	"slices"
)

func mimeHeaderPairs(h textproto.MIMEHeader) [][2]string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	pairs := make([][2]string, 0, len(keys))
	for _, k := range keys {
		for _, v := range h[k] {
			pairs = append(pairs, [2]string{k, v})
		}
	}
	return pairs
}

func parseMultipartStdlibReference(body []byte, boundary string) (map[string][]string, map[string][]FileHeader, error) {
	values := make(map[string][]string)
	files := make(map[string][]FileHeader)
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for parts := 0; ; parts++ {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			return values, files, nil
		}
		if err != nil {
			return nil, nil, errMultipartMalformed
		}
		if parts == maxMultipartParts {
			return nil, nil, errMultipartTooManyParts
		}
		part, ok := interpretMultipartHeader(mimeHeaderPairs(p.Header))
		if !ok {
			return nil, nil, errMultipartMalformed
		}
		data, err := io.ReadAll(p)
		if err != nil {
			return nil, nil, errMultipartMalformed
		}
		switch {
		case part.name == "":
		case part.hasFilename:
			addMultipartFile(files, part, FileHeader{Size: int64(len(data)), Data: data})
		default:
			addMultipartValue(values, part, data)
		}
	}
}

func hasBareLF(b []byte) bool {
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			return true
		}
	}
	return false
}
