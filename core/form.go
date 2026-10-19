//go:build linux && amd64

package core

import (
	"bytes"
	"io"
)

// FileHeader describes a single file uploaded in a multipart/form-data request.
//
// Filename is the client-provided file name (e.g. "photo.png").
// Size is the file size in bytes.
// ContentType is the part's Content-Type, defaulting to "application/octet-stream".
// Data holds the raw file bytes.
type FileHeader struct {
	Filename    string
	Size        int64
	ContentType string
	Header      [][2]string
	Data        []byte
}

func (fh FileHeader) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(fh.Data)), nil
}

func parseFormURLEncoded(body []byte) map[string][]string {
	return parseQueryString(string(body))
}
