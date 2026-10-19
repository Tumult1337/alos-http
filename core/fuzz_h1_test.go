//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

var fuzzH1Seeds = [][]byte{
	[]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
	[]byte("GET / HTTP/1.0\r\n\r\n"),
	[]byte("POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"),
	[]byte("POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc"),
	[]byte("GET /a HTTP/1.1\r\nHost: a\r\nX: b\nc\r\n\r\n"),
	[]byte("GET /a HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n"),
	[]byte("GET http://h/p?q HTTP/1.1\r\nHost: x\r\n\r\n"),
	[]byte("GET /a\x00b HTTP/1.1\r\nHost: a\r\n\r\n"),
	[]byte("GET /../../etc/passwd HTTP/1.1\r\nHost: a\r\n\r\n"),
	[]byte("HACK /x HTTP/1.1\r\nHost: a\r\n\r\n"),
	[]byte("DOODLE /x HTTP/1.1\r\nHost: a\r\n\r\n"),
}

func FuzzParseH1RequestHead(f *testing.F) {
	for _, s := range [][]byte{benchReqTypical, benchReqPost, gateReqBrowser} {
		f.Add(s)
	}
	for _, s := range fuzzH1Seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		req := &Request{Headers: make([][2]string, 0, 16)}
		headerEnd, contentLength, hasContentLength, _, rejected, _, _, ok := ParseH1RequestHead(data, req, 8192, 128)
		if !ok || rejected {
			return
		}
		if sp := bytes.IndexByte(data, ' '); sp < 0 || req.Method != string(data[:sp]) {
			t.Fatalf("method %q does not match request line %q", req.Method, data[:min(len(data), 32)])
		}
		if headerEnd < 2 || headerEnd > len(data) {
			t.Fatalf("headerEnd %d out of range for len %d", headerEnd, len(data))
		}
		if !bytes.Equal(data[headerEnd-2:headerEnd], []byte("\r\n")) {
			t.Fatalf("headerEnd %d does not follow a CRLF", headerEnd)
		}
		if req.Method == "" {
			t.Fatal("accepted request has empty method")
		}
		if hasContentLength && contentLength < -1 {
			t.Fatalf("content length %d below the -1 sentinel", contentLength)
		}
		if len(req.Headers) > 128 {
			t.Fatalf("header count %d exceeds limit", len(req.Headers))
		}
	})
}
