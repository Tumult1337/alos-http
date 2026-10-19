//go:build linux && amd64

package core

import (
	"io"
	"strings"
	"testing"
)

func TestTLSEpollFixChunkedFramingIsStrict(t *testing.T) {
	rejected := []string{
		"5\nhello\r\n0\r\n\r\n",
		"5;x\nhello\r\n0\n\n",
		"5;a\rb\r\nhello\r\n0\r\n\r\n",
		"\t5\r\nhello\r\n0\r\n\r\n",
		" 5 \r\nhello\r\n0\r\n\r\n",
		"5 \r\nhello\r\n0\r\n\r\n",
		"5\r\r\nhello\r\n0\r\n\r\n",
		"5\r\nhello\r\n0\r\n\n",
		"5\r\nhello\r\n0\n\r\n",
		"5;a\x00b\r\nhello\r\n0\r\n\r\n",
		"5;\r\nhello\r\n0\r\n\r\n",
		"5;a=\r\nhello\r\n0\r\n\r\n",
		"5;a=\"x\r\nhello\r\n0\r\n\r\n",
		"5;a=\"x\ny\"\r\nhello\r\n0\r\n\r\n",
		"+5\r\nhello\r\n0\r\n\r\n",
		"5\r\nhello\r\n0\r\nX: y\n\r\n",
	}
	for _, body := range rejected {
		if _, status, _ := asyncChunkedComplete([]byte(body), 0); status != -1 {
			t.Errorf("asyncChunkedComplete(%q) status %d, want -1 (malformed)", body, status)
		}
		if _, _, ok := decodeChunkedInto(nil, []byte(body)); ok {
			t.Errorf("decodeChunkedInto(%q) accepted malformed framing", body)
		}
	}
	accepted := []string{
		"5\r\nhello\r\n0\r\n\r\n",
		"5;name\r\nhello\r\n0\r\n\r\n",
		"5 ;name = value\r\nhello\r\n0\r\n\r\n",
		"5;a=1;b=\"q \\\" \\\\ x\"\r\nhello\r\n0;last\r\n\r\n",
		"5\t;\tname\r\nhello\r\n0\r\nX-Trailer: v\r\n\r\n",
		"2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n",
		"0005\r\nhello\r\n000\r\n\r\n",
	}
	for _, body := range accepted {
		end, status, _ := asyncChunkedComplete([]byte(body), 0)
		if status != 1 || end != len(body) {
			t.Errorf("asyncChunkedComplete(%q) = end %d status %d, want complete", body, end, status)
			continue
		}
		got, _, ok := decodeChunkedInto(nil, []byte(body))
		if !ok || string(got) != "hello" {
			t.Errorf("decodeChunkedInto(%q) = %q ok=%v, want hello", body, got, ok)
		}
	}
}

func TestTLSEpollFixChunkedBareLFRejectedEndToEnd(t *testing.T) {
	ts := newTestServer(t, testServerOptions{Routes: func(r *Router) {
		r.POST("/", func(req *Request, resp *Response) { resp.Status(200).String("body=" + string(req.Body)) })
	}})
	for _, framing := range []string{"5\nhello\r\n0\r\n\r\n", "5;a\rb\r\nhello\r\n0\r\n\r\n", "5\r\nhello\r\n0\n\n"} {
		resp, body := ts.rawH1(t, "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"+framing)
		if resp.StatusCode != 400 {
			t.Fatalf("framing %q answered %d %q, want 400", framing, resp.StatusCode, body)
		}
	}
	c := ts.dial(t)
	if _, err := io.WriteString(c, "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5;ext=\"v\"\r\nhello\r\n0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(c)
	if !strings.Contains(string(raw), "200 OK") || !strings.HasSuffix(string(raw), "body=hello") {
		t.Fatalf("valid chunked body answered %q", raw)
	}
}
