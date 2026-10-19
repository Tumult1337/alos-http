//go:build linux && amd64

package core

import (
	"bytes"
	"strings"
	"testing"
)

func TestEpollChunkedPipelineRejectsWhatTheDecoderRejects(t *testing.T) {
	for name, wire := range chunkedMalformedCases {
		_, _, complete, _ := epollChunkedPipeline([]byte(wire))
		if complete {
			t.Errorf("%s: epoll pipeline accepted %q", name, wire)
		}
		if _, _, ok := decodeChunkedInto(nil, []byte(wire)); ok {
			t.Errorf("%s: decodeChunkedInto accepted %q", name, wire)
		}
	}
}

func TestEpollChunkedPipelineMatchesDecoderOnValidBodies(t *testing.T) {
	cases := []string{
		"5\r\nhello\r\n0\r\n\r\n",
		"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\n",
		"0\r\n\r\n",
		"1b58\r\n" + strings.Repeat("x", 0x1b58) + "\r\n0\r\n\r\n",
	}
	for _, wire := range cases {
		want := streamDecodeChunked([]byte(wire), len(wire)+1)
		if !want.done || want.err != nil {
			t.Fatalf("decoder rejected valid body %q: %v", wire, want.err)
		}
		body, end, complete, malformed := epollChunkedPipeline([]byte(wire + "GET / HTTP/1.1\r\n"))
		if !complete || malformed || end != want.consumed || !bytes.Equal(body, want.body) {
			t.Fatalf("%q: complete=%v malformed=%v end=%d want %d body=%q want %q", wire, complete, malformed, end, want.consumed, body, want.body)
		}
	}
}

func TestAsyncChunkedCompleteResumesFromChunkBoundary(t *testing.T) {
	wire := []byte("3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n")
	for cut := 1; cut < len(wire); cut++ {
		_, status, resume := asyncChunkedComplete(wire[:cut], 0)
		if status != 0 {
			t.Fatalf("cut %d: status %d, want need-more", cut, status)
		}
		end, status, _ := asyncChunkedComplete(wire, resume)
		if status != 1 || end != len(wire) {
			t.Fatalf("cut %d resume %d: status %d end %d, want 1/%d", cut, resume, status, end, len(wire))
		}
	}
}

func TestEpollRejectsChunkedBodyWithBadDataTerminator(t *testing.T) {
	ts := newTestServer(t, testServerOptions{Routes: func(r *Router) {
		r.POST("/up", func(req *Request, resp *Response) { resp.Status(200).Bytes(req.Body) })
	}})
	resp, _ := ts.rawH1(t, "POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX\r\n0\r\n\r\n")
	if resp.StatusCode != 400 {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	resp, body := ts.rawH1(t, "POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
	if resp.StatusCode != 200 || string(body) != "hello" {
		t.Fatalf("valid body: status %d body %q", resp.StatusCode, body)
	}
}
