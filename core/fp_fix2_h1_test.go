//go:build linux && amd64

package core

import (
	"io"
	"net"
	"slices"
	"testing"
)

func TestFPFix2ResponseFieldNameWhitespaceIsRemoved(t *testing.T) {
	var p h1Parser
	block := []byte("HTTP/1.1 200 OK\r\nContent-Type : text/html\r\nContent-Length\t: 5\r\nX-Multi \t : v\r\nX-Plain: w\r\n")
	chunked, contentLen, err := p.parseHeaderBlock(block, "GET")
	if err != nil || chunked || contentLen != 5 {
		t.Fatalf("whitespace before colon: chunked=%v len=%d err=%v", chunked, contentLen, err)
	}
	var got [][2]string
	for _, h := range p.hdr {
		got = append(got, [2]string{string(h[0]), string(h[1])})
	}
	want := [][2]string{{"content-type", "text/html"}, {"content-length", "5"}, {"x-multi", "v"}, {"x-plain", "w"}}
	if !slices.Equal(got, want) {
		t.Fatalf("headers %q, want %q", got, want)
	}
}

func TestFPFix2ResponseFieldNameWhitespaceStillRejectsBadLines(t *testing.T) {
	for _, line := range []string{
		" : x",
		"\t: x",
		"X A : b",
		"X-A \x00: b",
		"X-A \r: b",
		"X-A  b",
		" folded : b",
	} {
		var p h1Parser
		block := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n" + line)
		if _, _, err := p.parseHeaderBlock(block, "GET"); err == nil {
			t.Errorf("%q: accepted", line)
		}
	}
}

func TestFPFix2ProxyForwardsRepairedFieldName(t *testing.T) {
	addr := rawOrigin(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type : text/plain\r\nContent-Length : 2\r\n\r\nok")
	})
	resp, err := fpFixClientGet(t, addr)
	if err != nil || resp.Status != 200 || string(resp.Body) != "ok" {
		t.Fatalf("legacy backend: %v %+v", err, resp)
	}
	if !slices.Contains(resp.Headers, [2]string{"content-type", "text/plain"}) {
		t.Fatalf("headers %q lack the repaired content-type", resp.Headers)
	}
}
