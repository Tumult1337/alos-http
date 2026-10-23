//go:build linux && amd64

package core

import (
	"reflect"
	"strings"
	"testing"
)

type h1ParseOutcome struct {
	headerEnd, contentLength                           int
	hasContentLength, closeConn, chunked, tooLarge, ok bool
	reject                                             h1RejectReason
}

func parseBoth(raw []byte, maxBytes, maxCount int) (got, want h1ParseOutcome, gotReq, wantReq *Request) {
	gotReq, wantReq = &Request{}, &Request{}
	got.headerEnd, got.contentLength, got.hasContentLength, got.closeConn, got.reject, got.chunked, got.tooLarge, got.ok = parseH1RequestHead(raw, gotReq, maxBytes, maxCount)
	want.headerEnd, want.contentLength, want.hasContentLength, want.closeConn, want.reject, want.chunked, want.tooLarge, want.ok = parseH1RequestHeadRef(raw, wantReq, maxBytes, maxCount)
	return got, want, gotReq, wantReq
}

func checkParseMatchesRef(t *testing.T, raw []byte, maxBytes, maxCount int) {
	t.Helper()
	got, want, gotReq, wantReq := parseBoth(raw, maxBytes, maxCount)
	if got != want {
		t.Fatalf("%q: got %+v, reference %+v", raw, got, want)
	}
	if want.ok && want.reject == h1RejectNone && !want.tooLarge && !reflect.DeepEqual(gotReq, wantReq) {
		t.Fatalf("%q: request state differs\n got  %+v\n want %+v", raw, gotReq, wantReq)
	}
}

var rootGetRequestShapes = []struct {
	name string
	raw  []byte
}{
	{"wrk", []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1:18443\r\n\r\n")},
	{"curl", []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n")},
	{"browser", []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nsec-ch-ua: \"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\"\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: \"Windows\"\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nSec-Fetch-Site: none\r\nSec-Fetch-Mode: navigate\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n")},
}

func h1ParseTemplates() []string {
	out := []string{
		string(benchReqTypical),
		string(benchReqPost),
		"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
		"GET / HTTP/1.0\r\nUser-Agent: x\r\nConnection: keep-alive\r\nX-Pad: " + strings.Repeat("p", 40) + "\r\n\r\n",
		"POST /u HTTP/1.1\r\nHost: h.example:8080\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\nX-Forwarded-For: 1.2.3.4\r\nX-Real-IP: 5.6.7.8\r\n\r\n",
		"GET http://abs.example/p?q=1 HTTP/1.1\r\nHost: other\r\nOrigin: https://o\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer t\r\nAccept-Encoding: gzip\r\n\r\n",
	}
	for _, r := range rootGetRequestShapes {
		out = append(out, string(r.raw))
	}
	for _, c := range h1StrictCases() {
		out = append(out, c.raw)
	}
	out = append(out, h2Fix2H1FramingTemplates()...)
	return out
}

func TestParseH1MatchesReferenceOnTemplates(t *testing.T) {
	for _, tmpl := range h1ParseTemplates() {
		checkParseMatchesRef(t, []byte(tmpl), 8192, 128)
		for n := 0; n < len(tmpl); n++ {
			checkParseMatchesRef(t, []byte(tmpl[:n]), 8192, 128)
		}
	}
}

func TestParseH1MatchesReferenceOnEveryByte(t *testing.T) {
	checked := 0
	for _, tmpl := range h1ParseTemplates()[:3] {
		raw := []byte(tmpl)
		for pos := 0; pos < len(raw); pos++ {
			orig := raw[pos]
			for c := 0; c < 256; c++ {
				raw[pos] = byte(c)
				checkParseMatchesRef(t, raw, 8192, 128)
				checked++
			}
			raw[pos] = orig
		}
	}
	t.Logf("checked %d requests", checked)
}

func TestParseH1MatchesReferenceAtLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\nHost: a\r\n")
	for i := 0; i < 40; i++ {
		b.WriteString("X-Header-Number: value-value-value\r\n")
	}
	b.WriteString("\r\n")
	raw := []byte(b.String())
	for _, maxCount := range []int{1, 2, 10, 40, 41, 42, 128} {
		checkParseMatchesRef(t, raw, 8192, maxCount)
	}
	for _, maxBytes := range []int{16, 64, 200, len(raw) - 3, len(raw) - 2, len(raw) - 1, len(raw), 8192} {
		checkParseMatchesRef(t, raw, maxBytes, 128)
	}
	big := "GET / HTTP/1.1\r\nHost: a\r\nX-Big: " + strings.Repeat("v", 1024) + "\r\n\r\n"
	checkParseMatchesRef(t, []byte(big), 8192, 128)
}

func FuzzParseH1Differential(f *testing.F) {
	for _, tmpl := range h1ParseTemplates() {
		f.Add([]byte(tmpl))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		checkParseMatchesRef(t, raw, 8192, 128)
		checkParseMatchesRef(t, raw, 256, 8)
	})
}
