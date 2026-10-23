//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

const (
	altSvcTestPort  = 4433
	altSvcTestValue = `h3=":4433"; ma=86400`
	altSvcTestLine  = "Alt-Svc: " + altSvcTestValue + "\r\n"
)

func altSvcServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	s := New(cfg)
	s.enableAltSvc(altSvcTestPort)
	return s
}

func altSvcResponse(s *Server, tls bool, headers ...[2]string) *Response {
	resp := &Response{StatusCode: 200}
	resp.Status(200).String("body")
	resp.Headers = append(resp.Headers, headers...)
	resp.lazyReq = &Request{Method: "GET", IsTLS: tls, server: s}
	if tls {
		addAltSvcHeader(resp, s)
	}
	return resp
}

func hpackAltSvcValues(t *testing.T, block []byte) []string {
	t.Helper()
	headers, err := newHpackDecoder(4096).Decode(block)
	if err != nil {
		t.Fatalf("HPACK block does not decode: %v", err)
	}
	var values []string
	for _, h := range headers {
		if EqualFoldASCII(h[0], altSvcHeaderName) {
			values = append(values, h[1])
		}
	}
	return values
}

func h1AltSvcValues(t *testing.T, raw []byte) []string {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("serialised response does not parse: %v\n%q", err, raw)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Header.Values("Alt-Svc")
}

func TestAltSvcHeaderEncoding(t *testing.T) {
	alt := newAltSvcHeader(altSvcTestPort)
	if string(alt.h1) != altSvcTestLine {
		t.Fatalf("H1 line %q, want %q", alt.h1, altSvcTestLine)
	}
	if got := hpackAltSvcValues(t, alt.hpack); len(got) != 1 || got[0] != altSvcTestValue {
		t.Fatalf("HPACK alt-svc %q, want [%q]", got, altSvcTestValue)
	}
}

func TestAltSvcOnlyAfterEnableAndNotWhenDisabled(t *testing.T) {
	if New(Config{}).altSvcFor(true) != nil {
		t.Fatal("Alt-Svc advertised before QUIC bound")
	}
	if altSvcServer(t, Config{DisableAltSvc: true}).altSvcFor(true) != nil {
		t.Fatal("Alt-Svc advertised with DisableAltSvc set")
	}
	s := New(Config{})
	s.enableAltSvc(0)
	if s.altSvcFor(true) != nil {
		t.Fatal("Alt-Svc advertised for port 0")
	}
}

func TestAltSvcH1Serializer(t *testing.T) {
	enabled := altSvcServer(t, Config{})
	disabled := altSvcServer(t, Config{DisableAltSvc: true})
	cases := []struct {
		name    string
		resp    *Response
		want    []string
		hasBody bool
	}{
		{"tls", altSvcResponse(enabled, true), []string{altSvcTestValue}, true},
		{"plain", altSvcResponse(enabled, false), nil, true},
		{"disabled", altSvcResponse(disabled, true), nil, true},
		{"handler-set", altSvcResponse(enabled, true, [2]string{"Alt-Svc", "clear"}), []string{"clear"}, true},
		{"handler-set-lowercase", altSvcResponse(enabled, true, [2]string{"alt-svc", "clear"}), []string{"clear"}, true},
	}
	for _, tc := range cases {
		for _, keepAlive := range []bool{true, false} {
			raw := appendPlainResponseMode(tc.resp, nil, keepAlive, true)
			if got := h1AltSvcValues(t, raw); strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("%s keepAlive=%v: Alt-Svc %q, want %q", tc.name, keepAlive, got, tc.want)
			}
			if !bytes.HasSuffix(raw, []byte("\r\n\r\nbody")) {
				t.Fatalf("%s: body not after the header terminator: %q", tc.name, raw)
			}
		}
	}
	untouched := &Response{StatusCode: 200}
	untouched.lazyReq = &Request{Method: "GET", IsTLS: true, server: enabled}
	if raw := appendPlainResponseMode(untouched, nil, true, false); bytes.Contains(raw, []byte("Alt-Svc")) {
		t.Fatal("the serializer added Alt-Svc on its own")
	}
}

func TestAddAltSvcHeaderIsIdempotent(t *testing.T) {
	s := altSvcServer(t, Config{})
	resp := altSvcResponse(s, true)
	addAltSvcHeader(resp, s)
	if n := len(resp.Headers); n != 1 || resp.Headers[0] != newAltSvcHeader(altSvcTestPort).field {
		t.Fatalf("headers after two adds: %q", resp.Headers)
	}
	addAltSvcHeader(resp, nil)
	if len(resp.Headers) != 1 {
		t.Fatal("a nil server added a header")
	}
}

func TestAltSvcH2Serializer(t *testing.T) {
	enabled := altSvcServer(t, Config{})
	for _, tc := range []struct {
		name string
		resp *Response
		want []string
	}{
		{"tls", altSvcResponse(enabled, true), []string{altSvcTestValue}},
		{"h2c", altSvcResponse(enabled, false), nil},
		{"handler-set", altSvcResponse(enabled, true, [2]string{"Alt-Svc", "clear"}), []string{"clear"}},
		{"disabled", altSvcResponse(altSvcServer(t, Config{DisableAltSvc: true}), true), nil},
	} {
		frame := appendH2ResponseHeadersFrameIndexed(nil, 1, tc.resp, true, nil, respServerName(tc.resp), H2DefaultMaxFrameSize)
		if got := hpackAltSvcValues(t, frame[9:]); strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Fatalf("%s: alt-svc %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestAltSvcStreamHeads(t *testing.T) {
	alt := newAltSvcHeader(altSvcTestPort)
	for _, tc := range []struct {
		name    string
		alt     *altSvcHeader
		headers [][2]string
		want    []string
	}{
		{"tls", alt, nil, []string{altSvcTestValue}},
		{"plain", nil, nil, nil},
		{"handler-set", alt, [][2]string{{"ALT-SVC", "clear"}}, []string{"clear"}},
	} {
		head := appendH1StreamHead(nil, 200, tc.headers, "text/plain", false, true, "ALOS", tc.alt)
		if got := h1AltSvcValues(t, head); strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Fatalf("H1 stream %s: Alt-Svc %q, want %q", tc.name, got, tc.want)
		}
		enc := HpackEncoder{}
		encodeH2ResponseHeaders(&enc, 200, "text/plain", -1, tc.headers, "ALOS")
		enc.Buf = appendAltSvcHPACK(enc.Buf, tc.alt, tc.headers)
		if got := hpackAltSvcValues(t, enc.Buf); strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Fatalf("H2 stream %s: alt-svc %q, want %q", tc.name, got, tc.want)
		}
	}
}
