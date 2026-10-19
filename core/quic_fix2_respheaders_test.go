//go:build linux && amd64

package core

import "testing"

var quicFix2ConnectionSpecificResponse = [][2]string{
	{"Connection", "close"},
	{"Proxy-Connection", "keep-alive"},
	{"Keep-Alive", "timeout=5"},
	{"Transfer-Encoding", "chunked"},
	{"Upgrade", "h2c"},
	{"TE", "trailers"},
}

var quicFix2EndToEndResponse = [][2]string{
	{"Proxy-Authenticate", "Basic realm=\"edge\""},
	{"Trailer", "Server-Timing"},
	{"Proxy-Authorization", "Basic Zm9vOmJhcg=="},
	{"X-Kept", "yes"},
}

func quicFix2CountFields(fields [][2]string) map[string]int {
	counts := map[string]int{}
	for _, f := range fields {
		counts[f[0]]++
	}
	return counts
}

func quicFix2CheckResponseFields(t *testing.T, proto string, fields [][2]string) {
	t.Helper()
	counts := quicFix2CountFields(fields)
	for _, h := range quicFix2ConnectionSpecificResponse {
		if name := ToLowerASCII(h[0]); counts[name] != 0 {
			t.Errorf("%s: connection-specific field %q was sent", proto, name)
		}
	}
	for _, h := range quicFix2EndToEndResponse {
		if name := ToLowerASCII(h[0]); counts[name] != 1 {
			t.Errorf("%s: end-to-end field %q sent %d times, want 1", proto, name, counts[name])
		}
	}
}

func quicFix2ResponseHeaders() [][2]string {
	headers := append([][2]string(nil), quicFix2ConnectionSpecificResponse...)
	return append(headers, quicFix2EndToEndResponse...)
}

func TestQUICFix2H3ResponseKeepsEndToEndFields(t *testing.T) {
	bp := qpackEncodeResponseHeaders(407, "text/plain", 0, quicFix2ResponseHeaders(), "alos")
	var dec QPACKDecoder
	fields, err := dec.Decode(*bp)
	if err != nil {
		t.Fatal(err)
	}
	quicFix2CheckResponseFields(t, "HTTP/3", fields)
}

func TestQUICFix2H2ResponseKeepsEndToEndFields(t *testing.T) {
	enc := HpackEncoder{}
	encodeH2ResponseHeaders(&enc, 407, "text/plain", 0, quicFix2ResponseHeaders(), "alos")
	fields, err := newHpackDecoder(4096).Decode(enc.Buf)
	if err != nil {
		t.Fatal(err)
	}
	quicFix2CheckResponseFields(t, "HTTP/2", fields)
}

func TestQUICFix2H2SingleResponseHeaderPath(t *testing.T) {
	for _, h := range quicFix2EndToEndResponse {
		enc := HpackEncoder{}
		encodeH2ResponseHeaders(&enc, 407, "", -1, [][2]string{h}, "alos")
		fields, err := newHpackDecoder(4096).Decode(enc.Buf)
		if err != nil {
			t.Fatal(err)
		}
		if n := quicFix2CountFields(fields)[ToLowerASCII(h[0])]; n != 1 {
			t.Errorf("HTTP/2 lone %q sent %d times, want 1", h[0], n)
		}
	}
	for _, h := range quicFix2ConnectionSpecificResponse {
		enc := HpackEncoder{}
		encodeH2ResponseHeaders(&enc, 200, "", -1, [][2]string{h}, "alos")
		fields, err := newHpackDecoder(4096).Decode(enc.Buf)
		if err != nil {
			t.Fatal(err)
		}
		if n := quicFix2CountFields(fields)[ToLowerASCII(h[0])]; n != 0 {
			t.Errorf("HTTP/2 lone connection-specific %q was sent", h[0])
		}
	}
}

func BenchmarkQUICFix2H2ResponseEncode(b *testing.B) {
	headers := [][2]string{{"Cache-Control", "no-store"}, {"X-Request-Id", "abc123"}, {"Vary", "Accept-Encoding"}}
	b.ReportAllocs()
	enc := HpackEncoder{}
	for b.Loop() {
		enc.Buf = enc.Buf[:0]
		encodeH2ResponseHeaders(&enc, 200, "text/plain", 128, headers, "alos")
	}
}
