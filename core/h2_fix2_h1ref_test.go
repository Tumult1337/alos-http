//go:build linux && amd64

package core

import "testing"

func h2Fix2H1FramingTemplates() []string {
	return []string{
		"GET / HTTP/1.1\r\nHost: a\r\nConnection: te, close\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nConnection: foo,\tclose\r\n\r\n",
		"GET / HTTP/1.0\r\nConnection: keep-alive, te\r\n\r\n",
		"GET / HTTP/1.0\r\nConnection: Keep-Alive\r\nConnection: close\r\n\r\n",
		"POST / HTTP/1.0\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \r\nContent-Length: 5\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
	}
}

func h2Fix2CheckFramingOutcome(t *testing.T, raw string, wantClose bool, wantReject h1RejectReason) {
	t.Helper()
	got, want, _, _ := parseBoth([]byte(raw), 8192, 128)
	if want.closeConn != wantClose || want.reject != wantReject {
		t.Fatalf("%q: reference parser gave close=%v reject=%d, RFC 9112 requires close=%v reject=%d", raw, want.closeConn, want.reject, wantClose, wantReject)
	}
	if got != want {
		t.Fatalf("%q: got %+v, reference %+v", raw, got, want)
	}
}

func TestH2Fix2H1ReferenceEncodesCurrentFramingRules(t *testing.T) {
	tmpl := h2Fix2H1FramingTemplates()
	h2Fix2CheckFramingOutcome(t, tmpl[0], true, h1RejectNone)
	h2Fix2CheckFramingOutcome(t, tmpl[1], true, h1RejectNone)
	h2Fix2CheckFramingOutcome(t, tmpl[2], true, h1RejectNone)
	h2Fix2CheckFramingOutcome(t, tmpl[3], false, h1RejectNone)
	h2Fix2CheckFramingOutcome(t, tmpl[4], true, h1RejectNone)
	h2Fix2CheckFramingOutcome(t, tmpl[5], false, h1RejectTransferEncoding)
	h2Fix2CheckFramingOutcome(t, tmpl[6], false, h1RejectTransferEncoding)
	h2Fix2CheckFramingOutcome(t, tmpl[7], false, h1RejectTransferEncoding)
	h2Fix2CheckFramingOutcome(t, tmpl[8], false, h1RejectTransferEncoding)
}

func TestH2Fix2H1ReferenceMatchesOnEveryFramingByte(t *testing.T) {
	checked := 0
	for _, tmpl := range h2Fix2H1FramingTemplates() {
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
