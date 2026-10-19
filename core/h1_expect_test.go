//go:build linux && amd64

package core

import "testing"

func TestClassifyExpect(t *testing.T) {
	cases := []struct {
		prev  h1Expect
		value string
		want  h1Expect
	}{
		{h1ExpectNone, "100-continue", h1ExpectContinue},
		{h1ExpectNone, "100-Continue", h1ExpectContinue},
		{h1ExpectNone, "100-CONTINUE", h1ExpectContinue},
		{h1ExpectNone, "", h1ExpectNone},
		{h1ExpectNone, "foo", h1ExpectUnknown},
		{h1ExpectNone, "100-continue, foo", h1ExpectUnknown},
		{h1ExpectNone, "100-continue;x=1", h1ExpectUnknown},
		{h1ExpectNone, "100-continu", h1ExpectUnknown},
		{h1ExpectContinue, "100-continue", h1ExpectContinue},
		{h1ExpectContinue, "foo", h1ExpectUnknown},
		{h1ExpectUnknown, "100-continue", h1ExpectUnknown},
		{h1ExpectContinue, "", h1ExpectContinue},
	}
	for _, tc := range cases {
		if got := classifyExpect(tc.prev, []byte(tc.value)); got != tc.want {
			t.Errorf("classifyExpect(%d, %q) = %d, want %d", tc.prev, tc.value, got, tc.want)
		}
	}
}

func TestParseH1RequestHeadExpect(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want h1Expect
	}{
		{"absent", "POST / HTTP/1.1\r\n" + h1StrictHost + "Content-Length: 5\r\n\r\n", h1ExpectNone},
		{"continue", "POST / HTTP/1.1\r\n" + h1StrictHost + "Expect: 100-continue\r\nContent-Length: 5\r\n\r\n", h1ExpectContinue},
		{"lowercase name", "POST / HTTP/1.1\r\n" + h1StrictHost + "expect: 100-Continue\r\n\r\n", h1ExpectContinue},
		{"padded value", "POST / HTTP/1.1\r\n" + h1StrictHost + "Expect:   100-continue  \r\n\r\n", h1ExpectContinue},
		{"unknown", "POST / HTTP/1.1\r\n" + h1StrictHost + "Expect: foo\r\n\r\n", h1ExpectUnknown},
		{"continue then unknown", "POST / HTTP/1.1\r\n" + h1StrictHost + "Expect: 100-continue\r\nExpect: foo\r\n\r\n", h1ExpectUnknown},
		{"unknown then continue", "POST / HTTP/1.1\r\n" + h1StrictHost + "Expect: foo\r\nExpect: 100-continue\r\n\r\n", h1ExpectUnknown},
		{"empty", "POST / HTTP/1.1\r\n" + h1StrictHost + "Expect:\r\n\r\n", h1ExpectNone},
		{"http10 continue ignored", "POST / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n", h1ExpectNone},
		{"http10 unknown ignored", "POST / HTTP/1.0\r\nExpect: foo\r\n\r\n", h1ExpectNone},
		{"other six-letter header", "GET / HTTP/1.1\r\n" + h1StrictHost + "Origin: https://a\r\nAccept: x\r\n\r\n", h1ExpectNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, reject, ok := parseStrict(tc.raw)
			if !ok || reject != h1RejectNone {
				t.Fatalf("parse ok=%v reject=%d", ok, reject)
			}
			if req.expect != tc.want {
				t.Fatalf("expect = %d, want %d", req.expect, tc.want)
			}
		})
	}
}

func TestRequestResetClearsExpect(t *testing.T) {
	for _, reset := range []func(*Request){(*Request).Reset, (*Request).resetFastH1} {
		req := &Request{expect: h1ExpectUnknown}
		reset(req)
		if req.expect != h1ExpectNone {
			t.Fatalf("expect = %d after reset", req.expect)
		}
	}
}
