//go:build linux && amd64

package core

import "testing"

func TestHpackMetaContentLength(t *testing.T) {
	var absent hpackRequestMeta
	if err := absent.observeHeader("x-a", "1"); err != nil {
		t.Fatal(err)
	}
	if got := absent.declaredLength(); got != -1 {
		t.Fatalf("absent declaredLength = %d", got)
	}

	cases := []struct {
		name   string
		values []string
		want   int64
		ok     bool
	}{
		{"single", []string{"10"}, 10, true},
		{"zero", []string{"0"}, 0, true},
		{"duplicate equal", []string{"7", "7"}, 7, true},
		{"duplicate different", []string{"7", "8"}, 0, false},
		{"not digits", []string{"1a"}, 0, false},
		{"negative", []string{"-1"}, 0, false},
		{"empty", []string{""}, 0, false},
		{"list", []string{"5, 5"}, 0, false},
		{"overflow", []string{"99999999999999999999999"}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var meta hpackRequestMeta
			var err error
			for _, v := range tc.values {
				if err = meta.observeHeader("content-length", v); err != nil {
					break
				}
			}
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if tc.ok && meta.declaredLength() != tc.want {
				t.Fatalf("declaredLength = %d, want %d", meta.declaredLength(), tc.want)
			}
		})
	}
}

func TestHpackDecodeRequestCarriesContentLength(t *testing.T) {
	var enc HpackEncoder
	for _, h := range [][2]string{
		{":method", "POST"}, {":scheme", "https"}, {":path", "/u"}, {":authority", "a"},
		{"content-length", "42"},
	} {
		enc.EncodeHeader(h[0], h[1])
	}
	block := enc.Buf
	dec := NewHpackDecoder()
	for round := 0; round < 2; round++ {
		_, meta, _, err := dec.DecodeRequest(nil, block)
		if err != nil {
			t.Fatal(err)
		}
		if got := meta.declaredLength(); got != 42 {
			t.Fatalf("round %d: declaredLength = %d", round, got)
		}
	}
}
