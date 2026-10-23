//go:build linux && amd64

package core

import "testing"

func fuzzHPACKSeedBlock(headers [][2]string) []byte {
	var enc HpackEncoder
	for _, h := range headers {
		enc.EncodeHeader(h[0], h[1])
	}
	return enc.Buf
}

func FuzzHPACKDecodeRequest(f *testing.F) {
	f.Add(fuzzHPACKSeedBlock(gateH2BrowserHeaders))
	f.Add(fuzzHPACKSeedBlock([][2]string{{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {":authority", "a"}}))
	f.Add([]byte{0x82, 0x86, 0x84, 0x41, 0x01, 'a'})
	f.Add([]byte{0x3f, 0xe1, 0x1f})
	f.Add([]byte{0x40, 0x7f, 0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Fuzz(func(t *testing.T, block []byte) {
		dec := NewHpackDecoder()
		for range 2 {
			headers, _, err := dec.DecodeRequest(nil, block)
			if err != nil {
				return
			}
			for _, h := range headers {
				for i := 0; i < len(h[0]); i++ {
					if c := h[0][i]; c >= 'A' && c <= 'Z' {
						t.Fatalf("accepted uppercase header name %q", h[0])
					}
				}
			}
		}
	})
}

func fuzzToToken(b []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
	out := make([]byte, 0, len(b)+1)
	out = append(out, 'x')
	for _, c := range b {
		out = append(out, alphabet[int(c)%len(alphabet)])
	}
	return string(out)
}

func fuzzToVisible(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = 0x21 + c%0x5e
	}
	return string(out)
}

func FuzzHPACKRoundTrip(f *testing.F) {
	f.Add([]byte("user-agent"), []byte("Mozilla/5.0"), []byte("x-trace"), []byte("abc"))
	f.Add([]byte(""), []byte(""), []byte("a"), []byte("b"))
	f.Fuzz(func(t *testing.T, n1, v1, n2, v2 []byte) {
		want := [][2]string{{fuzzToToken(n1), fuzzToVisible(v1)}, {fuzzToToken(n2), fuzzToVisible(v2)}}
		got, err := NewHpackDecoder().Decode(fuzzHPACKSeedBlock(want))
		if err != nil {
			t.Fatalf("decode of encoder output failed: %v (%q)", err, want)
		}
		if len(got) != len(want) {
			t.Fatalf("got %d fields, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("field %d: got %q, want %q", i, got[i], want[i])
			}
		}
	})
}
