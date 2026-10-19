//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

func referenceH2FieldValueValid(value string) bool {
	if value != "" && strings.ContainsAny(value[:1]+value[len(value)-1:], " \t") {
		return false
	}
	return !strings.ContainsAny(value, "\x00\r\n")
}

func TestContainsLineBreakWithNULEveryPosition(t *testing.T) {
	probes := []byte{0x00, '\r', '\n', 0x01, 0x0b, 0x0c, 0x0e, 0x80, 0x8a, 0x8d, 0xff}
	for n := 0; n <= 70; n++ {
		base := []byte(strings.Repeat("v", n))
		for pos := 0; pos < n; pos++ {
			for _, p := range probes {
				s := append([]byte(nil), base...)
				s[pos] = p
				want := strings.ContainsAny(string(s), "\x00\r\n")
				if got := containsLineBreak(string(s), lineBreakCRLFNUL); got != want {
					t.Fatalf("NUL mode len %d pos %d byte %#x: got %v want %v", n, pos, p, got, want)
				}
				want = strings.ContainsAny(string(s), "\r\n")
				if got := containsLineBreak(string(s), lineBreakCRLF); got != want {
					t.Fatalf("CRLF mode len %d pos %d byte %#x: got %v want %v", n, pos, p, got, want)
				}
			}
		}
	}
}

func TestIsValidH2FieldValueMatchesReference(t *testing.T) {
	cases := []string{"", "a", " a", "a ", "\ta", "a\t", "a b", "a\x00b", "a\rb", "a\nb", "\x00", strings.Repeat("x", 9) + "\x00",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "\x80\xff", strings.Repeat("y", 64) + "\n" + strings.Repeat("z", 7)}
	for _, c := range cases {
		if got, want := isValidH2FieldValue(c), referenceH2FieldValueValid(c); got != want {
			t.Errorf("%q: got %v want %v", c, got, want)
		}
	}
}

func FuzzH2FieldValueDifferential(f *testing.F) {
	for _, s := range []string{"", "text/html", " x", "x\t", "a\x00", "abcdefgh\r", strings.Repeat("q", 40) + "\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if got, want := isValidH2FieldValue(value), referenceH2FieldValueValid(value); got != want {
			t.Fatalf("%q: got %v want %v", value, got, want)
		}
	})
}
