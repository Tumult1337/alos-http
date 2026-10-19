//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

func TestH2FixPathValidatorMatchesByteReference(t *testing.T) {
	reference := func(p string) bool {
		for i := 0; i < len(p); i++ {
			if p[i] <= ' ' || p[i] == 0x7f {
				return false
			}
		}
		return true
	}
	for n := 1; n <= 40; n++ {
		buf := []byte(strings.Repeat("a", n))
		for pos := 0; pos < n; pos++ {
			for c := 0; c < 256; c++ {
				buf[pos] = byte(c)
				p := string(buf)
				if got, want := isValidH2Path(p), reference(p); got != want {
					t.Fatalf("isValidH2Path(%q) = %v, want %v", p, got, want)
				}
			}
			buf[pos] = 'a'
		}
	}
}
