//go:build linux && amd64

package core

import "testing"

func TestValidateHostFollowsRFC3986HostSyntax(t *testing.T) {
	valid := []string{"", "example.com", "example.com:8443", "[::1]:443", "[2001:db8::1]", "127.0.0.1", "xn--bcher-kva.example", "a_b.example", "a~b%41"}
	for _, h := range valid {
		if !ValidateHost(h) {
			t.Errorf("ValidateHost(%q) = false, want true", h)
		}
	}
	invalid := []string{"a b", "a\tb", "a\x00b", "a\rb", "a\nb", "a\x7fb", "x@y", "a/b", `a\b`, "a?b", "a#b", `a"b`, "a<b", "a>b", "a{b", "a|b", "a^b", "a`b", "\xc3\xa9.com"}
	for _, h := range invalid {
		if ValidateHost(h) {
			t.Errorf("ValidateHost(%q) = true, want false", h)
		}
	}
}
