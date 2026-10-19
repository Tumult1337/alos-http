//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

func TestCookiePartitioned(t *testing.T) {
	cases := []struct {
		cookie Cookie
		want   string
	}{
		{Cookie{Name: "a", Value: "b", Partitioned: true}, "a=b; Secure; Partitioned"},
		{Cookie{Name: "a", Value: "b", Secure: true, Partitioned: true}, "a=b; Secure; Partitioned"},
		{Cookie{Name: "embed", Value: "1", Path: "/", HttpOnly: true, SameSite: SameSiteNone, Partitioned: true}, "embed=1; Path=/; HttpOnly; Secure; SameSite=None; Partitioned"},
		{Cookie{Name: "a", Value: "b"}, "a=b"},
		{Cookie{Name: "a", Value: "b", Secure: true}, "a=b; Secure"},
	}
	for _, c := range cases {
		if got := c.cookie.String(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.cookie, got, c.want)
		}
	}
	resp := newTestResp()
	resp.SetCookie(Cookie{Name: "a", Value: "b", Partitioned: true})
	if v, _ := respHeader(resp, "set-cookie"); strings.Count(v, "; Secure") != 1 || !strings.HasSuffix(v, "; Partitioned") {
		t.Fatalf("Set-Cookie %q", v)
	}
}

func TestCookieAttributeInjection(t *testing.T) {
	c := Cookie{Name: "sid;x", Value: "v; Domain=evil.example; Max-Age=999999", Path: "/a;b", Domain: "ok.example;Secure", HttpOnly: true}
	got := c.String()
	want := "sidx=v Domain=evil.example Max-Age=999999; Path=/ab; Domain=ok.exampleSecure; HttpOnly"
	if got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	plain := Cookie{Name: "a", Value: "b c\x7f\"q\""}
	if got := plain.String(); got != "a=b c\x7f\"q\"" {
		t.Fatalf("bytes other than CR, LF, NUL and ';' were changed: %q", got)
	}
}
