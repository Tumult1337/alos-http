//go:build linux && amd64

package core

import (
	"strconv"
	"strings"
	"testing"
)

func TestH2FixCookieCrumbsAreJoined(t *testing.T) {
	req := &Request{Headers: [][2]string{
		{":path", "/"},
		{"cookie", "a=1"},
		{"accept", "*/*"},
		{"cookie", "session=abc; theme=dark"},
		{"Cookie", "lang=en"},
	}}
	for name, want := range map[string]string{"a": "1", "session": "abc", "theme": "dark", "lang": "en"} {
		if got := req.Cookie(name); got != want {
			t.Errorf("Cookie(%q) = %q across split cookie crumbs, want %q", name, got, want)
		}
	}
	if n := len(req.Cookies()); n != 4 {
		t.Errorf("Cookies() returned %d cookies across 3 crumbs, want 4", n)
	}
}

func TestH2FixCookieCrumbsShareThePairCap(t *testing.T) {
	var crumb strings.Builder
	for i := range maxCookiePairs {
		if i > 0 {
			crumb.WriteString("; ")
		}
		crumb.WriteString("k" + strconv.Itoa(i) + "=v")
	}
	full := crumb.String()
	req := &Request{Headers: [][2]string{{"cookie", full}, {"cookie", full}, {"cookie", "late=1"}}}
	cookies := req.Cookies()
	if len(cookies) > maxCookiePairs {
		t.Fatalf("Cookies() returned %d pairs across crumbs, want <= %d", len(cookies), maxCookiePairs)
	}
	if spare := cookies[len(cookies):cap(cookies)]; len(spare) > 0 && spare[0] != (Cookie{}) {
		t.Fatalf("truncated cookie cache still references dropped pair %+v", spare[0])
	}
}

func TestH2FixCookieSingleHeaderUnchanged(t *testing.T) {
	req := &Request{Headers: [][2]string{{"Host", "x"}, {"Cookie", "session=4f9c; theme=dark"}}}
	if req.Cookie("session") != "4f9c" || req.Cookie("theme") != "dark" || req.Cookie("missing") != "" {
		t.Fatalf("single Cookie header parsed as %+v", req.Cookies())
	}
	empty := &Request{Headers: [][2]string{{"Host", "x"}}}
	if empty.Cookie("session") != "" || len(empty.Cookies()) != 0 {
		t.Fatalf("request without Cookie returned %+v", empty.Cookies())
	}
}

func BenchmarkH2FixCookieLookup(b *testing.B) {
	headers := [][2]string{
		{"Host", "example.com"},
		{"User-Agent", "Mozilla/5.0"},
		{"Accept", "*/*"},
		{"Cookie", "session=4f9c2a7e1b8d4c6aa0e3f5b7c9d1e2f4; theme=dark; lang=en; consent=1"},
		{"Accept-Encoding", "gzip"},
	}
	req := &Request{Headers: headers}
	b.ReportAllocs()
	for b.Loop() {
		req.cookiesParsed = false
		req.cookiesCache = req.cookiesCache[:0]
		if req.Cookie("lang") != "en" {
			b.Fatal("lang cookie missing")
		}
	}
}
