//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

func referenceContainsCRLF(s string) bool { return strings.ContainsAny(s, "\r\n") }

func TestContainsCRLFMatchesReference(t *testing.T) {
	probes := []byte{'\r', '\n', 0x0c, 0x0e, 0x0b, 0x09, 0x8d, 0x8a, 0x00, 0xff, 0x7f, 0x01}
	for n := 0; n <= crlfInlineScanMax+9; n++ {
		base := []byte(strings.Repeat("a", n))
		if got := containsCRLF(string(base)); got {
			t.Fatalf("len %d clean string reported CRLF", n)
		}
		for pos := 0; pos < n; pos++ {
			for _, p := range probes {
				s := append([]byte(nil), base...)
				s[pos] = p
				if got, want := containsCRLF(string(s)), referenceContainsCRLF(string(s)); got != want {
					t.Fatalf("len %d pos %d byte %#x: got %v want %v", n, pos, p, got, want)
				}
			}
		}
	}
}

func TestContainsCRLFEveryByteValue(t *testing.T) {
	for n := 1; n <= 24; n++ {
		for v := 0; v < 256; v++ {
			s := strings.Repeat(string([]byte{byte(v)}), n)
			if got, want := containsCRLF(s), referenceContainsCRLF(s); got != want {
				t.Fatalf("len %d byte %#x: got %v want %v", n, v, got, want)
			}
		}
	}
}

func FuzzContainsCRLF(f *testing.F) {
	for _, s := range []string{"", "a", "abc\r", "\nabcdefgh", "abcdefgh\r", "session=abc123; theme=dark", strings.Repeat("x", 40) + "\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := containsCRLF(s), referenceContainsCRLF(s); got != want {
			t.Fatalf("%q: got %v want %v", s, got, want)
		}
	})
}

func referenceSplitForwardableIP(addr string) (string, bool, bool) {
	ip := extractIP(addr)
	return ip, forwardableIP(ip), strings.IndexByte(ip, ':') >= 0
}

var forwardableIPSeeds = []string{
	"", ":", "::", ":80", "203.0.113.7:51234", "203.0.113.7", "[2001:db8::1]:443", "[2001:db8::1]",
	"[2001:db8::1", "2001:db8::1", "fe80::1%eth0", "[fe80::1%25eth0]:80", "1.2.3.4:ab\"z", "1.2.3.4\":80",
	"evil\r\n:80", "host.example:80", "unix", "@", "1.2.3.4:", "[]:80", "[::ffff:1.2.3.4]:8080",
}

func TestSplitForwardableIPMatchesReference(t *testing.T) {
	for _, addr := range forwardableIPSeeds {
		ip, ok, v6 := splitForwardableIP(addr)
		wantIP, wantOK, wantV6 := referenceSplitForwardableIP(addr)
		if ip != wantIP || ok != wantOK || v6 != wantV6 {
			t.Errorf("%q: got (%q,%v,%v) want (%q,%v,%v)", addr, ip, ok, v6, wantIP, wantOK, wantV6)
		}
	}
}

func FuzzSplitForwardableIP(f *testing.F) {
	for _, s := range forwardableIPSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, addr string) {
		ip, ok, v6 := splitForwardableIP(addr)
		wantIP, wantOK, wantV6 := referenceSplitForwardableIP(addr)
		if ip != wantIP || ok != wantOK || v6 != wantV6 {
			t.Fatalf("%q: got (%q,%v,%v) want (%q,%v,%v)", addr, ip, ok, v6, wantIP, wantOK, wantV6)
		}
	})
}

func TestAppendForwardingHeadersWire(t *testing.T) {
	cases := []struct {
		name string
		req  *Request
		want string
	}{
		{"tls v4 host", &Request{RemoteAddr: "203.0.113.7:51234", Host: "app.example", IsTLS: true},
			"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Host: app.example\r\nForwarded: for=203.0.113.7;proto=https;host=\"app.example\"\r\n"},
		{"plain v6 no host", &Request{RemoteAddr: "[2001:db8::1]:443"},
			"X-Forwarded-For: 2001:db8::1\r\nX-Forwarded-Proto: http\r\nForwarded: for=\"[2001:db8::1]\";proto=http\r\n"},
		{"unforwardable client bad host", &Request{RemoteAddr: "evil\r\n:80", Host: "bad host\r\n", IsTLS: true},
			"X-Forwarded-Proto: https\r\nForwarded: for=unknown;proto=https\r\n"},
		{"plain v4 host", &Request{RemoteAddr: "10.0.0.2:1", Host: "h.example:8080"},
			"X-Forwarded-For: 10.0.0.2\r\nX-Forwarded-Proto: http\r\nX-Forwarded-Host: h.example:8080\r\nForwarded: for=10.0.0.2;proto=http;host=\"h.example:8080\"\r\n"},
	}
	for _, c := range cases {
		if got := string(appendForwardingHeaders(nil, c.req)); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
		pairs := appendForwardingHeaderPairs(nil, c.req)
		var rebuilt strings.Builder
		for _, p := range pairs {
			rebuilt.WriteString(p[0] + ": " + p[1] + "\r\n")
		}
		if rebuilt.String() != c.want {
			t.Errorf("%s pairs:\n got %q\nwant %q", c.name, rebuilt.String(), c.want)
		}
	}
}

func BenchmarkContainsCRLF(b *testing.B) {
	values := []string{"bench/1.0", "*/*", "abcdef0123456789", "session=abc123; theme=dark", "User-Agent"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, v := range values {
			if containsCRLF(v) {
				b.Fatal("unexpected CRLF")
			}
		}
	}
}
