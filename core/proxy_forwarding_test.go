//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

func withRemote(req *Request, remote string) *Request {
	req.RemoteAddr = remote
	return req
}

func forwardingLines(t *testing.T, req *Request) map[string][]string {
	t.Helper()
	got := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(appendForwardingHeaders(nil, req)), "\r\n"), "\r\n") {
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ": ")
		if !ok {
			t.Fatalf("malformed forwarding line %q", line)
		}
		got[name] = append(got[name], value)
	}
	for _, pair := range appendForwardingHeaderPairs(nil, req) {
		if vals := got[pair[0]]; len(vals) != 1 || vals[0] != pair[1] {
			t.Fatalf("pair form %q=%q disagrees with the wire form %v", pair[0], pair[1], vals)
		}
	}
	return got
}

func TestForwardingHeaders(t *testing.T) {
	trusted := newTrustedProxyMatcher([]string{"10.0.0.0/8"}, false)
	cases := []struct {
		name    string
		req     *Request
		trust   bool
		want    map[string]string
		absent  []string
		wantIPs string
	}{
		{
			name: "direct TLS client ignores a spoofed chain",
			req: &Request{RemoteAddr: "203.0.113.7:5000", IsTLS: true, Host: "app.test",
				Headers: [][2]string{{"X-Forwarded-For", "1.1.1.1"}}},
			want: map[string]string{
				"X-Forwarded-For":   "203.0.113.7",
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "app.test",
				"Forwarded":         `for=203.0.113.7;proto=https;host="app.test"`,
			},
		},
		{
			name:  "trusted peer extends the incoming chain",
			req:   &Request{RemoteAddr: "10.0.0.5:443", Host: "app.test:8080", Headers: [][2]string{{"X-Forwarded-For", "198.51.100.1, 192.0.2.9"}}},
			trust: true,
			want: map[string]string{
				"X-Forwarded-For":   "198.51.100.1, 192.0.2.9, 10.0.0.5",
				"X-Forwarded-Proto": "http",
				"Forwarded":         `for=192.0.2.9;proto=http;host="app.test:8080"`,
			},
		},
		{
			name:  "trusted peer with only X-Real-IP keeps the client in the chain",
			req:   &Request{RemoteAddr: "10.0.0.5:443", Host: "app.test", Headers: [][2]string{{"X-Real-IP", "192.0.2.44"}}},
			trust: true,
			want:  map[string]string{"X-Forwarded-For": "192.0.2.44, 10.0.0.5"},
		},
		{
			name:  "trusted peer without forwarding headers",
			req:   &Request{RemoteAddr: "10.0.0.5:443", Host: "app.test"},
			trust: true,
			want:  map[string]string{"X-Forwarded-For": "10.0.0.5", "Forwarded": `for=10.0.0.5;proto=http;host="app.test"`},
		},
		{
			name: "IPv6 client is quoted in Forwarded",
			req:  &Request{RemoteAddr: "[2001:db8::1]:443", IsTLS: true, Host: "app.test"},
			want: map[string]string{"X-Forwarded-For": "2001:db8::1", "Forwarded": `for="[2001:db8::1]";proto=https;host="app.test"`},
		},
		{
			name:   "unusable host is not forwarded",
			req:    &Request{RemoteAddr: "203.0.113.7:5000", Host: `bad"host`},
			want:   map[string]string{"Forwarded": "for=203.0.113.7;proto=http"},
			absent: []string{"X-Forwarded-Host"},
		},
		{
			name:   "unusable client address",
			req:    &Request{RemoteAddr: "1.2.3.4\r\nX-Evil: 1", Host: "app.test"},
			want:   map[string]string{"Forwarded": `for=unknown;proto=http;host="app.test"`},
			absent: []string{"X-Forwarded-For", "X-Evil"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.trust {
				applyTrustedRealIP(c.req, trusted)
			}
			got := forwardingLines(t, c.req)
			for name, want := range c.want {
				if vals := got[name]; len(vals) != 1 || vals[0] != want {
					t.Errorf("%s = %q, want %q", name, vals, want)
				}
			}
			for _, name := range c.absent {
				if _, ok := got[name]; ok {
					t.Errorf("%s present: %q", name, got[name])
				}
			}
		})
	}
}

func TestForwardingHeadersAreStrippedFromClients(t *testing.T) {
	for _, name := range []string{"X-Forwarded-For", "x-forwarded-proto", "X-FORWARDED-HOST", "Forwarded", "X-Real-IP"} {
		if !isProxyFilteredHeaderFold(name) {
			t.Errorf("client-supplied %s is relayed upstream", name)
		}
	}
}

func TestRealIPRewriteRecordsPeer(t *testing.T) {
	m := newTrustedProxyMatcher([]string{"10.0.0.5"}, false)
	req := &Request{RemoteAddr: "10.0.0.5:443", Headers: [][2]string{{"X-Forwarded-For", "192.0.2.1"}}}
	applyTrustedRealIP(req, m)
	if req.RemoteAddr != "192.0.2.1" || req.peerAddr != "10.0.0.5:443" {
		t.Fatalf("RemoteAddr=%q peerAddr=%q", req.RemoteAddr, req.peerAddr)
	}
	untrusted := &Request{RemoteAddr: "203.0.113.9:1", Headers: [][2]string{{"X-Forwarded-For", "192.0.2.1"}}}
	applyTrustedRealIP(untrusted, m)
	if untrusted.RemoteAddr != "203.0.113.9:1" || untrusted.peerAddr != "" {
		t.Fatalf("untrusted peer rewritten: RemoteAddr=%q peerAddr=%q", untrusted.RemoteAddr, untrusted.peerAddr)
	}
	untrusted.Reset()
	if untrusted.peerAddr != "" {
		t.Fatal("Reset left peerAddr set")
	}
}
