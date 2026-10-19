//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

func panicMessage(fn func()) (msg string, panicked bool) {
	defer func() {
		if v := recover(); v != nil {
			msg, _ = v.(string)
			panicked = true
		}
	}()
	fn()
	return "", false
}

func TestRealIPPanicsOnInvalidTrustedProxy(t *testing.T) {
	cases := [][]string{
		{"10.0.0.0/88"},
		{"10.0.0.0/8", "bad"},
		{""},
		{"10.0.0.1 "},
		{"example.com"},
	}
	for _, proxies := range cases {
		msg, panicked := panicMessage(func() { RealIP(proxies...) })
		if !panicked {
			t.Errorf("RealIP(%q) did not panic", proxies)
			continue
		}
		if !strings.Contains(msg, "invalid trusted proxy") {
			t.Errorf("RealIP(%q) panic message %q does not name the problem", proxies, msg)
		}
	}
}

func TestRealIPAcceptsValidTrustedProxies(t *testing.T) {
	for _, proxies := range [][]string{nil, {"10.0.0.0/8"}, {"192.168.1.1"}, {"::1", "2001:db8::/32", "172.16.0.0/12"}} {
		if msg, panicked := panicMessage(func() { RealIP(proxies...) }); panicked {
			t.Errorf("RealIP(%q) panicked: %s", proxies, msg)
		}
	}
}

func TestRealIPTrustsOnlyListedPeers(t *testing.T) {
	h := RealIP("10.0.0.0/8", "192.168.1.1")(func(req *Request, resp *Response) {})
	cases := []struct {
		peer, want string
	}{
		{"10.1.2.3:5000", "203.0.113.9"},
		{"192.168.1.1:5000", "203.0.113.9"},
		{"192.168.1.2:5000", "192.168.1.2:5000"},
		{"8.8.8.8:5000", "8.8.8.8:5000"},
	}
	for _, c := range cases {
		req := &Request{RemoteAddr: c.peer, Headers: [][2]string{{"X-Forwarded-For", "203.0.113.9"}}}
		h(req, &Response{})
		if req.RemoteAddr != c.want {
			t.Errorf("peer %s: RemoteAddr %q, want %q", c.peer, req.RemoteAddr, c.want)
		}
	}
}

func TestNewPanicsOnInvalidTrustedProxy(t *testing.T) {
	msg, panicked := panicMessage(func() { New(Config{TrustedProxies: []string{"x"}}) })
	if !panicked {
		t.Fatal("New with TrustedProxies [\"x\"] did not panic")
	}
	if !strings.Contains(msg, `invalid trusted proxy "x"`) {
		t.Fatalf("panic message %q does not name the bad entry", msg)
	}
}

func TestNewAcceptsValidTrustedProxies(t *testing.T) {
	msg, panicked := panicMessage(func() { New(Config{TrustedProxies: []string{"10.0.0.0/8", "::1"}}) })
	if panicked {
		t.Fatalf("New with valid TrustedProxies panicked: %s", msg)
	}
}
