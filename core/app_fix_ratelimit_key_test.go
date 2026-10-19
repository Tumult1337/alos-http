//go:build linux && amd64

package core

import (
	"testing"
	"time"
)

func TestAppFixRateLimitMiddlewareGroupsIPv6By64(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	handler := RateLimitMiddleware(RateLimitMiddlewareConfig{MaxRequests: 2, Window: time.Minute, StopCh: stop})(func(req *Request, resp *Response) {
		resp.String("ok")
	})
	status := func(remote string) int {
		req := &Request{Method: "GET", Path: "/", RemoteAddr: remote}
		resp := &Response{}
		resp.Reset()
		handler(req, resp)
		return resp.StatusCode
	}
	for i, remote := range []string{"[2001:db8:1:2::1]:1000", "[2001:db8:1:2::2]:1000"} {
		if got := status(remote); got != 200 {
			t.Fatalf("request %d from %s got %d", i, remote, got)
		}
	}
	if got := status("[2001:db8:1:2:ffff::3]:1000"); got != 429 {
		t.Fatalf("third request from the same /64 got %d, want 429", got)
	}
	if got := status("[2001:db8:1:3::1]:1000"); got != 200 {
		t.Fatalf("a different /64 got %d, want 200", got)
	}
	if got := status("192.0.2.7:1000"); got != 200 {
		t.Fatalf("IPv4 client got %d, want 200", got)
	}
}

func TestAppFixRateLimitEngineGroupsIPv6By64(t *testing.T) {
	rle := NewRateLimitEngine()
	defer rle.Stop()
	rle.SetRules([]RateLimitRule{{Path: "/*", MaxReqs: 2, Window: time.Minute, BlockFor: time.Minute}})
	for _, ip := range []string{"2001:db8::1", "2001:db8::2"} {
		if ok, _, _ := rle.Check(ip, "/x"); !ok {
			t.Fatalf("%s rejected early", ip)
		}
	}
	if ok, _, _ := rle.Check("2001:db8::abcd:3", "/x"); ok {
		t.Fatal("rotating addresses inside one /64 reset the engine budget")
	}
	if ok, _, _ := rle.Check("198.51.100.9", "/x"); !ok {
		t.Fatal("IPv4 client affected by an IPv6 /64 block")
	}
}

func TestAppFixRateLimitKeyForIP(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1":            "192.0.2.1",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2::9%eth0": "2001:db8:1:2::/64",
		"::ffff:192.0.2.1":     "::ffff:192.0.2.1",
		"not-an-ip":            "not-an-ip",
		"":                     "",
	} {
		if got := rateLimitKeyForIP(in); got != want {
			t.Errorf("rateLimitKeyForIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func BenchmarkAppFixRateLimitMiddlewareIPv4(b *testing.B) {
	stop := make(chan struct{})
	defer close(stop)
	handler := RateLimitMiddleware(RateLimitMiddlewareConfig{MaxRequests: 1 << 62, Window: time.Hour, StopCh: stop})(func(req *Request, resp *Response) {})
	req := &Request{Method: "GET", Path: "/", RemoteAddr: "192.0.2.7:51234"}
	resp := &Response{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		handler(req, resp)
	}
}

func BenchmarkAppFixRateLimitEngineIPv4(b *testing.B) {
	rle := NewRateLimitEngine()
	defer rle.Stop()
	rle.SetRules([]RateLimitRule{{Path: "/*", MaxReqs: 1 << 62, Window: time.Hour, BlockFor: time.Minute}})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rle.Check("192.0.2.7", "/x")
	}
}
