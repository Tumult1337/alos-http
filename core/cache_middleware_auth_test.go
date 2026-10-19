//go:build linux && amd64

package core

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func cookieUserHandler(calls *int32) HandlerFunc {
	return func(req *Request, resp *Response) {
		atomic.AddInt32(calls, 1)
		switch req.Header("cookie") {
		case "s=a":
			resp.Status(200).String("hello A")
		case "s=b":
			resp.Status(200).String("hello B")
		default:
			resp.Status(200).String("hello anon")
		}
	}
}

func TestCacheDoesNotShareResponsesAcrossCookieUsers(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := cookieUserHandler(&calls)

	cases := []struct {
		hdrs [][2]string
		want string
	}{
		{[][2]string{{"Cookie", "s=a"}}, "hello A"},
		{[][2]string{{"Cookie", "s=b"}}, "hello B"},
		{nil, "hello anon"},
		{[][2]string{{"Cookie", "s=a"}}, "hello A"},
		{[][2]string{{"COOKIE", "s=b"}}, "hello B"},
		{nil, "hello anon"},
	}
	for i, c := range cases {
		resp := cResp()
		rc.handle(h, cReq("GET", "x", "/me", "", c.hdrs...), resp)
		if got := string(resp.transmittedBodyBytes()); got != c.want {
			t.Fatalf("request %d: body %q, want %q", i, got, c.want)
		}
	}
	if calls != 5 {
		t.Fatalf("handler ran %d times, want 5 (only the second anonymous request is a hit)", calls)
	}
	if rc.Len() != 1 {
		t.Fatalf("cache holds %d entries, want 1 (anonymous only)", rc.Len())
	}
}

func TestCacheBypassesRequestsWithAuthorization(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) {
		atomic.AddInt32(&calls, 1)
		resp.Status(200).String("user " + req.Header("authorization"))
	}
	for _, tok := range []string{"Bearer one", "Bearer two", "Bearer one"} {
		resp := cResp()
		rc.handle(h, cReq("GET", "x", "/me", "", [2]string{"authorization", tok}), resp)
		if got := string(resp.transmittedBodyBytes()); got != "user "+tok {
			t.Fatalf("token %q: body %q", tok, got)
		}
	}
	if calls != 3 || rc.Len() != 0 {
		t.Fatalf("calls=%d len=%d, want 3 calls and nothing stored", calls, rc.Len())
	}
}

func TestCacheAnonymousEntryNotServedToCredentialedRequest(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := cookieUserHandler(&calls)
	rc.handle(h, cReq("GET", "x", "/me", ""), cResp())
	resp := cResp()
	rc.handle(h, cReq("GET", "x", "/me", "", [2]string{"Cookie", "s=a"}), resp)
	if got := string(resp.transmittedBodyBytes()); got != "hello A" {
		t.Fatalf("credentialed request got %q, want its own response", got)
	}
}

func TestCacheKeyFuncSeparatesUsersAndOverridesBypass(t *testing.T) {
	rc := NewResponseCache(CacheConfig{
		TTL: time.Minute,
		KeyFunc: func(req *Request) (string, bool) {
			return req.Path + "|" + req.Header("cookie"), true
		},
	})
	defer rc.Stop()
	var calls int32
	h := cookieUserHandler(&calls)
	for _, round := range []int{1, 2} {
		for _, c := range []struct{ cookie, want string }{{"s=a", "hello A"}, {"s=b", "hello B"}} {
			resp := cResp()
			rc.handle(h, cReq("GET", "x", "/me", "", [2]string{"Cookie", c.cookie}), resp)
			if got := string(resp.transmittedBodyBytes()); got != c.want {
				t.Fatalf("round %d cookie %q: body %q, want %q", round, c.cookie, got, c.want)
			}
		}
	}
	if calls != 2 || rc.Len() != 2 {
		t.Fatalf("calls=%d len=%d, want 2 calls and 2 per-user entries", calls, rc.Len())
	}
}

func TestCacheKeyFuncFalseSkipsCache(t *testing.T) {
	rc := NewResponseCache(CacheConfig{
		TTL:     time.Minute,
		KeyFunc: func(req *Request) (string, bool) { return "", false },
	})
	defer rc.Stop()
	var calls int32
	h := cookieUserHandler(&calls)
	for range 3 {
		rc.handle(h, cReq("GET", "x", "/me", ""), cResp())
	}
	if calls != 3 || rc.Len() != 0 {
		t.Fatalf("calls=%d len=%d, want 3 calls and nothing stored", calls, rc.Len())
	}
}

func TestCacheHonoursVary(t *testing.T) {
	cases := []struct {
		vary   string
		stored bool
	}{
		{"Origin", false},
		{"*", false},
		{"Accept-Encoding, Origin", false},
		{"accept-language", false},
		{"Accept-Encoding", true},
		{" accept-encoding ,ACCEPT-ENCODING", true},
		{"", true},
	}
	for _, c := range cases {
		rc := NewResponseCache(CacheConfig{TTL: time.Minute})
		var calls int32
		h := func(req *Request, resp *Response) {
			atomic.AddInt32(&calls, 1)
			resp.SetHeader("Vary", c.vary)
			resp.Status(200).String("v")
		}
		rc.handle(h, cReq("GET", "x", "/v", ""), cResp())
		rc.handle(h, cReq("GET", "x", "/v", ""), cResp())
		rc.Stop()
		wantCalls := int32(2)
		if c.stored {
			wantCalls = 1
		}
		if calls != wantCalls {
			t.Errorf("Vary %q: handler ran %d times, want %d", c.vary, calls, wantCalls)
		}
	}
}

func TestCacheMultipleVaryHeadersAllChecked(t *testing.T) {
	if cacheableHeaders([][2]string{{"Vary", "Accept-Encoding"}, {"vary", "Cookie"}}) {
		t.Fatal("second Vary header naming Cookie must make the response uncacheable")
	}
}

func TestCarriesCredentials(t *testing.T) {
	yes := [][][2]string{
		{{"Cookie", "a=1"}},
		{{"cookie", ""}},
		{{"X-A", "1"}, {"AUTHORIZATION", "Basic eA=="}},
	}
	no := [][][2]string{
		nil,
		{{"Cookies", "a=1"}},
		{{"Set-Cookie", "a=1"}},
		{{"Proxy-Authorization", "x"}},
		{{"X-Authorization", "x"}},
		{{"Accept", strings.Repeat("a", 13)}},
	}
	for _, h := range yes {
		if !carriesCredentials(h) {
			t.Errorf("carriesCredentials(%v) = false, want true", h)
		}
	}
	for _, h := range no {
		if carriesCredentials(h) {
			t.Errorf("carriesCredentials(%v) = true, want false", h)
		}
	}
}
