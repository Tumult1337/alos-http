//go:build linux && amd64

package core

import (
	"testing"
	"time"
)

func TestAppFixDirectlyAssignedEnginesAreEnforced(t *testing.T) {
	ts := newTestServer(t, testServerOptions{
		Routes: func(r *Router) {
			r.GET("/", func(req *Request, resp *Response) { resp.String("root") })
			r.GET("/x", func(req *Request, resp *Response) { resp.String("x") })
		},
		Setup: func(s *Server) {
			s.RateLimit = NewRateLimitEngine()
			s.RateLimit.SetRules([]RateLimitRule{{Path: "/*", MaxReqs: 1, Window: time.Minute}})
			s.CORS = NewCORSEngine(CORSConfig{AllowOrigins: []string{"https://app.test"}})
		},
	})
	first, _ := ts.rawH1(t, "GET /x HTTP/1.1\r\nHost: x\r\nOrigin: https://app.test\r\nConnection: close\r\n\r\n")
	if first.StatusCode != 200 {
		t.Fatalf("first request status %d, want 200", first.StatusCode)
	}
	if got := first.Header.Get("Access-Control-Allow-Origin"); got != "https://app.test" {
		t.Fatalf("directly assigned CORS engine ignored: Access-Control-Allow-Origin %q", got)
	}
	for _, path := range []string{"/x", "/"} {
		resp, _ := ts.rawH1(t, "GET "+path+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		if resp.StatusCode != 429 {
			t.Fatalf("directly assigned rate limit ignored on %s: status %d, want 429", path, resp.StatusCode)
		}
	}
}
