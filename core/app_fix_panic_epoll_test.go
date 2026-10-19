//go:build linux && amd64

package core

import (
	"net/http"
	"testing"
)

func TestAppFixServerSurvivesPanickingOnPanicHook(t *testing.T) {
	ts := newTestServer(t, testServerOptions{
		Config: func(cfg *Config) {
			cfg.PlainHTTP = true
			cfg.OnPanic = func(*Request, any, []byte) { panic("hook is broken too") }
		},
		Routes: func(r *Router) {
			r.GET("/boom", func(req *Request, resp *Response) { panic("handler panic") })
			r.GET("/ok", func(req *Request, resp *Response) { resp.String("ok") })
		},
	})
	if resp, _ := ts.rawH1(t, "GET /boom HTTP/1.1\r\nHost: "+ts.domain+"\r\nConnection: close\r\n\r\n"); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("panicking handler got %d, want 500", resp.StatusCode)
	}
	if resp, body := ts.rawH1(t, "GET /ok HTTP/1.1\r\nHost: "+ts.domain+"\r\nConnection: close\r\n\r\n"); resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("server after a panicking OnPanic hook: %d %q", resp.StatusCode, body)
	}
}
