//go:build linux && amd64

package core

import (
	"bufio"
	"net/http"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	perfH1DateSkew       = 3 * time.Second
	perfH1HandlerDate    = "Tue, 15 Nov 1994 08:12:31 GMT"
	perfH1StaleDateLine  = "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n"
	perfH1MemoStatusLine = "HTTP/1.1 200 OK\r\n"
)

func perfH1DateRoutes(r *Router) {
	r.GET("/", func(req *Request, resp *Response) { resp.String("root") })
	r.GET("/plain", func(req *Request, resp *Response) { resp.String("plain") })
	r.GET("/own-date", func(req *Request, resp *Response) {
		resp.SetHeader("Date", perfH1HandlerDate).String("own")
	})
	r.GET("/stream", func(req *Request, resp *Response) {
		sw := resp.EnsureStreamWriter()
		_ = sw.WriteHeader(200, nil, "text/plain")
		resp.SetStreamer(sw)
		_ = sw.WriteChunk([]byte("chunk"))
		_ = sw.Close()
	})
}

func perfH1Fetch(t *testing.T, ts *testServer, path string) *http.Response {
	t.Helper()
	conn := perfH1DirectDial(t, ts.addr)
	if _, err := conn.Write(perfH1Get(path, "")); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("%s: read response: %v", path, err)
	}
	_ = resp.Body.Close()
	return resp
}

func perfH1AssertFreshDate(t *testing.T, path string, values []string) {
	t.Helper()
	if len(values) != 1 {
		t.Fatalf("%s: %d Date headers %q, want exactly 1", path, len(values), values)
	}
	got, err := http.ParseTime(values[0])
	if err != nil {
		t.Fatalf("%s: Date %q is not an IMF-fixdate: %v", path, values[0], err)
	}
	if skew := time.Duration(got.UnixNano() - turbo.UnixNano()).Abs(); skew > perfH1DateSkew {
		t.Fatalf("%s: Date %q is %v away from now", path, values[0], skew)
	}
}

func TestPerfH1ResponsesCarryOneCurrentDate(t *testing.T) {
	for _, inline := range []bool{false, true} {
		ts := newTestServer(t, testServerOptions{Routes: perfH1DateRoutes, Config: func(cfg *Config) { cfg.InlineHandlers, cfg.DisableInlineHandlers = inline, !inline }})
		for _, path := range []string{"/", "/plain", "/missing"} {
			perfH1AssertFreshDate(t, path, perfH1Fetch(t, ts, path).Header.Values("Date"))
		}
		if got := perfH1Fetch(t, ts, "/own-date").Header.Values("Date"); len(got) != 1 || got[0] != perfH1HandlerDate {
			t.Fatalf("handler-set Date: got %q, want exactly [%q]", got, perfH1HandlerDate)
		}
		if !inline {
			perfH1AssertFreshDate(t, "/stream", perfH1Fetch(t, ts, "/stream").Header.Values("Date"))
		}
	}
}
