//go:build linux && amd64

package core

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func altSvcRoutes(r *Router) {
	r.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("root") })
	r.GET("/x", func(req *Request, resp *Response) { resp.Status(200).String("x") })
	r.GET("/own", func(req *Request, resp *Response) {
		resp.SetHeader("Alt-Svc", "clear")
		resp.Status(200).String("own")
	})
	r.GET("/stream", func(req *Request, resp *Response) {
		sw := resp.EnsureStreamWriter()
		resp.SetStreamer(sw)
		if sw.WriteHeader(200, nil, "text/plain") == nil {
			_ = sw.WriteChunk([]byte("streamed"))
		}
	})
}

func altSvcGet(t *testing.T, cl *http.Client, url string) []string {
	t.Helper()
	resp, err := cl.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	return resp.Header.Values("Alt-Svc")
}

func TestAltSvcAdvertisedOverTLSWhenQUICRuns(t *testing.T) {
	ts := newTestServer(t, testServerOptions{
		TLS:    true,
		Routes: altSvcRoutes,
		Setup:  func(s *Server) { go func() { _ = s.ListenAndServeQUIC() }() },
	})
	waitFor(t, harnessIOTimeout, func() bool { return ts.srv.altSvc.Load() != nil })
	_, port, _ := net.SplitHostPort(ts.addr)
	want := `h3=":` + port + `"; ma=86400`
	for _, proto := range []string{"http/1.1", "h2"} {
		cl := ts.client(t, proto)
		for path, expect := range map[string]string{"/": want, "/x": want, "/stream": want, "/own": "clear"} {
			if got := altSvcGet(t, cl, ts.url(path)); strings.Join(got, "|") != expect {
				t.Fatalf("%s %s: Alt-Svc %q, want [%s]", proto, path, got, expect)
			}
		}
	}
}

func TestAltSvcNeverOnPlainHTTP(t *testing.T) {
	ts := newTestServer(t, testServerOptions{
		Routes: altSvcRoutes,
		Setup:  func(s *Server) { s.enableAltSvc(altSvcTestPort) },
	})
	cl := ts.client(t, "")
	for _, path := range []string{"/", "/x", "/stream"} {
		if got := altSvcGet(t, cl, ts.url(path)); len(got) != 0 {
			t.Fatalf("plain HTTP %s carried Alt-Svc %q", path, got)
		}
	}
}

func TestAltSvcDisabled(t *testing.T) {
	ts := newTestServer(t, testServerOptions{
		TLS:    true,
		Routes: altSvcRoutes,
		Config: func(c *Config) { c.DisableAltSvc = true },
		Setup:  func(s *Server) { s.enableAltSvc(altSvcTestPort) },
	})
	for _, proto := range []string{"http/1.1", "h2"} {
		cl := ts.client(t, proto)
		for _, path := range []string{"/", "/x", "/stream"} {
			if got := altSvcGet(t, cl, ts.url(path)); len(got) != 0 {
				t.Fatalf("%s %s with DisableAltSvc carried Alt-Svc %q", proto, path, got)
			}
		}
	}
}
