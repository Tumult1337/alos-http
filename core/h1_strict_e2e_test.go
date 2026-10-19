//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"testing"
)

func newStrictH1Server(t *testing.T) *testServer {
	return newTestServer(t, testServerOptions{Routes: func(r *Router) {
		r.GET("/", func(req *Request, resp *Response) { resp.String("root") })
		r.GET("/x", func(req *Request, resp *Response) { resp.String("x:" + req.Host) })
	}})
}

func TestH1StrictRejectsOverTheWire(t *testing.T) {
	ts := newStrictH1Server(t)
	bad := []string{
		"GET / HTTP/1.1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX Y: 1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-A: \x01\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-A: a\nb\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a@b\r\n\r\n",
		"GET /x HTTP/1.1\r\n\r\n",
		"GET /x HTTP/1.1\r\nHost: a\r\nNoColon\r\n\r\n",
		"GET /x HTTP/1.1\r\nHost: a\r\n: v\r\n\r\n",
		"GET /x\x01 HTTP/1.1\r\nHost: a\r\n\r\n",
	}
	for _, raw := range bad {
		before := Stats.H1Rejected.Load()
		c := ts.dial(t)
		if _, err := io.WriteString(c, raw); err != nil {
			t.Fatalf("write: %v", err)
		}
		br := bufio.NewReader(c)
		resp, body := readH1Response(t, br, "GET")
		if resp.StatusCode != 400 || string(body) != "Bad Request" {
			t.Errorf("%q: status %d body %q, want 400 Bad Request", raw, resp.StatusCode, body)
		}
		if !resp.Close {
			t.Errorf("%q: response does not announce Connection: close", raw)
		}
		if n, err := br.ReadByte(); err == nil {
			t.Errorf("%q: connection still open, read %q", raw, n)
		}
		if Stats.H1Rejected.Load() <= before {
			t.Errorf("%q: Stats.H1Rejected did not increase", raw)
		}
		_ = c.Close()
	}
}

func TestH1StrictAcceptsValidEdgeCasesOverTheWire(t *testing.T) {
	ts := newStrictH1Server(t)
	cases := []struct {
		raw, body string
	}{
		{"GET / HTTP/1.1\r\nHost: a\r\n\r\n", "root"},
		{"GET / HTTP/1.0\r\n\r\n", "root"},
		{"GET /x HTTP/1.1\r\nHost:\r\n\r\n", "x:"},
		{"GET /x HTTP/1.1\r\nHost: a\r\nX-A: caf\xc3\xa9\r\n\r\n", "x:a"},
		{"GET http://abs.test/x HTTP/1.1\r\nHost: other.test\r\n\r\n", "x:abs.test"},
		{"\r\n\r\nGET /x HTTP/1.1\r\nHost:  spaced.test \t\r\n\r\n", "x:spaced.test"},
	}
	for _, c := range cases {
		resp, body := ts.rawH1(t, c.raw)
		if resp.StatusCode != 200 || string(body) != c.body {
			t.Errorf("%q: status %d body %q, want 200 %q", c.raw, resp.StatusCode, body, c.body)
		}
	}
}
