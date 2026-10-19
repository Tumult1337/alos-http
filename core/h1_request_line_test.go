//go:build linux && amd64

package core

import "testing"

func TestParseH1MethodIsExact(t *testing.T) {
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "HACK", "DOODLE", "PARTY", "OPTIONX", "PROPFIND", "M-SEARCH"} {
		req := &Request{Headers: make([][2]string, 0, 4)}
		_, _, _, _, rejected, _, _, ok := ParseH1RequestHead([]byte(method+" /x HTTP/1.1\r\nHost: a\r\n\r\n"), req, 0, 0)
		if !ok || rejected {
			t.Fatalf("%s: ok=%v rejected=%v", method, ok, rejected)
		}
		if req.Method != method {
			t.Fatalf("method %q parsed as %q", method, req.Method)
		}
	}
}

func TestParseH1RejectsRequestLineWithoutSpaces(t *testing.T) {
	for _, line := range []string{"GARBAGE\r\n\r\n", " \r\n\r\n", "GET\r\nHost: a\r\n\r\n"} {
		req := &Request{Headers: make([][2]string, 0, 4)}
		_, _, _, _, rejected, _, _, ok := ParseH1RequestHead([]byte(line), req, 0, 0)
		if !ok || !rejected {
			t.Fatalf("%q: ok=%v rejected=%v, want a rejection", line, ok, rejected)
		}
	}
}

func TestEpollH1IgnoresLeadingEmptyLines(t *testing.T) {
	ts := newTestServer(t, testServerOptions{Routes: func(r *Router) {
		r.GET("/ping", func(req *Request, resp *Response) { resp.Status(200).String("pong") })
	}})
	resp, body := ts.rawH1(t, "\r\n\r\nGET /ping HTTP/1.1\r\nHost: x\r\n\r\n")
	if resp.StatusCode != 200 || string(body) != "pong" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	resp, _ = ts.rawH1(t, "GARBAGE\r\n\r\n")
	if resp.StatusCode != 400 {
		t.Fatalf("request line without spaces: status %d, want 400", resp.StatusCode)
	}
}

func TestEpollH1UnknownMethodIsNotTreatedAsHead(t *testing.T) {
	ts := newTestServer(t, testServerOptions{Routes: func(r *Router) {
		r.HEAD("/x", func(req *Request, resp *Response) { resp.Status(200).String("head") })
	}})
	resp, _ := ts.rawH1(t, "HACK /x HTTP/1.1\r\nHost: x\r\n\r\n")
	if resp.StatusCode != 405 && resp.StatusCode != 404 {
		t.Fatalf("HACK routed to the HEAD handler: status %d", resp.StatusCode)
	}
}

func TestSanitizeRequestPathStripsEveryControlTerminator(t *testing.T) {
	cases := map[string]string{
		"/a\rb\x00c": "/a",
		"/a\nb\rc":   "/a",
		"/a\x00b\rc": "/a",
		"/ok":        "/ok",
	}
	for in, want := range cases {
		if got := sanitizeRequestPath(in); got != want {
			t.Fatalf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
