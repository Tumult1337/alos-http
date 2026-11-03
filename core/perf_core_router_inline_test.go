//go:build linux && amd64

package core

import "testing"

func TestPerfCoreRouteInlineOption(t *testing.T) {
	r := NewRouter()
	calls := 0
	shared := func(req *Request, resp *Response) {
		calls++
		resp.String(req.ParamValue("id"))
	}
	r.Use(func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			resp.SetHeaderUnsafe("x-mw", "1")
			next(req, resp)
		}
	})
	r.GET("/inline", shared).Inline()
	r.GET("/async", shared)
	r.GET("/user/:id", shared).Inline()
	r.GET("/files/*rest", shared)
	req := &Request{}
	if _, inline := r.lookupInline("GET", "/inline", req); inline {
		t.Fatal("an unbuilt router must not report inline routes")
	}
	r.Build()
	for _, c := range []struct {
		method, path string
		inline       bool
	}{
		{"GET", "/inline", true},
		{"GET", "/async", false},
		{"GET", "/user/42", true},
		{"GET", "/files/a/b", false},
		{"GET", "/missing", false},
		{"POST", "/inline", false},
		{"HEAD", "/inline", false},
	} {
		req := &Request{Method: c.method, Path: c.path}
		handler, inline := r.lookupInline(c.method, c.path, req)
		if inline != c.inline {
			t.Fatalf("%s %s inline=%v, want %v", c.method, c.path, inline, c.inline)
		}
		if handler == nil {
			t.Fatalf("%s %s: nil handler", c.method, c.path)
		}
	}
	req = &Request{Method: "GET", Path: "/user/42"}
	resp := &Response{}
	resp.Reset()
	handler, _ := r.lookupInline("GET", "/user/42", req)
	handler(req, resp)
	if string(resp.GetBody()) != "42" || calls != 1 {
		t.Fatalf("inline route body %q calls %d", resp.GetBody(), calls)
	}
	if v, _ := respHeader(resp, "x-mw"); v != "1" {
		t.Fatal("router middleware skipped on an inline route")
	}
	plain := NewRouter()
	plain.GET("/x", shared)
	plain.Build()
	if plain.hasInlineRoutes() {
		t.Fatal("router without inline routes reports some")
	}
}
