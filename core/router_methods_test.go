//go:build linux && amd64

package core

import "testing"

func routerDo(r *Router, method, path string) (*Request, *Response) {
	req := &Request{Method: method, Path: path}
	resp := &Response{lazyReq: req}
	r.Lookup(method, path, req)(req, resp)
	return req, resp
}

func newMethodsRouter() *Router {
	r := NewRouter()
	r.GET("/a", func(req *Request, resp *Response) {
		resp.SetHeader("X-A", "1")
		resp.Status(200).String("a")
	})
	r.GET("/u/:id", func(req *Request, resp *Response) { resp.Status(200).String("u" + req.ParamValue("id")) })
	r.GET("/f/*rest", func(req *Request, resp *Response) { resp.Status(200).String("f" + req.ParamValue("rest")) })
	r.GET("/b", func(req *Request, resp *Response) { resp.Status(200).String("get-b") })
	r.HEAD("/b", func(req *Request, resp *Response) { resp.Status(299).String("head-b") })
	r.GET("/m", func(req *Request, resp *Response) { resp.Status(200).String("m") })
	r.POST("/m", func(req *Request, resp *Response) { resp.Status(200).String("m") })
	r.DELETE("/m", func(req *Request, resp *Response) { resp.Status(200).String("m") })
	r.GET("/o", func(req *Request, resp *Response) { resp.Status(200).String("o") })
	r.OPTIONS("/o", func(req *Request, resp *Response) { resp.Status(288).String("custom-options") })
	r.GET("/p/:id", func(req *Request, resp *Response) { resp.Status(200).String("get-p") })
	r.HEAD("/p/:other", func(req *Request, resp *Response) { resp.Status(277).String("head-p") })
	r.POST("/postonly", func(req *Request, resp *Response) { resp.Status(201).String("p") })
	r.Build()
	return r
}

func TestRouterImplicitHEAD(t *testing.T) {
	r := newMethodsRouter()
	cases := []struct {
		path   string
		status int
		body   string
	}{
		{"/a", 200, "a"},
		{"/u/7", 200, "u7"},
		{"/f/x/y", 200, "fx/y"},
		{"/b", 299, "head-b"},
		{"/p/9", 277, "head-p"},
	}
	for _, tc := range cases {
		_, resp := routerDo(r, "HEAD", tc.path)
		if resp.StatusCode != tc.status || string(resp.GetBody()) != tc.body {
			t.Errorf("HEAD %s = %d %q, want %d %q", tc.path, resp.StatusCode, resp.GetBody(), tc.status, tc.body)
		}
	}
	_, resp := routerDo(r, "HEAD", "/a")
	if v, _ := respHeader(resp, "X-A"); v != "1" {
		t.Errorf("HEAD /a lost the GET handler's headers: %v", resp.Headers)
	}
	if _, resp := routerDo(r, "HEAD", "/postonly"); resp.StatusCode != 405 {
		t.Errorf("HEAD on a POST-only route = %d, want 405", resp.StatusCode)
	}
}

func TestRouterAutoOPTIONS(t *testing.T) {
	r := newMethodsRouter()
	cases := []struct {
		path  string
		allow string
	}{
		{"/a", "GET, HEAD, OPTIONS"},
		{"/u/1", "GET, HEAD, OPTIONS"},
		{"/m", "DELETE, GET, HEAD, OPTIONS, POST"},
		{"/postonly", "OPTIONS, POST"},
	}
	for _, tc := range cases {
		_, resp := routerDo(r, "OPTIONS", tc.path)
		allow, _ := respHeader(resp, "Allow")
		if resp.StatusCode != 204 || allow != tc.allow || len(resp.GetBody()) != 0 {
			t.Errorf("OPTIONS %s = %d allow %q body %q, want 204 %q", tc.path, resp.StatusCode, allow, resp.GetBody(), tc.allow)
		}
	}
	if _, resp := routerDo(r, "OPTIONS", "/o"); resp.StatusCode != 288 {
		t.Errorf("explicit OPTIONS handler not used: %d", resp.StatusCode)
	}
	_, resp := routerDo(r, "OPTIONS", "/missing")
	if _, has := respHeader(resp, "Allow"); resp.StatusCode != 404 || has {
		t.Errorf("OPTIONS on an unknown path = %d %v, want 404 without Allow", resp.StatusCode, resp.Headers)
	}
}

func TestRouterMethodNotAllowedAllow(t *testing.T) {
	r := newMethodsRouter()
	cases := []struct {
		method, path, allow string
	}{
		{"POST", "/a", "GET, HEAD, OPTIONS"},
		{"PUT", "/m", "DELETE, GET, HEAD, OPTIONS, POST"},
		{"GET", "/postonly", "OPTIONS, POST"},
		{"PATCH", "/f/z", "GET, HEAD, OPTIONS"},
	}
	for _, tc := range cases {
		req, resp := routerDo(r, tc.method, tc.path)
		allow, _ := respHeader(resp, "Allow")
		if resp.StatusCode != 405 || allow != tc.allow {
			t.Errorf("%s %s = %d allow %q, want 405 %q", tc.method, tc.path, resp.StatusCode, allow, tc.allow)
		}
		if req.ParamCount != 0 {
			t.Errorf("%s %s left %d params from probing", tc.method, tc.path, req.ParamCount)
		}
	}
	if _, resp := routerDo(r, "POST", "/nothing-here"); resp.StatusCode != 404 {
		t.Errorf("unknown path = %d, want 404", resp.StatusCode)
	}
}

func TestRouterCustomMethodNotAllowedGetsAllow(t *testing.T) {
	r := NewRouter()
	r.GET("/x", func(req *Request, resp *Response) { resp.Status(200) })
	r.MethodNotAllowed(func(req *Request, resp *Response) { resp.Status(405).String("custom") })
	r.Build()
	_, resp := routerDo(r, "DELETE", "/x")
	if allow, _ := respHeader(resp, "Allow"); resp.StatusCode != 405 || allow != "GET, HEAD, OPTIONS" || string(resp.GetBody()) != "custom" {
		t.Fatalf("got %d %q allow %q", resp.StatusCode, resp.GetBody(), allow)
	}
}

func TestRouterAutoOPTIONSRunsGlobalMiddleware(t *testing.T) {
	r := NewRouter()
	r.Use(func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			resp.SetHeader("X-MW", "ran")
			next(req, resp)
		}
	})
	r.GET("/x", func(req *Request, resp *Response) { resp.Status(200) })
	r.Build()
	for _, method := range []string{"OPTIONS", "POST", "HEAD"} {
		_, resp := routerDo(r, method, "/x")
		if v, _ := respHeader(resp, "X-MW"); v != "ran" {
			t.Errorf("%s: global middleware did not run", method)
		}
	}
}

func TestRouterRootCatchAllAllow(t *testing.T) {
	r := NewRouter()
	r.GET("/*all", func(req *Request, resp *Response) { resp.Status(200) })
	r.Build()
	_, resp := routerDo(r, "POST", "/any/thing")
	if allow, _ := respHeader(resp, "Allow"); resp.StatusCode != 405 || allow != "GET, HEAD, OPTIONS" {
		t.Fatalf("got %d allow %q", resp.StatusCode, allow)
	}
	if _, resp := routerDo(r, "HEAD", "/any/thing"); resp.StatusCode != 200 {
		t.Fatalf("HEAD under a root catch-all = %d", resp.StatusCode)
	}
}

func TestRouterMethodMatchingIsExact(t *testing.T) {
	r := newMethodsRouter()
	for _, method := range []string{"GETX", "GEX", "get", "POSTX", "DELETEX", "HEADER", "OPTION", "PATCHY", "TRACEROUTE", "CONNECTS", "PUTS"} {
		if idx := methodIndex(method); idx != -1 {
			t.Errorf("methodIndex(%q) = %d, want -1", method, idx)
		}
		if _, resp := routerDo(r, method, "/m"); resp.StatusCode != 404 {
			t.Errorf("%s /m = %d, want 404", method, resp.StatusCode)
		}
	}
	for i, method := range allMethods {
		if idx := methodIndex(method); idx != i {
			t.Errorf("methodIndex(%q) = %d, want %d", method, idx, i)
		}
	}
}

func TestRouterAllowResetBetweenRequests(t *testing.T) {
	r := newMethodsRouter()
	req, _ := routerDo(r, "POST", "/a")
	if req.allow == "" {
		t.Fatal("405 did not record Allow")
	}
	req.resetFastH1()
	if req.allow != "" {
		t.Fatal("resetFastH1 kept Allow")
	}
	req.allow = "x"
	req.Reset()
	if req.allow != "" {
		t.Fatal("Reset kept Allow")
	}
}
