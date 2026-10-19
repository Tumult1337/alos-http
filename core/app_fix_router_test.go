//go:build linux && amd64

package core

import "testing"

func appFixNamedHandler(name string) HandlerFunc {
	return func(req *Request, resp *Response) {
		value := ""
		if req.ParamCount > 0 {
			value = req.Params[0].Value
		}
		resp.String(name + ":" + value)
	}
}

func appFixRoute(t *testing.T, r *Router, method, path string) (int, string, string) {
	t.Helper()
	req := &Request{Method: method, Path: path}
	resp := &Response{}
	resp.Reset()
	r.Lookup(method, path, req)(req, resp)
	allow := ""
	for _, h := range resp.Headers {
		if EqualFoldASCII(h[0], "allow") {
			allow = h[1]
		}
	}
	return resp.StatusCode, string(resp.GetBody()), allow
}

func TestAppFixRouterPrefixedCatchAllStaysUnderItsPrefix(t *testing.T) {
	r := NewRouter()
	r.GET("/static/*filepath", appFixNamedHandler("static"))
	r.Build()
	if status, body, _ := appFixRoute(t, r, "GET", "/static/css/app.css"); status != 200 || body != "static:css/app.css" {
		t.Fatalf("in-prefix path got %d %q", status, body)
	}
	if status, body, _ := appFixRoute(t, r, "GET", "/static/"); status != 200 || body != "static:" {
		t.Fatalf("bare prefix got %d %q", status, body)
	}
	if status, body, _ := appFixRoute(t, r, "GET", "/admin/secret"); status != 404 {
		t.Fatalf("path outside the catch-all prefix got %d %q, want 404", status, body)
	}
	if status, _, allow := appFixRoute(t, r, "POST", "/admin/secret"); status != 404 || allow != "" {
		t.Fatalf("POST outside the prefix got %d Allow=%q, want 404 with no Allow", status, allow)
	}
	if status, _, allow := appFixRoute(t, r, "POST", "/static/x"); status != 405 || allow == "" {
		t.Fatalf("POST inside the prefix got %d Allow=%q, want 405 with Allow", status, allow)
	}
}

func TestAppFixRouterRootCatchAllStillCatchesEverything(t *testing.T) {
	r := NewRouter()
	r.GET("/*filepath", appFixNamedHandler("all"))
	r.Build()
	for path, want := range map[string]string{"/": "all:", "/a/b": "all:a/b", "/admin/secret": "all:admin/secret"} {
		if status, body, _ := appFixRoute(t, r, "GET", path); status != 200 || body != want {
			t.Fatalf("GET %s got %d %q, want %q", path, status, body, want)
		}
	}
}

func appFixBacktrackRouter() *Router {
	r := NewRouter()
	r.GET("/users/new", appFixNamedHandler("new"))
	r.GET("/users/:id/view", appFixNamedHandler("view"))
	r.GET("/files/:name", appFixNamedHandler("file"))
	r.GET("/files/latest/meta", appFixNamedHandler("meta"))
	r.GET("/a/*rest", appFixNamedHandler("rest"))
	r.GET("/a/b/c/d", appFixNamedHandler("abcd"))
	r.GET("/a/:id/c/e", appFixNamedHandler("idce"))
	return r
}

func appFixBacktrackCases() map[string]string {
	return map[string]string{
		"/users/new":         "new:",
		"/users/new/view":    "view:new",
		"/users/42/view":     "view:42",
		"/files/latest":      "file:latest",
		"/files/latest/meta": "meta:",
		"/files/other":       "file:other",
		"/a/b/c/d":           "abcd:",
		"/a/b/c/e":           "idce:b",
		"/a/b/zzz":           "rest:b/zzz",
		"/a/x/c/e":           "idce:x",
	}
}

func TestAppFixRouterBacktracksFromStaticToParamBuilt(t *testing.T) {
	r := appFixBacktrackRouter()
	r.Build()
	for path, want := range appFixBacktrackCases() {
		if status, body, _ := appFixRoute(t, r, "GET", path); status != 200 || body != want {
			t.Errorf("built GET %s got %d %q, want %q", path, status, body, want)
		}
	}
	if status, _, _ := appFixRoute(t, r, "GET", "/users/new/edit"); status != 404 {
		t.Errorf("unrouted /users/new/edit got %d, want 404", status)
	}
}

func TestAppFixRouterBacktracksFromStaticToParamUnbuilt(t *testing.T) {
	r := appFixBacktrackRouter()
	for path, want := range appFixBacktrackCases() {
		if !r.Match("GET", path) {
			t.Errorf("unbuilt Match GET %s = false, want a match for %q", path, want)
			continue
		}
		if status, body, _ := appFixRoute(t, r, "GET", path); status != 200 || body != want {
			t.Errorf("unbuilt GET %s got %d %q, want %q", path, status, body, want)
		}
	}
}

func BenchmarkAppFixRouterMiss(b *testing.B) {
	router := NewRouter()
	h := func(req *Request, resp *Response) {}
	router.GET("/route/:id", h)
	router.GET("/users/:uid/orders/:oid", h)
	router.GET("/users/new", h)
	router.GET("/static/*filepath", h)
	router.Build()
	req := &Request{Headers: make([][2]string, 0, 16)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		appFixRouterSink = router.Lookup("GET", "/users/42/nope/x", req)
	}
}

var appFixRouterSink HandlerFunc
