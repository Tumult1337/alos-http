//go:build linux && amd64

package core

import "testing"

var perfCoreRouteTable = []struct {
	method string
	path   string
}{
	{"GET", "/"},
	{"GET", "/plaintext"},
	{"GET", "/json"},
	{"GET", "/health"},
	{"GET", "/metrics"},
	{"GET", "/favicon.ico"},
	{"GET", "/robots.txt"},
	{"GET", "/login"},
	{"POST", "/login"},
	{"GET", "/logout"},
	{"GET", "/signup"},
	{"POST", "/signup"},
	{"GET", "/dashboard"},
	{"GET", "/dashboard/settings"},
	{"GET", "/dashboard/billing"},
	{"GET", "/user/:id"},
	{"GET", "/user/:id/profile"},
	{"GET", "/user/:id/posts"},
	{"GET", "/user/:id/posts/:postID"},
	{"PUT", "/user/:id"},
	{"DELETE", "/user/:id"},
	{"GET", "/api/v1/users"},
	{"POST", "/api/v1/users"},
	{"GET", "/api/v1/users/:id"},
	{"PATCH", "/api/v1/users/:id"},
	{"DELETE", "/api/v1/users/:id"},
	{"GET", "/api/v1/users/:id/orders"},
	{"GET", "/api/v1/users/:id/orders/:orderID"},
	{"GET", "/api/v1/products"},
	{"GET", "/api/v1/products/:sku"},
	{"POST", "/api/v1/products"},
	{"GET", "/api/v1/products/:sku/reviews"},
	{"GET", "/api/v1/orders"},
	{"POST", "/api/v1/orders"},
	{"GET", "/api/v1/orders/:id"},
	{"GET", "/api/v1/search"},
	{"GET", "/api/v1/categories"},
	{"GET", "/api/v1/categories/:slug"},
	{"GET", "/api/v2/status"},
	{"GET", "/api/v2/events"},
	{"POST", "/api/v2/events"},
	{"GET", "/blog"},
	{"GET", "/blog/:slug"},
	{"GET", "/blog/tag/:tag"},
	{"GET", "/docs/*path"},
	{"GET", "/static/*filepath"},
	{"POST", "/echo"},
	{"GET", "/bytes/64k"},
	{"GET", "/bytes/1m"},
	{"GET", "/browser"},
}

var perfCoreSinkHandler HandlerFunc

func perfCoreRouter() *Router {
	r := NewRouter()
	h := func(req *Request, resp *Response) {}
	for _, rt := range perfCoreRouteTable {
		r.Handle(rt.method, rt.path, h)
	}
	r.Build()
	return r
}

func perfCoreRouterReq() *Request {
	return &Request{Headers: make([][2]string, 0, 16)}
}

var perfCoreRouterCases = []struct {
	name   string
	method string
	path   string
}{
	{"static_root", "GET", "/"},
	{"static_short", "GET", "/plaintext"},
	{"static_deep", "GET", "/api/v1/categories"},
	{"param_one", "GET", "/user/12345"},
	{"param_two", "GET", "/api/v1/users/42/orders/9001"},
	{"param_suffix", "GET", "/api/v1/products/sku-991/reviews"},
	{"catchall", "GET", "/static/file-64k.bin"},
	{"miss_404", "GET", "/nonexistent/path/here"},
	{"miss_405", "PUT", "/api/v1/products"},
}

func BenchmarkPerfCoreRouterLookup(b *testing.B) {
	r := perfCoreRouter()
	req := perfCoreRouterReq()
	for _, tc := range perfCoreRouterCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				perfCoreSinkHandler = r.Lookup(tc.method, tc.path, req)
			}
		})
	}
}

func TestPerfCoreRouterLookupResolves(t *testing.T) {
	r := NewRouter()
	hit := ""
	for _, rt := range perfCoreRouteTable {
		pattern := rt.method + " " + rt.path
		r.Handle(rt.method, rt.path, func(req *Request, resp *Response) { hit = pattern })
	}
	r.Build()
	want := map[string]string{
		"static_root":  "GET /",
		"static_short": "GET /plaintext",
		"static_deep":  "GET /api/v1/categories",
		"param_one":    "GET /user/:id",
		"param_two":    "GET /api/v1/users/:id/orders/:orderID",
		"param_suffix": "GET /api/v1/products/:sku/reviews",
		"catchall":     "GET /static/*filepath",
		"miss_404":     "",
		"miss_405":     "",
	}
	for _, tc := range perfCoreRouterCases {
		hit = ""
		req := perfCoreRouterReq()
		resp := &Response{}
		r.Lookup(tc.method, tc.path, req)(req, resp)
		if hit != want[tc.name] {
			t.Fatalf("%s: matched %q, want %q", tc.name, hit, want[tc.name])
		}
		switch tc.name {
		case "miss_404":
			if resp.StatusCode != 404 {
				t.Fatalf("miss_404 status %d", resp.StatusCode)
			}
		case "miss_405":
			if resp.StatusCode != 405 {
				t.Fatalf("miss_405 status %d", resp.StatusCode)
			}
		case "param_two":
			if req.ParamValue("id") != "42" || req.ParamValue("orderID") != "9001" {
				t.Fatalf("param_two params %+v", req.Params[:req.ParamCount])
			}
		case "catchall":
			if req.ParamValue("filepath") != "file-64k.bin" {
				t.Fatalf("catchall param %q", req.ParamValue("filepath"))
			}
		}
	}
}

func TestPerfCoreRouterLookupZeroAlloc(t *testing.T) {
	r := perfCoreRouter()
	req := perfCoreRouterReq()
	for _, tc := range perfCoreRouterCases {
		allocs := testing.AllocsPerRun(200, func() {
			perfCoreSinkHandler = r.Lookup(tc.method, tc.path, req)
		})
		if allocs != 0 {
			t.Fatalf("Router.Lookup %s %s allocates %.1f/op, want 0", tc.method, tc.path, allocs)
		}
	}
}

var perfCoreSinkString string

func BenchmarkPerfCoreParamValue(b *testing.B) {
	r := perfCoreRouter()
	req := perfCoreRouterReq()
	r.Lookup("GET", "/api/v1/users/42/orders/9001", req)
	b.Run("first", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			perfCoreSinkString = req.ParamValue("id")
		}
	})
	b.Run("second", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			perfCoreSinkString = req.ParamValue("orderID")
		}
	})
	b.Run("absent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			perfCoreSinkString = req.ParamValue("nope")
		}
	})
}

func BenchmarkPerfCoreW3Handler(b *testing.B) {
	r := NewRouter()
	r.GET("/user/:id", func(req *Request, resp *Response) {
		resp.String(req.ParamValue("id"))
	})
	r.Build()
	req := perfCoreRouterReq()
	req.Method = "GET"
	resp := &Response{}
	b.ReportAllocs()
	for b.Loop() {
		resp.resetFastH1()
		r.Lookup("GET", "/user/12345", req)(req, resp)
	}
	if resp.bodyString != "12345" {
		b.Fatalf("body %q", resp.bodyString)
	}
}

func TestPerfCoreParamValueZeroAlloc(t *testing.T) {
	r := NewRouter()
	r.GET("/user/:id", func(req *Request, resp *Response) {
		resp.String(req.ParamValue("id"))
	})
	r.Build()
	req := perfCoreRouterReq()
	req.Method = "GET"
	resp := &Response{}
	allocs := testing.AllocsPerRun(200, func() {
		resp.resetFastH1()
		r.Lookup("GET", "/user/12345", req)(req, resp)
	})
	if allocs != 0 {
		t.Fatalf("W3 lookup+ParamValue+String allocates %.1f/op, want 0", allocs)
	}
	if resp.bodyString != "12345" {
		t.Fatalf("body %q", resp.bodyString)
	}
}
