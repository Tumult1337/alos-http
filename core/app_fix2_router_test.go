//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

func appFix2ParamDumpHandler(name string) HandlerFunc {
	return func(req *Request, resp *Response) {
		parts := make([]string, 0, req.ParamCount)
		for i := 0; i < req.ParamCount; i++ {
			parts = append(parts, req.Params[i].Key+"="+req.Params[i].Value)
		}
		resp.String(name + "[" + strings.Join(parts, ",") + "]")
	}
}

func appFix2BacktrackParamRouter() *Router {
	r := NewRouter()
	r.GET("/a/b/:x/c", appFix2ParamDumpHandler("bxc"))
	r.GET("/a/:y/z/:x", appFix2ParamDumpHandler("yzx"))
	r.GET("/m/n/:p/q", appFix2ParamDumpHandler("npq"))
	r.GET("/m/:k/*rest", appFix2ParamDumpHandler("krest"))
	return r
}

func appFix2BacktrackParamCases() map[string]string {
	return map[string]string{
		"/a/b/z/k":   "yzx[y=b,x=k]",
		"/a/b/v/c":   "bxc[x=v]",
		"/a/q/z/k":   "yzx[y=q,x=k]",
		"/m/n/v/w":   "krest[k=n,rest=v/w]",
		"/m/n/v/q":   "npq[p=v]",
		"/m/o/v/w/x": "krest[k=o,rest=v/w/x]",
	}
}

func TestAppFix2RouterBacktrackDropsFailedBranchParams(t *testing.T) {
	for _, mode := range []string{"built", "unbuilt"} {
		r := appFix2BacktrackParamRouter()
		if mode == "built" {
			r.Build()
		}
		for path, want := range appFix2BacktrackParamCases() {
			status, body, _ := appFixRoute(t, r, "GET", path)
			if status != 200 || body != want {
				t.Errorf("%s GET %s got %d %q, want %q", mode, path, status, body, want)
			}
		}
	}
}

func TestAppFix2RouterBacktrackParamValueSeesWinningBranch(t *testing.T) {
	r := appFix2BacktrackParamRouter()
	r.Build()
	req := &Request{Method: "GET", Path: "/a/b/z/k"}
	if h := r.Lookup("GET", "/a/b/z/k", req); h == nil {
		t.Fatal("no handler for /a/b/z/k")
	}
	if got := req.ParamValue("x"); got != "k" {
		t.Fatalf("ParamValue(x) = %q, want %q", got, "k")
	}
	if got := req.ParamValue("y"); got != "b" {
		t.Fatalf("ParamValue(y) = %q, want %q", got, "b")
	}
}
