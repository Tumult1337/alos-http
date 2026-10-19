//go:build linux && amd64

package core

import "testing"

func appFixCORSResponse(t *testing.T, cfg CORSConfig, origin string) *Response {
	t.Helper()
	handler := CORS(cfg)(func(req *Request, resp *Response) {
		resp.String("ok")
	})
	req := &Request{Method: "GET", Path: "/api/data"}
	if origin != "" {
		req.Headers = [][2]string{{"Origin", origin}}
	}
	resp := &Response{}
	resp.Reset()
	handler(req, resp)
	return resp
}

func appFixHeaderValues(resp *Response, name string) []string {
	var out []string
	for _, h := range resp.Headers {
		if EqualFoldASCII(h[0], name) {
			out = append(out, h[1])
		}
	}
	return out
}

func TestAppFixCORSAllowListAlwaysVariesOnOrigin(t *testing.T) {
	cfg := CORSConfig{AllowOrigins: []string{"https://app.test"}}
	for _, origin := range []string{"", "https://evil.test", "https://app.test"} {
		resp := appFixCORSResponse(t, cfg, origin)
		if vary := appFixHeaderValues(resp, "vary"); len(vary) != 1 || vary[0] != "Origin" {
			t.Errorf("origin %q: Vary headers %q, want exactly one \"Origin\"", origin, vary)
		}
		acao := appFixHeaderValues(resp, "access-control-allow-origin")
		if want := origin == "https://app.test"; want != (len(acao) == 1) {
			t.Errorf("origin %q: Access-Control-Allow-Origin %q", origin, acao)
		}
	}
	ce := NewCORSEngine(cfg)
	resp := &Response{}
	resp.Reset()
	resp.SetHeaderUnsafe("Vary", "Accept-Encoding, Origin")
	ce.applyCORS(ce.snapshot.Load(), &Request{Method: "GET", Headers: [][2]string{{"Origin", "https://app.test"}}}, resp)
	if vary := appFixHeaderValues(resp, "vary"); len(vary) != 1 {
		t.Errorf("handler already varied on Origin, CORS added a duplicate: %q", vary)
	}
	if vary := appFixHeaderValues(appFixCORSResponse(t, CORSConfig{AllowOrigins: []string{"*"}}, ""), "vary"); len(vary) != 0 {
		t.Errorf("wildcard CORS does not depend on Origin but set Vary %q", vary)
	}
}

func BenchmarkAppFixCORSAllowList(b *testing.B) {
	handler := CORS(CORSConfig{AllowOrigins: []string{"https://app.test"}})(func(req *Request, resp *Response) {})
	req := &Request{Method: "GET", Path: "/api", Headers: [][2]string{{"Origin", "https://app.test"}}}
	resp := &Response{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp.resetFastH1()
		handler(req, resp)
	}
}
