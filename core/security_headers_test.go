//go:build linux && amd64

package core

import (
	"testing"
)

func applySecurityHeaders(cfg SecurityHeadersConfig) *Response {
	resp := newTestResp()
	SecurityHeaders(cfg)(func(req *Request, resp *Response) { resp.Status(200).String("ok") })(newTestReq(), resp)
	return resp
}

func TestSecurityHeadersEachField(t *testing.T) {
	cases := []struct {
		cfg   SecurityHeadersConfig
		name  string
		value string
	}{
		{SecurityHeadersConfig{ContentTypeNosniff: true}, "x-content-type-options", "nosniff"},
		{SecurityHeadersConfig{XFrameOptions: "SAMEORIGIN"}, "x-frame-options", "SAMEORIGIN"},
		{SecurityHeadersConfig{XSSProtection: true}, "x-xss-protection", "1; mode=block"},
		{SecurityHeadersConfig{HSTSMaxAge: 300}, "strict-transport-security", "max-age=300"},
		{SecurityHeadersConfig{HSTSMaxAge: 300, HSTSSubdomains: true, HSTSPreload: true}, "strict-transport-security", "max-age=300; includeSubDomains; preload"},
		{SecurityHeadersConfig{ReferrerPolicy: "no-referrer"}, "referrer-policy", "no-referrer"},
		{SecurityHeadersConfig{ContentSecurityPolicy: "default-src 'self'; img-src *"}, "content-security-policy", "default-src 'self'; img-src *"},
		{SecurityHeadersConfig{PermissionsPolicy: "geolocation=(), camera=()"}, "permissions-policy", "geolocation=(), camera=()"},
		{SecurityHeadersConfig{CrossOriginOpenerPolicy: "same-origin-allow-popups"}, "cross-origin-opener-policy", "same-origin-allow-popups"},
		{SecurityHeadersConfig{CrossOriginResourcePolicy: "same-site"}, "cross-origin-resource-policy", "same-site"},
		{SecurityHeadersConfig{CrossOriginEmbedderPolicy: "require-corp"}, "cross-origin-embedder-policy", "require-corp"},
	}
	for _, c := range cases {
		resp := applySecurityHeaders(c.cfg)
		if len(resp.Headers) != 1 || resp.Headers[0] != [2]string{c.name, c.value} {
			t.Errorf("%s: headers %q, want exactly [%s: %s]", c.name, resp.Headers, c.name, c.value)
		}
	}
	if resp := applySecurityHeaders(SecurityHeadersConfig{}); len(resp.Headers) != 0 {
		t.Errorf("zero config emitted %q", resp.Headers)
	}
}

func TestSecurityHeadersDefaults(t *testing.T) {
	resp := applySecurityHeaders(DefaultSecurityHeaders())
	want := map[string]string{
		"x-content-type-options":     "nosniff",
		"x-frame-options":            "DENY",
		"x-xss-protection":           "1; mode=block",
		"strict-transport-security":  "max-age=63072000; includeSubDomains; preload",
		"referrer-policy":            "strict-origin-when-cross-origin",
		"cross-origin-opener-policy": "same-origin",
	}
	if len(resp.Headers) != len(want) {
		t.Fatalf("defaults emitted %d headers: %q", len(resp.Headers), resp.Headers)
	}
	for _, h := range resp.Headers {
		if want[h[0]] != h[1] {
			t.Errorf("%s: %q, want %q", h[0], h[1], want[h[0]])
		}
	}
}

func TestSecurityHeadersStripLineBreaks(t *testing.T) {
	resp := applySecurityHeaders(SecurityHeadersConfig{
		ContentSecurityPolicy: "default-src 'self'\r\nSet-Cookie: stolen=1",
		XFrameOptions:         "DENY\n",
		PermissionsPolicy:     "\r\n",
	})
	for _, h := range resp.Headers {
		for i := 0; i < len(h[1]); i++ {
			if c := h[1][i]; c == '\r' || c == '\n' || c == 0 {
				t.Fatalf("%s value %q contains a line break", h[0], h[1])
			}
		}
	}
	if len(resp.Headers) != 2 {
		t.Fatalf("a value made only of line breaks should be dropped: %q", resp.Headers)
	}
}

func TestSecurityHeadersAllocFree(t *testing.T) {
	handler := SecurityHeaders(DefaultSecurityHeaders())(func(req *Request, resp *Response) {})
	req, resp := newTestReq(), newTestResp()
	allocs := testing.AllocsPerRun(100, func() {
		resp.Headers = resp.Headers[:0]
		handler(req, resp)
	})
	if allocs != 0 {
		t.Fatalf("%.1f allocations per response", allocs)
	}
}
