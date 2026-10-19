//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

const csrfTestToken = "0123456789abcdef"

func csrfRequest(method, host string, tls bool, headers ...[2]string) *Request {
	req := newTestReq()
	req.Method, req.Host, req.IsTLS = method, host, tls
	req.Headers = append(req.Headers, [2]string{"cookie", "csrf_token=" + csrfTestToken}, [2]string{"x-csrf-token", csrfTestToken})
	req.Headers = append(req.Headers, headers...)
	return req
}

func runCSRF(cfg CSRFConfig, req *Request) (*Response, bool) {
	resp := newTestResp()
	reached := false
	CSRF(cfg)(func(req *Request, resp *Response) { reached = true; resp.Status(200) })(req, resp)
	return resp, reached
}

func TestCSRFOriginChecks(t *testing.T) {
	cfg := CSRFConfig{TrustedOrigins: []string{"https://partner.example", "HTTPS://Admin.Example:443"}}
	cases := []struct {
		name    string
		method  string
		tls     bool
		headers [][2]string
		allowed bool
	}{
		{"cross-site fetch metadata", "POST", true, [][2]string{{"sec-fetch-site", "cross-site"}, {"origin", "https://app.example"}}, false},
		{"cross-site even with trusted origin", "POST", true, [][2]string{{"sec-fetch-site", "cross-site"}, {"origin", "https://partner.example"}}, false},
		{"same-site untrusted", "POST", true, [][2]string{{"sec-fetch-site", "same-site"}, {"origin", "https://other.app.example"}}, false},
		{"same-site trusted", "POST", true, [][2]string{{"sec-fetch-site", "same-site"}, {"origin", "https://partner.example"}}, true},
		{"same-site trusted with default port", "POST", true, [][2]string{{"sec-fetch-site", "same-site"}, {"origin", "https://admin.example"}}, true},
		{"same-origin fetch metadata", "POST", true, [][2]string{{"sec-fetch-site", "same-origin"}, {"origin", "https://app.example"}}, true},
		{"user-initiated", "POST", true, [][2]string{{"sec-fetch-site", "none"}}, true},
		{"foreign origin without metadata", "POST", true, [][2]string{{"origin", "https://evil.example"}}, false},
		{"null origin", "POST", true, [][2]string{{"origin", "null"}}, false},
		{"scheme downgrade origin", "POST", true, [][2]string{{"origin", "http://app.example"}}, false},
		{"same origin explicit default port", "POST", true, [][2]string{{"origin", "https://APP.example:443"}}, true},
		{"trusted origin without metadata", "PUT", true, [][2]string{{"origin", "https://partner.example"}}, true},
		{"plain http same origin", "POST", false, [][2]string{{"origin", "http://app.example"}}, true},
		{"foreign referer over tls", "POST", true, [][2]string{{"referer", "https://evil.example/form"}}, false},
		{"same referer over tls", "DELETE", true, [][2]string{{"referer", "https://app.example/settings?tab=1"}}, true},
		{"trusted referer over tls", "POST", true, [][2]string{{"referer", "https://partner.example/x"}}, true},
		{"foreign referer over plain http ignored", "POST", false, [][2]string{{"referer", "http://evil.example/"}}, true},
		{"no origin no referer", "POST", true, nil, true},
		{"safe method cross-site", "GET", true, [][2]string{{"sec-fetch-site", "cross-site"}, {"origin", "https://evil.example"}}, true},
	}
	for _, c := range cases {
		resp, reached := runCSRF(cfg, csrfRequest(c.method, "app.example", c.tls, c.headers...))
		if reached != c.allowed {
			t.Errorf("%s: reached handler=%v, want %v (status %d)", c.name, reached, c.allowed, resp.StatusCode)
		}
		if !c.allowed && resp.StatusCode != 403 {
			t.Errorf("%s: status %d, want 403", c.name, resp.StatusCode)
		}
	}
}

func TestCSRFTokenStillRequired(t *testing.T) {
	req := newTestReq()
	req.Method, req.Host, req.IsTLS = "POST", "app.example", true
	req.Headers = append(req.Headers, [2]string{"cookie", "csrf_token=" + csrfTestToken}, [2]string{"sec-fetch-site", "same-origin"}, [2]string{"origin", "https://app.example"})
	if resp, reached := runCSRF(CSRFConfig{}, req); reached || resp.StatusCode != 403 {
		t.Fatalf("same-origin request without a token reached the handler (status %d)", resp.StatusCode)
	}
}

func TestCSRFSameOriginFormFlow(t *testing.T) {
	form := newTestReq()
	form.Method, form.Host, form.IsTLS = "POST", "app.example", true
	form.Headers = append(form.Headers,
		[2]string{"cookie", "csrf_token=" + csrfTestToken},
		[2]string{"content-type", "application/x-www-form-urlencoded"},
		[2]string{"origin", "https://app.example"},
		[2]string{"sec-fetch-site", "same-origin"},
		[2]string{"referer", "https://app.example/form"})
	form.Body = []byte("name=x&csrf_token=" + csrfTestToken)
	if resp, reached := runCSRF(CSRFConfig{}, form); !reached || resp.StatusCode != 200 {
		t.Fatalf("same-origin form post rejected: status %d", resp.StatusCode)
	}
}

func TestCSRFForwardedProtoFromTrustedProxyOnly(t *testing.T) {
	behindProxy := csrfRequest("POST", "app.example", false, [2]string{"origin", "https://app.example"}, [2]string{"x-forwarded-proto", "https"})
	behindProxy.peerAddr = "10.0.0.1:443"
	if _, reached := runCSRF(CSRFConfig{}, behindProxy); !reached {
		t.Fatal("https origin rejected behind a trusted TLS-terminating proxy")
	}
	spoofed := csrfRequest("POST", "app.example", false, [2]string{"origin", "https://app.example"}, [2]string{"x-forwarded-proto", "https"})
	if _, reached := runCSRF(CSRFConfig{}, spoofed); reached {
		t.Fatal("X-Forwarded-Proto honoured from an untrusted peer")
	}
}

func TestCSRFRejectsInvalidTrustedOrigin(t *testing.T) {
	for _, bad := range []string{"partner.example", "https://partner.example/path", "https://", "://x", "https://user@partner.example"} {
		func() {
			defer func() {
				if r := recover(); r == nil || !strings.Contains(r.(string), "invalid CSRF trusted origin") {
					t.Errorf("%q: recovered %v", bad, r)
				}
			}()
			CSRF(CSRFConfig{TrustedOrigins: []string{bad}})
		}()
	}
}

func TestCSRFCustomErrorHandlerForOrigin(t *testing.T) {
	called := false
	cfg := CSRFConfig{ErrorHandler: func(req *Request, resp *Response) { called = true; resp.Status(418) }}
	resp, reached := runCSRF(cfg, csrfRequest("POST", "app.example", true, [2]string{"sec-fetch-site", "cross-site"}))
	if reached || !called || resp.StatusCode != 418 {
		t.Fatalf("reached %v called %v status %d", reached, called, resp.StatusCode)
	}
}

func TestRealIPMarksTrustedPeer(t *testing.T) {
	handler := RealIP("10.0.0.0/8")(func(req *Request, resp *Response) {})
	trusted := &Request{RemoteAddr: "10.1.2.3:443", Headers: [][2]string{{"x-forwarded-for", "203.0.113.7"}}}
	handler(trusted, newTestResp())
	if trusted.peerAddr != "10.1.2.3:443" || trusted.RemoteAddr != "203.0.113.7" {
		t.Fatalf("trusted peer: peerAddr %q RemoteAddr %q", trusted.peerAddr, trusted.RemoteAddr)
	}
	untrusted := &Request{RemoteAddr: "198.51.100.9:443", Headers: [][2]string{{"x-forwarded-for", "203.0.113.7"}}}
	handler(untrusted, newTestResp())
	if untrusted.peerAddr != "" || untrusted.RemoteAddr != "198.51.100.9:443" {
		t.Fatalf("untrusted peer: peerAddr %q RemoteAddr %q", untrusted.peerAddr, untrusted.RemoteAddr)
	}
	already := &Request{RemoteAddr: "10.9.9.9", peerAddr: "10.1.2.3:443"}
	handler(already, newTestResp())
	if already.peerAddr != "10.1.2.3:443" {
		t.Fatalf("RealIP replaced a peer recorded by the server: %q", already.peerAddr)
	}
}
