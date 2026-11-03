//go:build linux && amd64

package core

import (
	"encoding/base64"
	"testing"
)

func basicAuthRequest(user, password string) *Request {
	req := newTestReq()
	req.Headers = append(req.Headers, [2]string{"authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))})
	return req
}

func BenchmarkBasicAuthUserPresence(b *testing.B) {
	handler := BasicAuth(BasicAuthConfig{Users: map[string]string{"admin": "secret"}})(func(_ *Request, resp *Response) { resp.Status(200) })
	for _, tc := range []struct{ name, user, password string }{
		{"known_wrong_password", "admin", "guess"},
		{"unknown_user", "nobody", "guess"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			req := basicAuthRequest(tc.user, tc.password)
			resp := newTestResp()
			b.ReportAllocs()
			for b.Loop() {
				resp.StatusCode = 0
				resp.Headers = resp.Headers[:0]
				resp.body = resp.body[:0]
				handler(req, resp)
			}
			if resp.StatusCode != 401 {
				b.Fatalf("status %d, want 401", resp.StatusCode)
			}
		})
	}
}
