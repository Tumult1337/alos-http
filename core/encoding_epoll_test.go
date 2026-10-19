//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

func TestBrotliEnableCompressEpoll(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tls    bool
		accept string
		want   string
	}{
		{"plain-br", false, "gzip, deflate, br", "br"},
		{"plain-br-refused", false, "br;q=0, gzip", "gzip"},
		{"tls-br", true, "br", "br"},
		{"tls-identity", true, "identity", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t, testServerOptions{
				TLS: tc.tls,
				Config: func(cfg *Config) {
					cfg.PlainHTTP = !tc.tls
					cfg.EnableCompress = true
				},
				Routes: func(r *Router) {
					r.GET("/data", func(req *Request, resp *Response) { resp.Status(200).JSON(compressibleTestBody) })
				},
			})
			resp, body := ts.rawH1(t, "GET /data HTTP/1.1\r\nHost: "+ts.domain+"\r\nAccept-Encoding: "+tc.accept+"\r\nConnection: close\r\n\r\n")
			if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != tc.want {
				t.Fatalf("status %d Content-Encoding %q, want %q", resp.StatusCode, resp.Header.Get("Content-Encoding"), tc.want)
			}
			if resp.Header.Get("Vary") != "Accept-Encoding" {
				t.Fatalf("Vary %q", resp.Header.Get("Vary"))
			}
			if got := decodeContent(t, tc.want, body); !bytes.Equal(got, compressibleTestBody) {
				t.Fatalf("decoded %d bytes, want the original %d", len(got), len(compressibleTestBody))
			}
		})
	}
}
