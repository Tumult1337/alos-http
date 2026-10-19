//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net/http"
	"testing"

	"github.com/guno1928/turbo"
)

func TestWrapHTTPHandlerFlushEpoll(t *testing.T) {
	for _, alpn := range []string{"http/1.1", "h2"} {
		t.Run(alpn, func(t *testing.T) {
			release := make(chan struct{})
			ts := newTestServer(t, testServerOptions{
				TLS: true,
				Routes: func(r *Router) {
					r.GET("/stream", WrapHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						w.Header().Set("X-Stage", "headers")
						w.Header().Set("Content-Type", "text/plain")
						_, _ = io.WriteString(w, "first\n")
						w.(http.Flusher).Flush()
						select {
						case <-release:
						case <-turbo.After(harnessIOTimeout):
						}
						_, _ = io.WriteString(w, "second\n")
					})))
				},
			})
			resp, err := ts.client(t, alpn).Get(ts.url("/stream"))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 || resp.Header.Get("X-Stage") != "headers" || resp.Header.Get("Content-Type") != "text/plain" {
				t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
			}
			br := bufio.NewReader(resp.Body)
			if line, err := br.ReadString('\n'); err != nil || line != "first\n" {
				t.Fatalf("first chunk %q err %v, want it before the handler returns", line, err)
			}
			close(release)
			if rest, err := io.ReadAll(br); err != nil || string(rest) != "second\n" {
				t.Fatalf("rest %q err %v", rest, err)
			}
		})
	}
}
