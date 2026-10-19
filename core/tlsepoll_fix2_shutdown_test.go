//go:build linux && amd64

package core

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/guno1928/turbo"
)

func TestTLSEpollFix2ShutdownExpiryPostedBeforeDrainStillClosesStalledConns(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	ts := newTestServer(t, testServerOptions{
		Config: func(c *Config) { c.InlineHandlers = true },
		Routes: func(r *Router) {
			r.GET("/hold-loop", func(req *Request, resp *Response) {
				close(entered)
				<-release
				resp.Status(200).String("held")
			})
		},
	})
	releaseLoop := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseLoop)

	stalled := ts.dial(t)
	if _, err := io.WriteString(stalled, "GET / HTTP/1.1\r\nHost:"); err != nil {
		t.Fatal(err)
	}
	turbo.Sleep(harnessPollInterval)
	holder := ts.dial(t)
	if _, err := io.WriteString(holder, "GET /hold-loop HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-turbo.After(harnessIOTimeout):
		t.Fatal("inline handler never started")
	}

	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	if err := ts.srv.Shutdown(expired); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown with an expired ctx returned %v, want deadline exceeded", err)
	}
	releaseLoop()

	_ = stalled.SetReadDeadline(wallDeadline(tlsEpollFixExpiryCloseWait))
	if _, err := io.ReadAll(stalled); err != nil {
		t.Fatalf("stalled conn still open %v after a Shutdown deadline that expired before the worker saw done: %v", tlsEpollFixExpiryCloseWait, err)
	}
}
