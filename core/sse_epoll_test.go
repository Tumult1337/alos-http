//go:build linux && amd64

package core

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/guno1928/turbo"
)

func TestSSEHeartbeatEpoll(t *testing.T) {
	ts := newTestServer(t, testServerOptions{
		Config: func(cfg *Config) { cfg.PlainHTTP = true },
		Routes: func(r *Router) {
			r.GET("/events", func(req *Request, resp *Response) {
				sse := resp.SSE()
				if sse == nil {
					return
				}
				_ = sse.SendID(req.LastEventID()+"+1", "resume", "after "+req.LastEventID())
				stop := sse.StartHeartbeat(sseHeartbeatTestInterval)
				turbo.Sleep(4 * sseHeartbeatTestInterval)
				stop()
				_ = sse.SendData("bye")
			})
		},
	})
	c := ts.dial(t)
	if _, err := c.Write([]byte("GET /events HTTP/1.1\r\nHost: " + ts.domain + "\r\nLast-Event-ID: 41\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	body := bufio.NewReader(resp.Body)
	var seen strings.Builder
	pings := 0
	start := turbo.Now()
	for pings < 2 {
		line, err := body.ReadString('\n')
		if err != nil {
			t.Fatalf("after %q: %v", seen.String(), err)
		}
		seen.WriteString(line)
		if line == ": ping\n" {
			pings++
		}
	}
	if elapsed := turbo.Since(start); elapsed > 3*sseHeartbeatTestInterval {
		t.Fatalf("two heartbeats took %v", elapsed)
	}
	if !strings.HasPrefix(seen.String(), "id: 41+1\nevent: resume\ndata: after 41\n\n") {
		t.Fatalf("stream began %q", seen.String())
	}
}
