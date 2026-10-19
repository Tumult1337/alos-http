//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

const statsFlushCeiling = 2 * time.Second

func waitForByteCounters(t *testing.T, inAtLeast, outAtLeast uint64) (uint64, uint64) {
	t.Helper()
	deadline := time.Now().Add(statsFlushCeiling)
	for {
		in, out := Stats.BytesIn.Load(), Stats.BytesOut.Load()
		if in >= inAtLeast && out >= outAtLeast || time.Now().After(deadline) {
			return in, out
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func TestStatsBytes(t *testing.T) {
	const requests = 10
	const bodySize = 1500
	body := strings.Repeat("b", bodySize)
	ts := newTestServer(t, testServerOptions{Config: func(c *Config) { c.PlainHTTP = true }, Routes: func(r *Router) {
		r.POST("/echo", func(req *Request, resp *Response) { resp.Bytes(req.Body) })
	}})
	conn, err := net.DialTimeout("tcp", ts.addr, harnessIOTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(harnessIOTimeout))
	br := bufio.NewReader(conn)

	inBefore, outBefore := Stats.BytesIn.Load(), Stats.BytesOut.Load()
	var sent, received uint64
	for i := 0; i < requests; i++ {
		req := fmt.Sprintf("POST /echo HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s", ts.domain, bodySize, body)
		if _, err := io.WriteString(conn, req); err != nil {
			t.Fatal(err)
		}
		sent += uint64(len(req))
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || len(got) != bodySize {
			t.Fatalf("response %d: %d bytes, %v", i, len(got), err)
		}
		received += uint64(bodySize)
	}
	in, out := waitForByteCounters(t, inBefore+sent, outBefore+received)
	if in-inBefore < sent {
		t.Fatalf("BytesIn grew by %d, want at least the %d bytes sent", in-inBefore, sent)
	}
	if out-outBefore < received {
		t.Fatalf("BytesOut grew by %d, want at least the %d body bytes received", out-outBefore, received)
	}
}
