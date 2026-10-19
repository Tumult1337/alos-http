//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	appFixUploadRateMbps    = 8
	appFixUploadBytesPerS   = appFixUploadRateMbps * 125000
	appFixUploadBurstBytes  = 65536
	appFixUploadExtraBytes  = 150000
	appFixUploadStreamAbove = 1024
)

func appFixStreamLimiterServer(t *testing.T, seen chan<- *ConnectionLimiter) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		Config: func(cfg *Config) {
			cfg.PlainHTTP = true
			cfg.ConnBandwidth = BandwidthConfig{MaxDownloadRate: 1000}
		},
		Routes: func(r *Router) {
			r.GET("/stream", func(req *Request, resp *Response) {
				sw := resp.EnsureStreamWriter()
				epollSW, ok := sw.(*epollH1StreamWriter)
				if !ok {
					seen <- nil
					resp.String("no epoll writer")
					return
				}
				seen <- epollSW.limiter
				_ = sw.WriteHeader(200, nil, "text/plain")
				resp.SetStreamer(sw)
				_ = sw.WriteChunk([]byte("data"))
				_ = sw.Close()
			})
		},
	})
}

func appFixStreamOnConn(t *testing.T, c io.ReadWriter, br *bufio.Reader, domain string, seen <-chan *ConnectionLimiter) *ConnectionLimiter {
	t.Helper()
	resp, body := appFixGetOnConn(t, c, br, domain, "/stream")
	if resp.StatusCode != http.StatusOK || body != "data" {
		t.Fatalf("stream got %d %q", resp.StatusCode, body)
	}
	return <-seen
}

func TestAppFixConnBandwidthBucketIsPerConnection(t *testing.T) {
	seen := make(chan *ConnectionLimiter, 4)
	ts := appFixStreamLimiterServer(t, seen)
	first := ts.dial(t)
	firstReader := bufio.NewReader(first)
	second := ts.dial(t)
	secondReader := bufio.NewReader(second)

	a1 := appFixStreamOnConn(t, first, firstReader, ts.domain, seen)
	b1 := appFixStreamOnConn(t, second, secondReader, ts.domain, seen)
	a2 := appFixStreamOnConn(t, first, firstReader, ts.domain, seen)
	if a1 == nil || b1 == nil {
		t.Fatalf("ConnBandwidth set but stream writers got limiters %p and %p", a1, b1)
	}
	if a1 == b1 {
		t.Fatal("two connections share one ConnBandwidth token bucket")
	}
	if a1 != a2 {
		t.Fatal("two requests on one keep-alive connection got different ConnBandwidth buckets")
	}
}

func TestAppFixConnBandwidthUploadIsThrottled(t *testing.T) {
	read := make(chan int64, 1)
	ts := newTestServer(t, testServerOptions{
		Config: func(cfg *Config) {
			cfg.PlainHTTP = true
			cfg.StreamBodyAbove = appFixUploadStreamAbove
			cfg.ConnBandwidth = BandwidthConfig{MaxUploadRate: appFixUploadRateMbps}
		},
		Routes: func(r *Router) {
			r.POST("/up", func(req *Request, resp *Response) {
				var n int64
				if body := req.BodyStream(); body != nil {
					n, _ = io.Copy(io.Discard, body)
				}
				read <- n
				resp.String("ok")
			})
		},
	})
	payload := bytes.Repeat([]byte{'u'}, appFixUploadBurstBytes+appFixUploadExtraBytes)
	c := ts.dial(t)
	_ = c.SetDeadline(wallDeadline(4 * harnessIOTimeout))
	start := turbo.Now()
	head := "POST /up HTTP/1.1\r\nHost: " + ts.domain + "\r\nContent-Length: " + strconv.Itoa(len(payload)) + "\r\n\r\n"
	go func() {
		_, _ = io.WriteString(c, head)
		_, _ = c.Write(payload)
	}()
	resp, body := readH1Response(t, bufio.NewReader(c), "POST")
	elapsed := turbo.Since(start)
	if got := <-read; resp.StatusCode != http.StatusOK || string(body) != "ok" || got != int64(len(payload)) {
		t.Fatalf("upload got status %d body %q, handler read %d of %d", resp.StatusCode, body, got, len(payload))
	}
	minimum := time.Duration(appFixUploadExtraBytes) * time.Second / appFixUploadBytesPerS * 2 / 3
	if elapsed < minimum {
		t.Fatalf("%d-byte upload under a %d Mbps ConnBandwidth limit finished in %v, want at least %v", len(payload), appFixUploadRateMbps, elapsed, minimum)
	}
}
