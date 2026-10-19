//go:build linux && amd64

package core

import (
	"io"
	"strconv"
	"testing"
)

func TestMetricsHandlerEpoll(t *testing.T) {
	ts := newTestServer(t, testServerOptions{
		TLS: true,
		Routes: func(r *Router) {
			r.GET("/metrics", MetricsHandler())
			r.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
		},
	})
	before := Stats.Snapshot()
	const h1Conns, h2Conns = 3, 2
	for range h1Conns {
		c := ts.client(t, "http/1.1")
		resp, err := c.Get(ts.url("/ok"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		c.CloseIdleConnections()
	}
	for range h2Conns {
		c := ts.client(t, "h2")
		resp, err := c.Get(ts.url("/ok"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("negotiated %s", resp.Proto)
		}
		c.CloseIdleConnections()
	}

	c := ts.client(t, "http/1.1")
	resp, err := c.Get(ts.url("/metrics"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != metricsContentType {
		t.Fatalf("status %d content type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	metrics, _ := parseMetricsText(t, string(body))
	grew := func(name string, from uint64, by uint64) {
		v, _ := strconv.ParseUint(metrics[name].value, 10, 64)
		if v < from+by {
			t.Errorf("%s = %d, want at least %d + %d", name, v, from, by)
		}
	}
	grew("alos_http_connections_total", before.TotalConns, h1Conns+h2Conns+1)
	grew("alos_http_h1_connections_total", before.H1Conns, h1Conns+1)
	grew("alos_http_h2_connections_total", before.H2Conns, h2Conns)
	grew("alos_http_requests_total", before.TotalReqs, h1Conns+h2Conns+1)
	if active, _ := strconv.ParseInt(metrics["alos_http_active_connections"].value, 10, 64); active < 1 {
		t.Errorf("active connections %d while serving the scrape", active)
	}
}
