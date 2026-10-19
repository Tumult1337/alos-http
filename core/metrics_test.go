//go:build linux && amd64

package core

import (
	"strconv"
	"strings"
	"testing"
)

type parsedMetric struct {
	kind  string
	help  string
	value string
}

func parseMetricsText(t *testing.T, text string) (map[string]parsedMetric, []string) {
	t.Helper()
	if !strings.HasSuffix(text, "\n") {
		t.Fatalf("output does not end with a newline: %q", text)
	}
	metrics := map[string]parsedMetric{}
	var order []string
	var pendingHelp, pendingType string
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "):
			name, help, ok := strings.Cut(strings.TrimPrefix(line, "# HELP "), " ")
			if !ok || help == "" {
				t.Fatalf("bad HELP line %q", line)
			}
			pendingHelp = name
			m := metrics[name]
			m.help = help
			metrics[name] = m
		case strings.HasPrefix(line, "# TYPE "):
			name, kind, ok := strings.Cut(strings.TrimPrefix(line, "# TYPE "), " ")
			if !ok || (kind != "counter" && kind != "gauge") || name != pendingHelp {
				t.Fatalf("bad TYPE line %q after HELP for %q", line, pendingHelp)
			}
			pendingType = name
			m := metrics[name]
			m.kind = kind
			metrics[name] = m
		default:
			fields := strings.Fields(line)
			if len(fields) != 2 || fields[0] != pendingType {
				t.Fatalf("sample line %q does not follow its TYPE line (%q)", line, pendingType)
			}
			if _, err := strconv.ParseInt(fields[1], 10, 64); err != nil {
				t.Fatalf("sample %q value: %v", line, err)
			}
			m := metrics[fields[0]]
			if m.value != "" {
				t.Fatalf("duplicate sample for %s", fields[0])
			}
			m.value = fields[1]
			metrics[fields[0]] = m
			order = append(order, fields[0])
			pendingType = ""
		}
	}
	return metrics, order
}

func TestMetricsHandlerFormat(t *testing.T) {
	snap := StatsSnapshot{
		ActiveConns: 7, TotalConns: 11, H1Conns: 13, H2Conns: 17, H3Conns: 19,
		TotalReqs: 23, RawReqs: 29, BlockedReqs: 31, H1Rejected: 37, BytesIn: 41, BytesOut: 1 << 40,
	}
	metrics, order := parseMetricsText(t, string(appendStatsMetrics(nil, &snap)))
	want := []struct {
		name, kind string
		value      uint64
	}{
		{"alos_http_active_connections", "gauge", 7},
		{"alos_http_connections_total", "counter", 11},
		{"alos_http_requests_total", "counter", 23},
		{"alos_http_requests_blocked_total", "counter", 31},
		{"alos_http_h1_rejected_total", "counter", 37},
		{"alos_http_bytes_received_total", "counter", 41},
		{"alos_http_bytes_sent_total", "counter", 1 << 40},
		{"alos_http_h1_connections_total", "counter", 13},
		{"alos_http_h2_connections_total", "counter", 17},
		{"alos_http_h3_connections_total", "counter", 19},
	}
	if len(order) != len(want) {
		t.Fatalf("got %d metrics %v, want %d", len(order), order, len(want))
	}
	for i, w := range want {
		m := metrics[w.name]
		if order[i] != w.name || m.kind != w.kind || m.value != strconv.FormatUint(w.value, 10) {
			t.Errorf("metric %d: got %s %+v, want %s %s %d", i, order[i], m, w.name, w.kind, w.value)
		}
	}
}

func TestMetricsHandler(t *testing.T) {
	before := Stats.Snapshot()
	req := &Request{Method: "GET", Path: "/metrics"}
	resp := &Response{}
	resp.Reset()
	MetricsHandler()(req, resp)
	after := Stats.Snapshot()
	if resp.StatusCode != 200 || resp.ContentType != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("status %d content type %q", resp.StatusCode, resp.ContentType)
	}
	metrics, order := parseMetricsText(t, string(resp.body))
	if len(order) != 1+len(statsCounters) {
		t.Fatalf("got %d metrics", len(order))
	}
	within := func(name string, lo, hi uint64) {
		v, _ := strconv.ParseUint(metrics[name].value, 10, 64)
		if v < lo || v > hi {
			t.Errorf("%s = %d, want within [%d, %d]", name, v, lo, hi)
		}
	}
	within("alos_http_requests_total", before.TotalReqs, after.TotalReqs)
	within("alos_http_connections_total", before.TotalConns, after.TotalConns)
	within("alos_http_bytes_sent_total", before.BytesOut, after.BytesOut)
	within("alos_http_h3_connections_total", before.H3Conns, after.H3Conns)
}

func TestMetricsHandlerAllocs(t *testing.T) {
	handler := MetricsHandler()
	req := &Request{Method: "GET", Path: "/metrics"}
	resp := &Response{}
	resp.Reset()
	handler(req, resp)
	allocs := testing.AllocsPerRun(100, func() {
		resp.Reset()
		handler(req, resp)
	})
	if allocs != 0 {
		t.Fatalf("%.1f allocations per scrape with a reused response, want 0", allocs)
	}
}

func BenchmarkMetricsHandler(b *testing.B) {
	handler := MetricsHandler()
	req := &Request{Method: "GET", Path: "/metrics"}
	resp := &Response{}
	b.ReportAllocs()
	for b.Loop() {
		resp.Reset()
		handler(req, resp)
	}
}
