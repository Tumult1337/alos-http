//go:build linux && amd64

package core

import "strconv"

const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

type statsCounter struct {
	name  string
	help  string
	value func(StatsSnapshot) uint64
}

var statsCounters = [...]statsCounter{
	{"alos_http_connections_total", "Client connections accepted.", func(s StatsSnapshot) uint64 { return s.TotalConns }},
	{"alos_http_requests_total", "Requests dispatched to handlers.", func(s StatsSnapshot) uint64 { return s.TotalReqs }},
	{"alos_http_requests_blocked_total", "Requests refused by connection or request limits, rate limiting, or as malformed.", func(s StatsSnapshot) uint64 { return s.BlockedReqs }},
	{"alos_http_h1_rejected_total", "HTTP/1 requests rejected by the strict parser.", func(s StatsSnapshot) uint64 { return s.H1Rejected }},
	{"alos_http_bytes_received_total", "Bytes received from clients.", func(s StatsSnapshot) uint64 { return s.BytesIn }},
	{"alos_http_bytes_sent_total", "Bytes sent to clients.", func(s StatsSnapshot) uint64 { return s.BytesOut }},
	{"alos_http_h1_connections_total", "Connections served as HTTP/1.", func(s StatsSnapshot) uint64 { return s.H1Conns }},
	{"alos_http_h2_connections_total", "Connections served as HTTP/2.", func(s StatsSnapshot) uint64 { return s.H2Conns }},
	{"alos_http_h3_connections_total", "QUIC connections that completed the handshake for HTTP/3.", func(s StatsSnapshot) uint64 { return s.H3Conns }},
}

func MetricsHandler() HandlerFunc {
	return func(req *Request, resp *Response) {
		snap := Stats.Snapshot()
		resp.Status(200)
		resp.ContentType = metricsContentType
		resp.body = appendStatsMetrics(resp.body[:0], &snap)
		resp.bodyString = ""
		resp.bodyIsText = false
	}
}

func appendStatsMetrics(dst []byte, s *StatsSnapshot) []byte {
	dst = appendMetricHeader(dst, "alos_http_active_connections", "Open client connections.", "gauge")
	dst = strconv.AppendInt(dst, s.ActiveConns, 10)
	dst = append(dst, '\n')
	for i := range statsCounters {
		c := &statsCounters[i]
		dst = appendMetricHeader(dst, c.name, c.help, "counter")
		dst = strconv.AppendUint(dst, c.value(*s), 10)
		dst = append(dst, '\n')
	}
	return dst
}

func appendMetricHeader(dst []byte, name, help, kind string) []byte {
	dst = append(dst, "# HELP "...)
	dst = append(dst, name...)
	dst = append(dst, ' ')
	dst = append(dst, help...)
	dst = append(dst, "\n# TYPE "...)
	dst = append(dst, name...)
	dst = append(dst, ' ')
	dst = append(dst, kind...)
	dst = append(dst, '\n')
	dst = append(dst, name...)
	return append(dst, ' ')
}
