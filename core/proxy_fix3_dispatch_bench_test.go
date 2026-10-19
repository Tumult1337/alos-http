//go:build linux && amd64

package core

import (
	"testing"
	"time"
)

const proxyFix3BenchRateLimit = 1 << 40

func proxyFix3BenchRateLimited(s *Server) {
	s.SetRateLimitRules([]RateLimitRule{{Path: "/*", MaxReqs: proxyFix3BenchRateLimit, Window: time.Minute}})
}

func BenchmarkProxyFix3InLoopRoundTripRateLimited(b *testing.B) {
	proxyFixBenchRoundTrip(b, "/bench?q=1", proxyFix3BenchRateLimited)
}

func BenchmarkProxyFix3DispatchedProxyRoundTrip(b *testing.B) {
	proxyFixBenchRoundTrip(b, "/bench?q=1", func(s *Server) {
		s.OnResponse(func(req *Request, resp *Response) {})
	})
}

func BenchmarkProxyFix3DispatchedHandler(b *testing.B) {
	if raceEnabled {
		b.Skip("the race detector distorts per-request cost")
	}
	_, addr := proxyFixStart(b, Config{}, nil, func(s *Server) {
		s.OnRequest(func(req *Request, resp *Response) bool { return true })
		s.Router.GET("/handler", func(req *Request, resp *Response) { resp.String("handled") })
	})
	drive := proxyFixKeepAliveDriver(b, addr, "/handler")
	drive(proxyFixBenchWarmup)
	b.ReportAllocs()
	b.ResetTimer()
	drive(b.N)
}
