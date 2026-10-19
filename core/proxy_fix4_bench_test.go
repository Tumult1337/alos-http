//go:build linux && amd64

package core

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func proxyFix4BenchLimitHooked(s *Server) {
	declined := func(RateLimitEvent, *Request, *Response) bool { return false }
	s.SetRateLimitRules([]RateLimitRule{{Path: "/*", MaxReqs: proxyFix3BenchRateLimit, Window: time.Minute, OnLimit: declined}})
	s.OnRateLimit(declined)
}

func BenchmarkProxyFix4InLoopRoundTripLimitHooked(b *testing.B) {
	proxyFixBenchRoundTrip(b, "/bench?q=1", proxyFix4BenchLimitHooked)
}

func BenchmarkProxyFix4InLoopTLSRoundTrip(b *testing.B) {
	if raceEnabled {
		b.Skip("the race detector distorts per-request cost")
	}
	origin := zeroAllocOrigin(b, proxyFixBenchBodySize)
	_, httpsAddr, _ := proxyFixStartTLS(b, Config{MaxConnsPerIP: -1}, func(s *Server) {
		s.AddProxyDomain(DomainConfig{Domain: proxyFixTLSDomain, Backends: []BackendConfig{{Addr: origin}}})
	})
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: proxyFixIOTimeout}, "tcp", httpsAddr, &tls.Config{
		InsecureSkipVerify: true, ServerName: proxyFixTLSDomain, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		b.Fatalf("tls dial: %v", err)
	}
	drive := proxyFixKeepAliveConnDriver(b, conn, proxyFixTLSDomain, "/bench?q=1")
	drive(proxyFixBenchWarmup)
	b.ReportAllocs()
	b.ResetTimer()
	drive(b.N)
}
