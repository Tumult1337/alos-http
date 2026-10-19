//go:build linux && amd64

package core

import (
	"crypto/tls"
	"testing"
)

func benchmarkTLSEpollFixParseClientHello(b *testing.B, cfg *tls.Config) {
	msg := captureClientHello(b, cfg)
	ch := &ParsedClientHello{}
	b.ReportAllocs()
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ParseClientHello(msg, ch); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTLSEpollFixParseClientHelloTLS13(b *testing.B) {
	benchmarkTLSEpollFixParseClientHello(b, &tls.Config{ServerName: harnessDomain, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
}

func BenchmarkTLSEpollFixParseClientHelloTLS12(b *testing.B) {
	benchmarkTLSEpollFixParseClientHello(b, &tls.Config{ServerName: harnessDomain, MaxVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
}
