//go:build linux && amd64

package core

import (
	"sync/atomic"
	"testing"
)

const quicFixBenchFrameBody = 16 << 10

func BenchmarkQUICFixReserveGlobalOnly(b *testing.B) {
	srv := New(Config{})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if srv.tryReserveBodyBytes(quicFixBenchFrameBody) {
			srv.releaseBodyBytes(quicFixBenchFrameBody)
		}
	}
}

func BenchmarkQUICFixReservePerConn(b *testing.B) {
	srv := New(Config{})
	var conn atomic.Int64
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if srv.tryReserveConnBodyBytes(&conn, quicFixBenchFrameBody) {
			srv.releaseConnBodyBytes(&conn, quicFixBenchFrameBody)
		}
	}
}
