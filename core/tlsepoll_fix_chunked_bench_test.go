//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

func benchTLSEpollFixChunked(b *testing.B, wire string) {
	src := []byte(wire)
	dst := make([]byte, 0, len(src))
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, status, _ := asyncChunkedComplete(src, 0); status != 1 {
			b.Fatal("incomplete")
		}
		var ok bool
		if dst, _, ok = decodeChunkedInto(dst[:0], src); !ok {
			b.Fatal("rejected")
		}
	}
}

func BenchmarkTLSEpollFixChunkedSmallChunks(b *testing.B) {
	benchTLSEpollFixChunked(b, strings.Repeat("10\r\n0123456789abcdef\r\n", 64)+"0\r\n\r\n")
}

func BenchmarkTLSEpollFixChunkedWithExtensions(b *testing.B) {
	benchTLSEpollFixChunked(b, strings.Repeat("10;sig=abc;q=\"x y\"\r\n0123456789abcdef\r\n", 64)+"0\r\n\r\n")
}
