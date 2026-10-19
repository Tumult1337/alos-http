//go:build linux && amd64

package core

import (
	"testing"
	"unsafe"
)

func BenchmarkAppFixStructSizes(b *testing.B) {
	sizes := []struct {
		name  string
		bytes uintptr
	}{
		{"epollConn", unsafe.Sizeof(epollConn{})},
		{"Request", unsafe.Sizeof(Request{})},
		{"Response", unsafe.Sizeof(Response{})},
		{"tlsWorkerH2State", unsafe.Sizeof(tlsWorkerH2State{})},
		{"epollSlab", unsafe.Sizeof(epollSlab{})},
		{"H2Stream", unsafe.Sizeof(H2Stream{})},
		{"TrafficAEAD", unsafe.Sizeof(TrafficAEAD{})},
		{"tls12State", unsafe.Sizeof(tls12State{})},
		{"ParsedClientHello", unsafe.Sizeof(ParsedClientHello{})},
	}
	for _, s := range sizes {
		b.ReportMetric(float64(s.bytes), s.name+"-bytes")
	}
}
