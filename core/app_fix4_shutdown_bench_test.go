//go:build linux && amd64

package core

import "testing"

func BenchmarkAppFix4PoolAcceptCloseCycle(b *testing.B) {
	s := &Server{}
	p := &epollConnPool{batchSize: 4, server: s}
	p.prewarm(4)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := p.get()
		s.activeConns.Add(1)
		Stats.ActiveConns.Add(1)
		p.put(c)
	}
}
