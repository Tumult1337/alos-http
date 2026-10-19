//go:build linux && amd64

package core

import "testing"

func TestQUICFixStalledAccountingReturnsToZero(t *testing.T) {
	p := newQUICFixStalledPeer(t)
	for i := 0; i < 2; i++ {
		quicFixSendRequest(p, uint64(i*4), h3AppendHeadersFrame(nil, quicFixGET("/big")))
	}
	p.awaitHandlersIdle()
	if p.qc.stalledSendBytes.Load() <= 0 {
		t.Fatal("stalled response bytes were not accounted")
	}
	for i := 0; i < 2; i++ {
		p.send(quicAppendMaxStreamDataFrame(nil, uint64(i*4), 2*quicFixBigResponse))
	}
	p.send(quicAppendMaxDataFrame(nil, 8*quicFixBigResponse))
	for i := 0; i < 2; i++ {
		p.awaitFin(uint64(i * 4))
	}
	if got := p.qc.stalledSendBytes.Load(); got != 0 {
		t.Fatalf("%d stalled bytes still accounted after every response drained", got)
	}
}
