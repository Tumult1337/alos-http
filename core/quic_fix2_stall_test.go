//go:build linux && amd64

package core

import (
	"testing"

	"github.com/guno1928/turbo"
)

const quicFix2StalledStreams = 4

func (p *quicTestPeer) hasStream(id uint64) bool {
	p.qc.streamsMu.Lock()
	defer p.qc.streamsMu.Unlock()
	_, ok := p.qc.streams[id]
	return ok
}

func TestQUICFix2SendStallResetsStreamsNotConn(t *testing.T) {
	startReqStreamWorkers()
	srv := New(Config{MaxPendingWriteBytes: quicFixPendingWriteCap})
	big := make([]byte, quicFixBigResponse)
	srv.Router.GET("/big", func(req *Request, resp *Response) { resp.Status(200).Bytes(big) })
	srv.Router.GET("/small", func(req *Request, resp *Response) { resp.Status(200).Bytes([]byte("ok")) })
	srv.Router.Build()
	p := newQUICTestPeerFor(t, srv)
	p.qc.peerStreamWindow = 1
	for i := 0; i < quicFix2StalledStreams; i++ {
		quicFixSendRequest(p, uint64(i*4), h3AppendHeadersFrame(nil, quicFixGET("/big")))
	}
	p.awaitHandlersIdle()
	if held := p.qc.stalledSendBytes.Load(); held <= p.qc.stallSoftCap {
		t.Fatalf("precondition: %d stalled bytes, want more than the %d soft cap", held, p.qc.stallSoftCap)
	}
	p.qc.peerStreamWindow = quicFixBigResponse
	now := turbo.UnixNano() + int64(quicFixStallTimeoutPlus)
	p.qc.lastActive.Store(now)
	p.qc.tick(now, true)
	if p.qc.closed.Load() {
		t.Fatal("a send stall closed the whole connection instead of resetting the stalled streams")
	}
	if held := p.qc.stalledSendBytes.Load(); held != 0 {
		t.Fatalf("%d stalled bytes still held after the stall timeout", held)
	}
	reset := map[uint64]bool{}
	for _, r := range p.sent().resets {
		if r.errorCode == quicFixH3ExcessiveLoad {
			reset[r.streamID] = true
		}
	}
	for i := 0; i < quicFix2StalledStreams; i++ {
		id := uint64(i * 4)
		if !reset[id] {
			t.Errorf("stalled stream %d was not reset with H3_EXCESSIVE_LOAD", id)
		}
		if p.hasStream(id) {
			t.Errorf("stalled stream %d was not retired after its reset", id)
		}
	}
	next := uint64(quicFix2StalledStreams * 4)
	quicFixSendRequest(p, next, h3AppendHeadersFrame(nil, quicFixGET("/small")))
	p.awaitHandlersIdle()
	if status := quicFixResponseStatus(t, p, next); status != 200 {
		t.Fatalf("request after the stall reset got status %d, want 200", status)
	}
}
