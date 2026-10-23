//go:build linux && amd64

package core

import (
	"net"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicFixBigResponse      = 1 << 20
	quicFixPendingWriteCap  = 1 << 20
	quicFixStalledStreams   = 16
	quicFixHardCapFactor    = 8
	quicFixH3ExcessiveLoad  = 0x0107
	quicFixStallTimeoutPlus = 11 * time.Second
)

var quicFixLoopback = net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}

func newQUICFixStalledPeer(t *testing.T) *quicTestPeer {
	t.Helper()
	startReqStreamWorkers()
	srv := New(Config{MaxPendingWriteBytes: quicFixPendingWriteCap})
	big := make([]byte, quicFixBigResponse)
	srv.Router.GET("/big", func(req *Request, resp *Response) { resp.Status(200).Bytes(big) })
	srv.Router.Build()
	p := newQUICTestPeerFor(t, srv)
	p.qc.peerStreamWindow = 1
	return p
}

func newQUICTestPeerFor(t *testing.T, srv *Server) *quicTestPeer {
	t.Helper()
	startReqStreamWorkers()
	pc := &capturePacketConn{}
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	qc := newQUICConn(srv, pc, &quicFixLoopback, dcid, []byte{9, 10, 11, 12, 13, 14, 15, 16})
	_, serverKeys, err := quicDeriveInitialKeys(dcid)
	if err != nil {
		t.Fatal(err)
	}
	_, keys, err := quicDeriveInitialKeys(dcid)
	if err != nil {
		t.Fatal(err)
	}
	qc.keys[quicSpaceAppData] = serverKeys
	qc.sendKeys[quicSpaceAppData] = serverKeys
	qc.addressValidated.Store(true)
	qc.peerStreamWindow = 1 << 20
	qc.peerUniStreamWindow = 1 << 20
	qc.handshakeDone.Store(true)
	newH3Conn(qc)
	t.Cleanup(qc.close)
	return &quicTestPeer{t: t, srv: srv, qc: qc, pc: pc, keys: keys, largest: -1, acked: -1}
}

func (p *quicTestPeer) pendingResponseBytes() (pending int, resets int) {
	p.qc.streamsMu.Lock()
	defer p.qc.streamsMu.Unlock()
	for _, s := range p.qc.streams {
		s.mu.Lock()
		pending += len(s.sendBuf)
		if s.sendReset {
			resets++
		}
		s.mu.Unlock()
	}
	return pending, resets
}

func (p *quicTestPeer) awaitHandlersIdle() {
	p.t.Helper()
	deadline := turbo.Deadline(quicPeerWait)
	for p.qc.activeReqStreams.Load() != 0 {
		if turbo.Until(deadline) <= 0 {
			p.t.Fatalf("%d request handlers still running", p.qc.activeReqStreams.Load())
		}
		turbo.Sleep(quicPeerPoll)
	}
}

func TestQUICFixStalledResponsesAreBoundedPerConn(t *testing.T) {
	p := newQUICFixStalledPeer(t)
	for i := 0; i < quicFixStalledStreams; i++ {
		quicFixSendRequest(p, uint64(i*4), h3AppendHeadersFrame(nil, quicFixGET("/big")))
	}
	p.awaitHandlersIdle()
	pending, _ := p.pendingResponseBytes()
	if limit := quicFixPendingWriteCap*quicFixHardCapFactor + quicFixBigResponse + 4096; pending > limit {
		t.Fatalf("a peer granting no stream credit pinned %d response bytes on one conn, want <= %d", pending, limit)
	}
	got := p.sent()
	excessive := 0
	for _, r := range got.resets {
		if r.errorCode == quicFixH3ExcessiveLoad {
			excessive++
		}
	}
	if excessive == 0 {
		t.Fatal("no stalled stream was reset with H3_EXCESSIVE_LOAD")
	}
}

func TestQUICFixStalledStreamsResetWithoutProgress(t *testing.T) {
	p := newQUICFixStalledPeer(t)
	for i := 0; i < 4; i++ {
		quicFixSendRequest(p, uint64(i*4), h3AppendHeadersFrame(nil, quicFixGET("/big")))
	}
	p.awaitHandlersIdle()
	p.qc.lastActive.Store(turbo.UnixNano() + int64(quicFixStallTimeoutPlus))
	p.qc.tick(turbo.UnixNano()+int64(quicFixStallTimeoutPlus), true)
	if held := p.qc.stalledSendBytes.Load(); held != 0 {
		t.Fatalf("a conn whose peer granted no credit for the stall timeout still holds %d stalled bytes", held)
	}
	excessive := 0
	for _, r := range p.sent().resets {
		if r.errorCode == quicFixH3ExcessiveLoad {
			excessive++
		}
	}
	if excessive != 4 {
		t.Fatalf("%d stalled streams reset with H3_EXCESSIVE_LOAD, want 4", excessive)
	}
}

func TestQUICFixStalledAccountingDrainsWithCredit(t *testing.T) {
	p := newQUICFixStalledPeer(t)
	for i := 0; i < 2; i++ {
		quicFixSendRequest(p, uint64(i*4), h3AppendHeadersFrame(nil, quicFixGET("/big")))
	}
	p.awaitHandlersIdle()
	if pending, _ := p.pendingResponseBytes(); pending == 0 {
		t.Fatal("responses were not held back by the 1-byte stream window")
	}
	for i := 0; i < 2; i++ {
		p.send(quicAppendMaxStreamDataFrame(nil, uint64(i*4), 2*quicFixBigResponse))
		p.send(quicAppendMaxDataFrame(nil, 8*quicFixBigResponse))
	}
	for i := 0; i < 2; i++ {
		p.awaitFin(uint64(i * 4))
	}
	p.qc.lastActive.Store(turbo.UnixNano() + int64(quicFixStallTimeoutPlus))
	p.qc.tick(turbo.UnixNano()+int64(quicFixStallTimeoutPlus), true)
	if p.qc.closed.Load() {
		t.Fatal("a conn whose responses all drained was closed as stalled")
	}
}
