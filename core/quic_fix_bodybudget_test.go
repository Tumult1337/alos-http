//go:build linux && amd64

package core

import (
	"bytes"
	"strconv"
	"testing"
)

const (
	quicFixBudget          = 8 << 20
	quicFixMaxBody         = 512 << 10
	quicFixConnWindow      = 16 << 20
	quicFixHogStreams      = 40
	quicFixHogStreamBytes  = 256 << 10
	quicFixVictimBodyBytes = 200 << 10
	quicFixSmallConnWindow = 64 << 10
	quicFixFlowChunk       = 48 << 10
	quicFixFlowControlErr  = 0x03
	quicFixRequestRejected = 0x010b
)

func newQUICFixBudgetServer() *Server {
	srv := New(Config{MaxInFlightBodyBytes: quicFixBudget, MaxBodySize: quicFixMaxBody, QUICMaxData: quicFixConnWindow})
	(&quicFixH3Routes{}).route(srv.Router)
	srv.Router.Build()
	return srv
}

func quicFixPOST(path string, length int) []byte {
	return quicFixQPACKBlock([2]string{":method", "POST"}, [2]string{":scheme", "https"}, [2]string{":authority", "a.test"}, [2]string{":path", path}, [2]string{"content-length", strconv.Itoa(length)})
}

func TestQUICFixOneConnCannotHoldWholeBodyBudget(t *testing.T) {
	startReqStreamWorkers()
	srv := newQUICFixBudgetServer()
	hog := newQUICTestPeerFor(t, srv)
	chunk := make([]byte, quicFixHogStreamBytes)
	for i := 0; i < quicFixHogStreams; i++ {
		hog.send(quicStreamBytes(uint64(i*4), 0, chunk, false))
	}
	if held := srv.inFlightBodyBytes.Load(); held >= quicFixBudget-quicFixVictimBodyBytes {
		t.Fatalf("one connection holds %d of the %d byte in-flight body budget", held, quicFixBudget)
	}
	rejected := 0
	for _, r := range hog.sent().resets {
		if r.errorCode == quicFixRequestRejected {
			rejected++
		}
	}
	if rejected == 0 || hog.qc.closed.Load() {
		t.Fatalf("over-budget streams: %d rejected with H3_REQUEST_REJECTED, conn closed=%v; want rejections on a live conn", rejected, hog.qc.closed.Load())
	}
	victim := newQUICTestPeerFor(t, srv)
	body := bytes.Repeat([]byte("v"), quicFixVictimBodyBytes)
	request := append(h3AppendHeadersFrame(nil, quicFixPOST("/upload", len(body))), h3AppendDataFrame(nil, body)...)
	victim.send(quicStreamBytes(0, 0, request, true))
	if got := quicFixResponseStatus(t, victim, 0); got != 200 {
		t.Fatalf("victim upload on another connection: status %d, want 200", got)
	}
}

func TestQUICFixConnectionFlowControlEnforced(t *testing.T) {
	startReqStreamWorkers()
	srv := New(Config{QUICMaxData: quicFixSmallConnWindow})
	srv.Router.Build()
	p := newQUICTestPeerFor(t, srv)
	p.send(quicStreamBytes(0, 0, make([]byte, quicFixFlowChunk), false))
	if p.qc.closed.Load() {
		t.Fatal("data within MAX_DATA closed the connection")
	}
	p.qc.streamsMu.Lock()
	granted := p.qc.dataRecvGranted
	p.qc.streamsMu.Unlock()
	p.send(quicStreamBytes(4, 0, make([]byte, granted-quicFixFlowChunk+1), false))
	p.awaitClose(quicFixFlowControlErr)
}
