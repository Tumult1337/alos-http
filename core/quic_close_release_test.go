//go:build linux && amd64

package core

import (
	"testing"
)

const (
	quicCloseProbeBudget    = 64 << 10
	quicCloseProbeBodyBytes = 20000
	quicCloseProbeConns     = 3
	quicCloseProbeReserve   = 8 << 10
)

func TestQUICClosePeerCloseReleasesPartialBodies(t *testing.T) {
	srv := New(Config{MaxInFlightBodyBytes: quicCloseProbeBudget})
	srv.Router.Build()
	request := h3AppendHeadersFrame(nil, quicFixGET("/upload"))
	request = quicAppendVarint(request, h3FrameData)
	request = quicAppendVarint(request, 2*quicCloseProbeBodyBytes)
	request = append(request, make([]byte, quicCloseProbeBodyBytes)...)
	for conn := 1; conn <= quicCloseProbeConns; conn++ {
		p := newQUICTestPeerFor(t, srv)
		p.send(quicStreamBytes(0, 0, request, false))
		if held := srv.inFlightBodyBytes.Load(); held < quicCloseProbeBodyBytes {
			t.Fatalf("conn %d: partial request reserved %d bytes, want at least %d", conn, held, quicCloseProbeBodyBytes)
		}
		p.send(quicAppendConnCloseFrame(nil, 0, 0, ""))
		if !p.qc.closed.Load() {
			t.Fatalf("conn %d: peer CONNECTION_CLOSE did not close the connection", conn)
		}
		if held := srv.inFlightBodyBytes.Load(); held != 0 {
			t.Fatalf("conn %d: global body budget leaked after close: %d of %d bytes", conn, held, quicCloseProbeBudget)
		}
		if held := p.qc.bodyReserved.Load(); held != 0 {
			t.Fatalf("conn %d: connection body budget leaked after close: %d", conn, held)
		}
	}
	if !srv.tryReserveBodyBytes(quicCloseProbeReserve) {
		t.Fatal("body budget exhausted after all connections closed")
	}
	srv.releaseBodyBytes(quicCloseProbeReserve)
}
