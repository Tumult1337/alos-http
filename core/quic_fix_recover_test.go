//go:build linux && amd64

package core

import (
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicFixRecoverCeiling = 2 * time.Second
	quicFixRecoverPoll    = 15 * time.Millisecond
)

func TestQUICFixRecvLoopPanicClosesConnection(t *testing.T) {
	startReqStreamWorkers()
	var panics atomic.Int32
	srv := New(Config{
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnPanic: func(*Request, any, []byte) { panics.Add(1) },
	})
	srv.Router.Build()
	p := newQUICTestPeerFor(t, srv)
	p.qc.h3 = &H3Conn{}
	go p.qc.recvLoop()
	p.qc.inbound <- quicInboundPkt{goAway: true}
	deadline := turbo.Deadline(quicFixRecoverCeiling)
	for panics.Load() == 0 && turbo.Until(deadline) > 0 {
		turbo.Sleep(quicFixRecoverPoll)
	}
	if panics.Load() == 0 {
		t.Fatal("injected recvLoop panic was not reported")
	}
	for !p.qc.closed.Load() && turbo.Until(deadline) > 0 {
		turbo.Sleep(quicFixRecoverPoll)
	}
	if !p.qc.closed.Load() {
		t.Fatal("connection stayed open after its recvLoop recovered from a panic")
	}
	select {
	case <-p.qc.done:
	default:
		t.Fatal("done channel not closed after recvLoop panic")
	}
}
