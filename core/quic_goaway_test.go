//go:build linux && amd64

package core

import (
	"testing"

	"github.com/guno1928/turbo"
)

func controlStreamGoAways(t *testing.T, f quicSentFrames, controlID uint64) []uint64 {
	t.Helper()
	var data []byte
	for _, s := range f.streams {
		if s.streamID != controlID {
			continue
		}
		if end := int(s.offset) + len(s.data); end > len(data) {
			data = append(data, make([]byte, end-len(data))...)
		}
		copy(data[s.offset:], s.data)
	}
	if len(data) == 0 {
		return nil
	}
	streamType, n := quicParseVarint(data)
	if n <= 0 || streamType != h3StreamControl {
		t.Fatalf("control stream starts with type %d", streamType)
	}
	var ids []uint64
	reader := h3FrameReader{data: data[n:]}
	for {
		frameType, payload, ok := reader.next()
		if !ok {
			return ids
		}
		if frameType == h3FrameGoaway {
			id, m := quicParseVarint(payload)
			if m != len(payload) {
				t.Fatalf("GOAWAY payload %x is not a single varint", payload)
			}
			ids = append(ids, id)
		}
	}
}

func newGoAwayPeer(t *testing.T, routes func(*Router)) *quicTestPeer {
	p := newQUICTestPeer(t, routes)
	p.qc.h3.sendControlStream()
	return p
}

func (p *quicTestPeer) awaitDrainClose() quicConnCloseFrame {
	p.t.Helper()
	got := p.awaitSent("drain CONNECTION_CLOSE", func(f quicSentFrames) bool {
		p.qc.tick(turbo.UnixNano(), false)
		return len(f.closes) > 0
	})
	if !p.qc.closed.Load() {
		p.t.Fatal("connection still open after the drain close")
	}
	return got.closes[0]
}

func TestH3GoAwayDrainsInFlightRequestThenCloses(t *testing.T) {
	h := newBlockingHandler()
	c := &countingRoutes{}
	p := newGoAwayPeer(t, func(r *Router) {
		h.route(r)
		c.route(r)
	})
	p.send(quicStreamBytes(0, 0, h3TestRequest("/block"), true))
	h.awaitEntered(t)

	p.qc.beginGoAway()
	got := p.awaitSent("GOAWAY", func(f quicSentFrames) bool {
		return len(controlStreamGoAways(t, f, p.qc.h3.controlID)) > 0
	})
	if ids := controlStreamGoAways(t, got, p.qc.h3.controlID); len(ids) != 1 || ids[0] != 4 {
		t.Fatalf("GOAWAY ids %v, want [4] (the first unprocessed client bidi stream)", ids)
	}

	p.send(quicStreamBytes(4, 0, h3TestRequest("/count"), true))
	got = p.awaitSent("refusal of stream 4", func(f quicSentFrames) bool { return len(f.resets) > 0 && len(f.stops) > 0 })
	if r := got.resets[0]; r.streamID != 4 || r.errorCode != h3ErrRequestRejected || r.finalSize != 0 {
		t.Fatalf("RESET_STREAM %+v, want stream 4 H3_REQUEST_REJECTED final size 0", r)
	}
	if s := got.stops[0]; s.streamID != 4 || s.errorCode != h3ErrRequestRejected {
		t.Fatalf("STOP_SENDING %+v, want stream 4 H3_REQUEST_REJECTED", s)
	}
	p.send(quicStreamBytes(4, 0, h3TestRequest("/count"), true))
	if c.hits.Load() != 0 {
		t.Fatal("a request above the GOAWAY id reached its handler")
	}

	p.pump()
	p.qc.tick(turbo.UnixNano(), false)
	if p.qc.closed.Load() {
		t.Fatal("connection closed while a request below the GOAWAY id was still running")
	}

	close(h.release)
	h.awaitCause(t, nil)
	p.awaitFin(0)
	if cc := p.awaitDrainClose(); !cc.isApp || cc.errorCode != h3ErrNoError {
		t.Fatalf("drain close %+v, want application close H3_NO_ERROR", cc)
	}
}

func TestH3GoAwayIdleConnectionClosesOnceGoAwayIsAcked(t *testing.T) {
	p := newGoAwayPeer(t, nil)
	p.qc.beginGoAway()
	got := p.sent()
	if ids := controlStreamGoAways(t, got, p.qc.h3.controlID); len(ids) != 1 || ids[0] != 0 {
		t.Fatalf("GOAWAY ids %v on an idle connection, want [0]", ids)
	}
	p.qc.tick(turbo.UnixNano(), false)
	if p.qc.closed.Load() {
		t.Fatal("connection closed before the peer acknowledged GOAWAY")
	}
	if cc := p.awaitDrainClose(); !cc.isApp || cc.errorCode != h3ErrNoError {
		t.Fatalf("drain close %+v, want application close H3_NO_ERROR", cc)
	}
}

func TestH3GoAwayKeepsServingStreamsBelowTheID(t *testing.T) {
	c := &countingRoutes{}
	p := newGoAwayPeer(t, c.route)
	req := h3TestRequest("/count")
	p.send(quicStreamBytes(8, 0, req, true))
	p.awaitFin(8)
	p.qc.beginGoAway()
	if ids := controlStreamGoAways(t, p.sent(), p.qc.h3.controlID); len(ids) != 1 || ids[0] != 12 {
		t.Fatalf("GOAWAY ids %v, want [12]", ids)
	}
	p.send(quicStreamBytes(0, 0, req, true))
	p.awaitFin(0)
	p.send(quicStreamBytes(4, 0, req, true))
	p.awaitFin(4)
	if c.hits.Load() != 3 {
		t.Fatalf("handler ran %d times, want 3 (streams 0 and 4 were opened implicitly before GOAWAY)", c.hits.Load())
	}
}

func TestQUICShutdownBeforeH3ClosesWithNoError(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.qc.h3 = nil
	p.qc.beginGoAway()
	got := p.sent()
	if len(got.closes) != 1 || got.closes[0].isApp || got.closes[0].errorCode != quicErrNoError || !p.qc.closed.Load() {
		t.Fatalf("closes %+v closed=%v, want one transport NO_ERROR close", got.closes, p.qc.closed.Load())
	}
}

func TestH3ForcedShutdownCancelsHandlers(t *testing.T) {
	h := newBlockingHandler()
	p := newGoAwayPeer(t, h.route)
	p.send(quicStreamBytes(0, 0, h3TestRequest("/block"), true))
	h.awaitEntered(t)
	p.qc.beginGoAway()
	p.qc.closeForShutdown(ErrServerShutdown)
	h.awaitCause(t, ErrServerShutdown)
	got := p.sent()
	if len(got.closes) != 1 || !got.closes[0].isApp || got.closes[0].errorCode != h3ErrNoError {
		t.Fatalf("forced close %+v, want application close H3_NO_ERROR", got.closes)
	}
}

func TestQUICTimerHubRunsUntilDrainedConnectionsClose(t *testing.T) {
	p := newGoAwayPeer(t, nil)
	hub := &p.srv.quicTimers
	done := make(chan struct{})
	hub.add(p.qc, done)
	close(done)
	stopped := make(chan struct{})
	go func() {
		hub.awaitStopped()
		close(stopped)
	}()
	p.qc.beginGoAway()
	select {
	case <-stopped:
		t.Fatal("timer hub stopped while a draining connection was still open")
	default:
	}
	p.awaitSent("drain close from the hub tick", func(f quicSentFrames) bool { return len(f.closes) > 0 })
	select {
	case <-stopped:
	case <-turbo.After(quicPeerWait):
		t.Fatal("timer hub never stopped after its last connection closed")
	}
}

func TestQUICTimerHubCloseAll(t *testing.T) {
	h := newBlockingHandler()
	p := newGoAwayPeer(t, h.route)
	p.send(quicStreamBytes(0, 0, h3TestRequest("/block"), true))
	h.awaitEntered(t)
	hub := &p.srv.quicTimers
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	hub.add(p.qc, done)
	hub.closeAll(ErrServerShutdown)
	h.awaitCause(t, ErrServerShutdown)
	if !p.qc.closed.Load() {
		t.Fatal("closeAll left the connection open")
	}
}

func awaitGoAwaySignal(t *testing.T, qc *QUICConn) {
	t.Helper()
	select {
	case pkt := <-qc.inbound:
		if !pkt.goAway {
			t.Fatalf("inbound carried %+v, want the GOAWAY signal", pkt)
		}
	case <-turbo.After(quicPeerWait):
		t.Fatal("no GOAWAY signal reached the connection")
	}
}

func TestQUICTimerHubSignalsGoAwayToEveryConnection(t *testing.T) {
	early := newGoAwayPeer(t, nil)
	late := newGoAwayPeer(t, nil)
	hub := &early.srv.quicTimers
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	hub.add(early.qc, done)
	hub.goAwayAll()
	awaitGoAwaySignal(t, early.qc)
	hub.add(late.qc, done)
	awaitGoAwaySignal(t, late.qc)
}

func TestQUICGoAwaySignalWaitsForAFullInbox(t *testing.T) {
	p := newGoAwayPeer(t, nil)
	for len(p.qc.inbound) < cap(p.qc.inbound) {
		p.qc.inbound <- quicInboundPkt{}
	}
	p.qc.signalGoAway()
	for i := 0; i < cap(p.qc.inbound); i++ {
		if pkt := <-p.qc.inbound; pkt.goAway {
			t.Fatal("GOAWAY signal overtook packets already queued")
		}
	}
	awaitGoAwaySignal(t, p.qc)
}
