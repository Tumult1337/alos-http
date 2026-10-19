//go:build linux && amd64

package core

import (
	"slices"
	"strconv"
	"testing"
)

const (
	quicFix2H3RequestRejected = 0x010b
	quicFix2GapStreamRecvCap  = 1 << 30
)

func TestQUICFix2TooManyGapsRejectsOnlyTheStream(t *testing.T) {
	routes := &quicFixH3Routes{}
	p := newQUICFixPeer(t, routes.route)
	before := p.srv.inFlightBodyBytes.Load()
	for k := quicFixSegmentCap + 1; k >= 1; k-- {
		p.send(quicStreamBytes(0, uint64(2*k), []byte{'x'}, false))
	}
	if p.qc.closed.Load() {
		t.Fatal("too many gaps on one stream closed the whole connection")
	}
	got := p.sent()
	stopped, reset := false, false
	for _, s := range got.stops {
		stopped = stopped || s.streamID == 0 && s.errorCode == quicFix2H3RequestRejected
	}
	for _, r := range got.resets {
		reset = reset || r.streamID == 0 && r.errorCode == quicFix2H3RequestRejected
	}
	if !stopped || !reset {
		t.Fatalf("stream with too many gaps: STOP_SENDING %v, RESET_STREAM %v, want both with H3_REQUEST_REJECTED", stopped, reset)
	}
	if p.hasStream(0) {
		t.Fatal("the rejected stream was not retired")
	}
	if held := p.srv.inFlightBodyBytes.Load() - before; held != 0 {
		t.Fatalf("the rejected stream still holds %d body-budget bytes", held)
	}
	p.send(quicStreamBytes(0, 1, []byte{'y'}, false))
	if p.qc.closed.Load() || p.hasStream(0) {
		t.Fatal("a late frame on the rejected stream reopened it or closed the connection")
	}
	quicFixSendRequest(p, 4, h3AppendHeadersFrame(nil, quicFixGET("/ok")))
	p.awaitHandlersIdle()
	if status := quicFixResponseStatus(t, p, 4); status != 200 {
		t.Fatalf("request after the rejected stream got status %d, want 200", status)
	}
}

func BenchmarkQUICFix2DescendingGapsAtCap(b *testing.B) {
	payload := []byte{'x'}
	b.ReportAllocs()
	for b.Loop() {
		s := &QUICStream{maxRecv: quicFix2GapStreamRecvCap}
		for k := quicFixSegmentCap; k >= 1; k-- {
			s.insertOOO(uint64(2*k), payload)
		}
	}
}

func BenchmarkQUICFix2SegmentInsertFront(b *testing.B) {
	for _, segments := range []int{quicFixSegmentCap, 4 * quicFixSegmentCap, 16 * quicFixSegmentCap} {
		b.Run(strconv.Itoa(segments), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var list []quicOOOSegment
				for k := segments; k >= 1; k-- {
					list = slices.Insert(list, 0, quicOOOSegment{off: uint64(2 * k)})
				}
			}
		})
	}
}

func TestQUICFix2TooManyGapsOnUniStreamClosesWithExcessiveLoad(t *testing.T) {
	p := newQUICFixPeer(t, nil)
	const peerUniStream = 2
	for k := quicFixSegmentCap + 1; k >= 1 && !p.qc.closed.Load(); k-- {
		p.send(quicStreamBytes(peerUniStream, uint64(2*k), []byte{'x'}, false))
	}
	p.awaitClose(quicFixH3ExcessiveLoad)
}
