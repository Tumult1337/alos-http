//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

const (
	quicFixSegmentCap          = 256
	quicFixSegmentOverhead     = 64
	quicFixProtocolViolation   = 0x0a
	quicFixFinalSizeError      = 0x06
	quicFixDescendingSegments  = 2000
	quicFixSequentialFrames    = 1000
	quicFixSequentialFrameSize = 100
	quicFixPermutationStride   = 7919
)

func (p *quicTestPeer) streamState(id uint64) (segments int, oooBytes uint64, ok bool) {
	p.qc.streamsMu.Lock()
	s, found := p.qc.streams[id]
	p.qc.streamsMu.Unlock()
	if !found {
		return 0, 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, chunk := range s.recvOOO.chunks {
		for i := range chunk {
			oooBytes += uint64(len(chunk[i].data))
		}
	}
	return s.recvOOO.len(), oooBytes, true
}

func TestQUICFixOutOfOrderSegmentsAreCapped(t *testing.T) {
	p := newQUICFixPeer(t, nil)
	before := p.srv.inFlightBodyBytes.Load()
	for k := quicFixDescendingSegments; k >= 1; k-- {
		p.send(quicStreamBytes(0, uint64(2*k), []byte{'x'}, false))
		segments, _, open := p.streamState(0)
		if !open {
			break
		}
		if segments > quicFixSegmentCap {
			t.Fatalf("stream holds %d out-of-order segments, cap is %d", segments, quicFixSegmentCap)
		}
		if charged := p.srv.inFlightBodyBytes.Load() - before; charged < int64(segments*(1+quicFixSegmentOverhead)) {
			t.Fatalf("%d segments charged only %d bytes to the body budget", segments, charged)
		}
	}
	if _, _, open := p.streamState(0); open || p.qc.closed.Load() {
		t.Fatalf("after %d gaps: stream kept %v, connection closed %v; want the stream rejected and the connection open", quicFixDescendingSegments, open, p.qc.closed.Load())
	}
}

func TestQUICFixOutOfOrderSegmentChargesOverhead(t *testing.T) {
	p := newQUICFixPeer(t, nil)
	before := p.srv.inFlightBodyBytes.Load()
	const gaps = 10
	for k := 1; k <= gaps; k++ {
		p.send(quicStreamBytes(0, uint64(2*k), []byte{'x'}, false))
	}
	charged := p.srv.inFlightBodyBytes.Load() - before
	if want := int64(gaps * (1 + quicFixSegmentOverhead)); charged != want {
		t.Fatalf("%d one-byte gaps charged %d bytes to the body budget, want %d", gaps, charged, want)
	}
}

func TestQUICFixSequentialFramesAfterHoleMerge(t *testing.T) {
	routes := &quicFixH3Routes{}
	p := newQUICFixPeer(t, routes.route)
	head := quicFixQPACKBlock([2]string{":method", "POST"}, [2]string{":scheme", "https"}, [2]string{":authority", "a.test"}, [2]string{":path", "/upload"})
	body := bytes.Repeat([]byte("0123456789"), quicFixSequentialFrames*quicFixSequentialFrameSize/10)
	request := append(h3AppendHeadersFrame(nil, head), h3AppendDataFrame(nil, body)...)
	const hole = quicFixSequentialFrameSize
	for off := hole; off < len(request); off += quicFixSequentialFrameSize {
		end := min(off+quicFixSequentialFrameSize, len(request))
		p.send(quicStreamBytes(0, uint64(off), request[off:end], end == len(request)))
	}
	segments, oooBytes, _ := p.streamState(0)
	if segments != 1 || oooBytes != uint64(len(request)-hole) {
		t.Fatalf("one hole followed by sequential frames left %d segments holding %d bytes, want 1 segment of %d", segments, oooBytes, len(request)-hole)
	}
	p.send(quicStreamBytes(0, 0, request[:hole], false))
	if got := quicFixResponseStatus(t, p, 0); got != 200 {
		t.Fatalf("status %d, want 200", got)
	}
	if p.qc.closed.Load() {
		t.Fatal("a legitimate reordered upload closed the connection")
	}
}

func TestQUICFixOutOfOrderReassemblyPreservesBytes(t *testing.T) {
	p := newQUICFixPeer(t, nil)
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i * 31)
	}
	const chunk = 37
	chunks := (len(data) + chunk - 1) / chunk
	for i := 0; i < chunks; i++ {
		c := (i * quicFixPermutationStride) % chunks
		start := c * chunk
		end := min(start+chunk+c%3*11, len(data))
		p.send(quicStreamBytes(0, uint64(start), data[start:end], false))
		if i%5 == 0 {
			p.send(quicStreamBytes(0, uint64(start), data[start:end], false))
		}
	}
	p.qc.streamsMu.Lock()
	s := p.qc.streams[0]
	p.qc.streamsMu.Unlock()
	s.mu.Lock()
	got := append([]byte(nil), s.recvBuf...)
	segments, accounted := s.recvOOO.len(), s.recvAccounted
	s.mu.Unlock()
	if !bytes.Equal(got, data) {
		t.Fatalf("reassembled %d bytes differ from the %d sent", len(got), len(data))
	}
	if segments != 0 || accounted != int64(len(data)) {
		t.Fatalf("after full reassembly: %d segments left, %d bytes accounted, want 0 and %d", segments, accounted, len(data))
	}
}

func newQUICFixPeer(t *testing.T, routes func(*Router)) *quicTestPeer {
	t.Helper()
	startReqStreamWorkers()
	return newQUICTestPeer(t, routes)
}

func TestQUICFixStreamFinalSizeEnforced(t *testing.T) {
	request := h3AppendHeadersFrame(nil, quicFixGET("/block"))
	size := uint64(len(request))
	cases := []struct {
		name   string
		frames [][]byte
	}{
		{"data past the final size", [][]byte{quicStreamBytes(0, 0, request, true), quicStreamBytes(0, size, []byte("extra"), false)}},
		{"second FIN moves the final size", [][]byte{quicStreamBytes(0, 0, request, true), quicStreamBytes(0, 0, append(append([]byte(nil), request...), "more"...), true)}},
		{"FIN below data already received", [][]byte{quicStreamBytes(0, size, []byte("tail"), false), quicStreamBytes(0, 0, request, true)}},
	}
	for _, tc := range cases {
		b := newBlockingHandler()
		p := newQUICFixPeer(t, b.route)
		var packet []byte
		for _, f := range tc.frames {
			packet = append(packet, f...)
		}
		p.send(packet)
		got := p.awaitSent("CONNECTION_CLOSE", func(f quicSentFrames) bool { return len(f.closes) > 0 })
		if got.closes[0].errorCode != quicFixFinalSizeError {
			t.Errorf("%s: CONNECTION_CLOSE %#x, want FINAL_SIZE_ERROR", tc.name, got.closes[0].errorCode)
		}
	}
}

func TestQUICFixHandshakeKeysDiscardedAtCompletion(t *testing.T) {
	p := newQUICFixPeer(t, nil)
	p.qc.handshakeDone.Store(false)
	p.qc.keys[quicSpaceHandshake] = p.keys
	p.qc.sendKeys[quicSpaceHandshake] = p.keys
	p.qc.sendFrames(quicSpaceHandshake, []byte{quicFixPingFrame}, true)
	ts := newQuicTLSState()
	ts.completeHandshake(p.qc)
	if p.qc.keys[quicSpaceHandshake] != nil || p.qc.sendKeys[quicSpaceHandshake] != nil {
		t.Fatal("Handshake keys were kept after the handshake completed")
	}
	if p.qc.loss.hasSentPackets(quicSpaceHandshake) {
		t.Fatal("Handshake-space packets are still tracked after the keys were discarded")
	}
}
