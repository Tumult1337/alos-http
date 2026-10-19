//go:build linux && amd64

package core

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/guno1928/turbo"
)

const (
	quicFix3StreamWindow      = 1 << 20
	quicFix3ConnWindow        = 4 << 20
	quicFix3MaxBody           = 2 << 20
	quicFix3ScaledGapCap      = quicFix3StreamWindow / quicFix3PacketPayload
	quicFix3UploadBody        = quicFix3StreamWindow - 1024
	quicFix3SegmentOverhead   = 64
	quicFix3WideFrameSize     = 16
	quicFix3WideFrames        = 3000
	quicFix3WideStride        = 7919
	quicFix3WideSpanFrames    = 5
	quicFix3H3RequestRejected = 0x010b
)

func newQUICFix3WidePeer(t *testing.T) *quicTestPeer {
	t.Helper()
	startReqStreamWorkers()
	routes := &quicFixH3Routes{}
	srv := New(Config{QUICMaxStreamData: quicFix3StreamWindow, QUICMaxData: quicFix3ConnWindow, MaxBodySize: quicFix3MaxBody, MaxConnsPerIP: -1})
	routes.route(srv.Router)
	srv.Router.Build()
	return newQUICTestPeerFor(t, srv)
}

func quicFix3UploadRequest() ([]byte, []byte) {
	head := quicFixQPACKBlock([2]string{":method", "POST"}, [2]string{":scheme", "https"}, [2]string{":authority", "a.test"}, [2]string{":path", "/upload"})
	body := make([]byte, quicFix3UploadBody)
	for i := range body {
		body[i] = byte(i * 13)
	}
	return append(h3AppendHeadersFrame(nil, head), h3AppendDataFrame(nil, body)...), body
}

func quicFix3SendPackets(p *quicTestPeer, request []byte, parity int) {
	for start := parity * quicFix3PacketPayload; start < len(request); start += 2 * quicFix3PacketPayload {
		end := min(start+quicFix3PacketPayload, len(request))
		p.send(quicStreamBytes(0, uint64(start), request[start:end], end == len(request)))
	}
}

func (p *quicTestPeer) awaitBodyBudget(want int64) int64 {
	p.t.Helper()
	deadline := turbo.Deadline(quicPeerWait)
	held := p.srv.inFlightBodyBytes.Load()
	for held != want && turbo.Until(deadline) > 0 {
		turbo.Sleep(quicPeerPoll)
		held = p.srv.inFlightBodyBytes.Load()
	}
	return held
}

func TestQUICFix3LargeWindowLossyUploadAccepted(t *testing.T) {
	p := newQUICFix3WidePeer(t)
	before := p.srv.inFlightBodyBytes.Load()
	request, body := quicFix3UploadRequest()
	quicFix3SendPackets(p, request, 1)
	segments, oooBytes, open := p.streamState(0)
	if !open || p.qc.closed.Load() {
		t.Fatalf("a lossy upload with every other packet missing was refused: stream open %v, connection closed %v", open, p.qc.closed.Load())
	}
	if segments <= quicFixSegmentCap {
		t.Fatalf("the lossy upload left only %d gaps, want more than %d to exercise the scaled cap", segments, quicFixSegmentCap)
	}
	if charged, want := p.srv.inFlightBodyBytes.Load()-before, int64(oooBytes)+int64(segments*quicFix3SegmentOverhead); charged != want {
		t.Fatalf("%d gaps holding %d bytes charged %d to the body budget, want %d", segments, oooBytes, charged, want)
	}
	quicFix3SendPackets(p, request, 0)
	if status := quicFixResponseStatus(t, p, 0); status != 200 {
		t.Fatalf("lossy upload got status %d, want 200", status)
	}
	reader := h3FrameReader{data: quicFixStreamData(p, 0)}
	reader.next()
	if _, payload, ok := reader.next(); !ok || string(payload) != strconv.Itoa(len(body)) {
		t.Fatalf("handler saw a body of %q bytes, want %d", payload, len(body))
	}
	if held := p.awaitBodyBudget(before); held != before {
		t.Fatalf("after the upload finished the body budget holds %d bytes, want %d", held-before, 0)
	}
}

func TestQUICFix3GapFloodBeyondScaledCapRejected(t *testing.T) {
	p := newQUICFix3WidePeer(t)
	before := p.srv.inFlightBodyBytes.Load()
	for k := quicFix3ScaledGapCap; k >= 1; k-- {
		p.send(quicStreamBytes(0, uint64(2*k), []byte{'x'}, false))
	}
	segments, _, open := p.streamState(0)
	if !open || segments != quicFix3ScaledGapCap {
		t.Fatalf("at the scaled cap: stream open %v with %d gaps, want open with %d", open, segments, quicFix3ScaledGapCap)
	}
	if charged, want := p.srv.inFlightBodyBytes.Load()-before, int64(segments*(1+quicFix3SegmentOverhead)); charged != want {
		t.Fatalf("%d one-byte gaps charged %d to the body budget, want %d", segments, charged, want)
	}
	p.send(quicStreamBytes(0, uint64(2*(quicFix3ScaledGapCap+1)), []byte{'x'}, false))
	if p.qc.closed.Load() {
		t.Fatal("a gap flood beyond the scaled cap closed the whole connection")
	}
	if p.hasStream(0) {
		t.Fatalf("a stream with %d gaps (cap %d) was not rejected", quicFix3ScaledGapCap+1, quicFix3ScaledGapCap)
	}
	reset := false
	for _, r := range p.sent().resets {
		reset = reset || r.streamID == 0 && r.errorCode == quicFix3H3RequestRejected
	}
	if !reset {
		t.Fatal("the flooded stream was not reset with H3_REQUEST_REJECTED")
	}
	if held := p.srv.inFlightBodyBytes.Load() - before; held != 0 {
		t.Fatalf("the rejected stream still holds %d body-budget bytes", held)
	}
}

func quicFix3WideFrame(data []byte, index, span int) quicStreamFrame {
	start := index * quicFix3WideFrameSize
	end := min(start+span*quicFix3WideFrameSize, len(data))
	return quicStreamFrame{offset: uint64(start), data: data[start:end]}
}

func quicFix3CheckWideAccounting(t *testing.T, s *QUICStream, step int) {
	t.Helper()
	overhead := s.recvAccounted - int64(len(s.recvBuf)) - int64(s.oooBytes)
	if overhead < 0 || overhead%quicFix3SegmentOverhead != 0 || (s.oooBytes > 0) != (overhead > 0) {
		t.Fatalf("step %d: %d accounted, %d contiguous, %d out of order: the remainder %d is not a whole number of segment charges", step, s.recvAccounted, len(s.recvBuf), s.oooBytes, overhead)
	}
}

func TestQUICFix3WideReassemblyKeepsBytesAndAccounting(t *testing.T) {
	data := make([]byte, quicFix3WideFrames*quicFix3WideFrameSize)
	for i := range data {
		data[i] = byte(i*31 + i>>8)
	}
	s := newQUICFix3WideStream()
	step := 0
	feed := func(f quicStreamFrame) {
		if _, flags := s.handleStreamFrame(f); flags&quicRecvAccepted == 0 {
			t.Fatalf("step %d: frame at offset %d refused (flags %#x)", step, f.offset, flags)
		}
		quicFix3CheckWideAccounting(t, s, step)
		step++
	}
	for i := 0; i < quicFix3WideFrames; i++ {
		if c := (i * quicFix3WideStride) % quicFix3WideFrames; c%2 == 1 {
			feed(quicFix3WideFrame(data, c, 1))
		}
	}
	for i := 0; i < quicFix3WideFrames; i++ {
		c := (i * quicFix3WideStride) % quicFix3WideFrames
		if c%2 == 1 {
			continue
		}
		feed(quicFix3WideFrame(data, c, 1+c%quicFix3WideSpanFrames))
		if c%7 == 0 {
			feed(quicFix3WideFrame(data, c, 1))
		}
	}
	if !bytes.Equal(s.recvBuf, data) {
		t.Fatalf("reassembled %d bytes differ from the %d sent", len(s.recvBuf), len(data))
	}
	if s.oooBytes != 0 || s.recvAccounted != int64(len(data)) {
		t.Fatalf("after full reassembly: %d out-of-order bytes, %d accounted, want 0 and %d", s.oooBytes, s.recvAccounted, len(data))
	}
}
