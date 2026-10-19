//go:build linux && amd64

package core

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicPeerWait          = 2 * time.Second
	quicPeerPoll          = 10 * time.Millisecond
	h3ErrRequestCancelled = 0x010c
)

type capturePacketConn struct {
	mu    sync.Mutex
	pkts  [][]byte
	addrs []net.Addr
}

func (c *capturePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.pkts = append(c.pkts, append([]byte(nil), p...))
	c.addrs = append(c.addrs, addr)
	c.mu.Unlock()
	return len(p), nil
}

func (c *capturePacketConn) snapshotWithAddrs() ([][]byte, []net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.pkts...), append([]net.Addr(nil), c.addrs...)
}

func (c *capturePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *capturePacketConn) Close() error                           { return nil }
func (c *capturePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (c *capturePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *capturePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *capturePacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *capturePacketConn) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.pkts...)
}

type quicSentFrames struct {
	resets     []quicResetStreamFrame
	stops      []quicStopSendingFrame
	closes     []quicConnCloseFrame
	streams    []quicStreamFrame
	maxStreams []quicMaxStreamsFrame
	newCIDs    []quicNewConnIDFrame
	retires    []uint64
	dcids      [][]byte
	challenges [][quicPathChallengeLen]byte
	responses  [][quicPathChallengeLen]byte
	pns        []uint64
}

type quicTestPeer struct {
	t       *testing.T
	srv     *Server
	qc      *QUICConn
	pc      *capturePacketConn
	keys    *quicKeys
	pn      uint64
	largest int64
	acked   int64
}

func newQUICTestPeer(t *testing.T, routes func(*Router)) *quicTestPeer {
	t.Helper()
	srv := New(Config{})
	if routes != nil {
		routes(srv.Router)
	}
	srv.Router.Build()
	pc := &capturePacketConn{}
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	scid := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	qc := newQUICConn(srv, pc, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}, dcid, scid)
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
	qc.handshakeDone.Store(true)
	newH3Conn(qc)
	t.Cleanup(qc.close)
	return &quicTestPeer{t: t, srv: srv, qc: qc, pc: pc, keys: keys, largest: -1, acked: -1}
}

func (p *quicTestPeer) send(frames []byte) {
	p.qc.processFrames(quicSpaceAppData, p.pn, frames)
	p.pn++
}

func (p *quicTestPeer) decode(raw []byte, largest *int64, out *quicSentFrames) {
	p.t.Helper()
	visitor := &quicFrameVisitor{
		onResetStream: func(f quicResetStreamFrame) { out.resets = append(out.resets, f) },
		onStopSending: func(f quicStopSendingFrame) { out.stops = append(out.stops, f) },
		onConnClose:   func(f quicConnCloseFrame) { out.closes = append(out.closes, f) },
		onMaxStreams:  func(f quicMaxStreamsFrame) { out.maxStreams = append(out.maxStreams, f) },
		onNewConnID: func(f quicNewConnIDFrame) {
			f.connID = append([]byte(nil), f.connID...)
			out.newCIDs = append(out.newCIDs, f)
		},
		onRetireConnID:  func(seq uint64) { out.retires = append(out.retires, seq) },
		onPathChallenge: func(d [quicPathChallengeLen]byte) { out.challenges = append(out.challenges, d) },
		onPathResponse:  func(d [quicPathChallengeLen]byte) { out.responses = append(out.responses, d) },
		onStream: func(f quicStreamFrame) {
			f.data = append([]byte(nil), f.data...)
			out.streams = append(out.streams, f)
		},
	}
	pkt := append([]byte(nil), raw...)
	out.dcids = append(out.dcids, append([]byte(nil), pkt[1:1+p.qc.dstCIDLen]...))
	hdr, err := quicParseShortHeader(pkt, p.qc.dstCIDLen)
	if err != nil {
		p.t.Fatalf("server sent an unparseable packet: %v", err)
	}
	plain, err := quicDecryptPacket(pkt, &hdr, p.keys, *largest)
	if err != nil {
		p.t.Fatalf("server sent an undecryptable packet: %v", err)
	}
	out.pns = append(out.pns, hdr.pn)
	if int64(hdr.pn) > *largest {
		*largest = int64(hdr.pn)
	}
	if int64(hdr.pn) > p.largest {
		p.largest = int64(hdr.pn)
	}
	if err := quicParseFrames(plain, visitor); err != nil {
		p.t.Fatalf("server sent malformed frames: %v", err)
	}
}

func (p *quicTestPeer) sent() quicSentFrames {
	p.t.Helper()
	var out quicSentFrames
	var largest int64
	for _, raw := range p.pc.snapshot() {
		p.decode(raw, &largest, &out)
	}
	return out
}

type quicSentPacketView struct {
	to     string
	size   int
	frames quicSentFrames
}

func (p *quicTestPeer) packets() []quicSentPacketView {
	p.t.Helper()
	raws, addrs := p.pc.snapshotWithAddrs()
	views := make([]quicSentPacketView, len(raws))
	var largest int64
	for i, raw := range raws {
		views[i] = quicSentPacketView{to: addrs[i].String(), size: len(raw)}
		p.decode(raw, &largest, &views[i].frames)
	}
	return views
}

func (p *quicTestPeer) pump() quicSentFrames {
	p.t.Helper()
	got := p.sent()
	if p.largest > p.acked && !p.qc.closed.Load() {
		p.acked = p.largest
		p.send(quicAppendACKFrame(nil, uint64(p.largest), 0, uint64(p.largest)))
	}
	return got
}

func (p *quicTestPeer) awaitSent(what string, cond func(quicSentFrames) bool) quicSentFrames {
	p.t.Helper()
	deadline := turbo.Deadline(quicPeerWait)
	for {
		got := p.pump()
		if cond(got) {
			return got
		}
		if turbo.Until(deadline) <= 0 {
			p.t.Fatalf("timed out waiting for %s; sent %+v", what, got)
		}
		turbo.Sleep(quicPeerPoll)
	}
}

func (p *quicTestPeer) awaitClose(code uint64) {
	p.t.Helper()
	got := p.awaitSent("CONNECTION_CLOSE", func(f quicSentFrames) bool { return len(f.closes) > 0 })
	if got.closes[0].errorCode != code {
		p.t.Fatalf("CONNECTION_CLOSE code %#x, want %#x", got.closes[0].errorCode, code)
	}
	if !p.qc.closed.Load() {
		p.t.Fatal("connection still open after CONNECTION_CLOSE")
	}
}

func (p *quicTestPeer) streamCount() int {
	p.qc.streamsMu.Lock()
	defer p.qc.streamsMu.Unlock()
	return len(p.qc.streams)
}

func (p *quicTestPeer) awaitStreamCount(n int) {
	p.t.Helper()
	deadline := turbo.Deadline(quicPeerWait)
	for p.streamCount() != n {
		if turbo.Until(deadline) <= 0 {
			p.t.Fatalf("stream map holds %d streams, want %d", p.streamCount(), n)
		}
		turbo.Sleep(quicPeerPoll)
	}
}

func h3TestRequest(path string) []byte {
	block := []byte{0x00, 0x00, 0xC0 | 17, 0xC0 | 23, 0x50, byte(len("a.test"))}
	block = append(block, "a.test"...)
	block = append(block, 0x51, byte(len(path)))
	block = append(block, path...)
	return h3AppendHeadersFrame(nil, block)
}

func quicStreamBytes(id, offset uint64, data []byte, fin bool) []byte {
	return quicAppendStreamFrame(nil, id, offset, data, fin)
}

type blockingHandler struct {
	entered chan struct{}
	cause   chan error
	release chan struct{}
}

func newBlockingHandler() *blockingHandler {
	return &blockingHandler{entered: make(chan struct{}, 1), cause: make(chan error, 1), release: make(chan struct{})}
}

func (b *blockingHandler) route(r *Router) {
	r.GET("/block", func(req *Request, resp *Response) {
		b.entered <- struct{}{}
		select {
		case <-req.Context().Done():
			b.cause <- req.CancelCause()
		case <-b.release:
			b.cause <- nil
		}
		resp.Status(200).String("late body")
	})
	r.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
}

func (b *blockingHandler) awaitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-b.entered:
	case <-time.After(quicPeerWait):
		t.Fatal("handler never started")
	}
}

func (b *blockingHandler) awaitCause(t *testing.T, want error) {
	t.Helper()
	select {
	case got := <-b.cause:
		if !errors.Is(got, want) {
			t.Fatalf("handler cancel cause %v, want %v", got, want)
		}
	case <-time.After(quicPeerWait):
		t.Fatal("handler context was never cancelled")
	}
}

func TestQUICResetStreamCancelsRunningHandler(t *testing.T) {
	h := newBlockingHandler()
	p := newQUICTestPeer(t, h.route)
	req := h3TestRequest("/block")
	p.send(quicStreamBytes(0, 0, req, true))
	h.awaitEntered(t)
	p.send(quicAppendResetStreamFrame(nil, 0, h3ErrRequestCancelled, uint64(len(req))))
	h.awaitCause(t, ErrClientGone)
	p.awaitStreamCount(0)
	if got := p.sent(); len(got.closes) != 0 {
		t.Fatalf("a valid RESET_STREAM closed the connection: %+v", got.closes)
	}
}

func TestQUICResetStreamAbandonsIncompleteRequest(t *testing.T) {
	h := newBlockingHandler()
	p := newQUICTestPeer(t, h.route)
	req := h3TestRequest("/block")
	partial := req[:len(req)-3]
	p.send(quicStreamBytes(4, 0, partial, false))
	before := p.qc.dataRecv
	finalSize := uint64(len(partial) + 100)
	p.send(quicAppendResetStreamFrame(nil, 4, h3ErrRequestCancelled, finalSize))

	got := p.awaitSent("RESET_STREAM", func(f quicSentFrames) bool { return len(f.resets) > 0 })
	if r := got.resets[0]; r.streamID != 4 || r.errorCode != h3ErrRequestIncomplete || r.finalSize != 0 {
		t.Fatalf("server RESET_STREAM = %+v, want stream 4 H3_REQUEST_INCOMPLETE final size 0", r)
	}
	p.awaitStreamCount(0)
	if p.qc.dataRecv != before+100 {
		t.Fatalf("connection flow control counted %d bytes, want the final size %d", p.qc.dataRecv, before+100)
	}
	p.send(quicStreamBytes(4, uint64(len(partial)), req[len(partial):], true))
	select {
	case <-h.entered:
		t.Fatal("a reset request was dispatched")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestQUICResetStreamRepeatedIsIdempotent(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.send(quicStreamBytes(8, 0, []byte("abc"), false))
	frame := quicAppendResetStreamFrame(nil, 8, h3ErrRequestCancelled, 3)
	p.send(frame)
	p.send(frame)
	got := p.awaitSent("RESET_STREAM", func(f quicSentFrames) bool { return len(f.resets) > 0 })
	if len(got.resets) != 1 || len(got.closes) != 0 {
		t.Fatalf("repeated reset: %d resets, closes %+v", len(got.resets), got.closes)
	}
}

func TestQUICResetStreamErrors(t *testing.T) {
	cases := []struct {
		name  string
		setup []byte
		reset []byte
		code  uint64
	}{
		{"final size changes after FIN", quicStreamBytes(0, 0, []byte("hello"), true), quicAppendResetStreamFrame(nil, 0, 0, 6), quicErrFinalSize},
		{"final size below received", quicStreamBytes(0, 0, []byte("hello world"), false), quicAppendResetStreamFrame(nil, 0, 0, 5), quicErrFinalSize},
		{"final size below out-of-order data", quicStreamBytes(0, 100, []byte("x"), false), quicAppendResetStreamFrame(nil, 0, 0, 50), quicErrFinalSize},
		{"final size beyond flow control window", quicStreamBytes(0, 0, []byte("a"), false), quicAppendResetStreamFrame(nil, 0, 0, 1<<40), quicErrFlowControl},
		{"send-only stream", nil, quicAppendResetStreamFrame(nil, 3, 0, 0), quicErrStreamState},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newQUICTestPeer(t, nil)
			if tc.setup != nil {
				p.send(tc.setup)
			}
			p.send(tc.reset)
			p.awaitClose(tc.code)
		})
	}
}

func TestQUICStopSendingResetsResponseAndCancelsHandler(t *testing.T) {
	h := newBlockingHandler()
	p := newQUICTestPeer(t, h.route)
	p.send(quicStreamBytes(0, 0, h3TestRequest("/block"), true))
	h.awaitEntered(t)
	p.send(quicAppendStopSendingFrame(nil, 0, h3ErrRequestCancelled))

	got := p.awaitSent("RESET_STREAM", func(f quicSentFrames) bool { return len(f.resets) > 0 })
	if r := got.resets[0]; r.streamID != 0 || r.errorCode != h3ErrRequestCancelled || r.finalSize != 0 {
		t.Fatalf("server RESET_STREAM = %+v, want stream 0 code %#x final size 0", r, h3ErrRequestCancelled)
	}
	h.awaitCause(t, ErrClientGone)
	p.awaitStreamCount(0)
	for _, f := range p.sent().streams {
		if f.streamID == 0 {
			t.Fatalf("response data sent on a stopped stream: %+v", f)
		}
	}
}

func TestQUICStopSendingAfterPartialResponseUsesSentSize(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	s := p.qc.openLocalUniStream()
	payload := []byte("control stream bytes")
	_ = s.Write(payload)
	p.qc.sendStreamData(s)
	p.send(quicAppendStopSendingFrame(nil, s.id, 0x0104))
	got := p.awaitSent("RESET_STREAM", func(f quicSentFrames) bool { return len(f.resets) > 0 })
	if r := got.resets[0]; r.streamID != s.id || r.finalSize != uint64(len(payload)) || r.errorCode != 0x0104 {
		t.Fatalf("RESET_STREAM = %+v, want stream %d final size %d", r, s.id, len(payload))
	}
	if err := s.Write([]byte("more")); err == nil {
		t.Fatal("write after STOP_SENDING succeeded")
	}
}

func TestQUICStopSendingErrors(t *testing.T) {
	cases := []struct {
		name     string
		streamID uint64
	}{
		{"receive-only client uni stream", 2},
		{"server bidi stream never opened", 1},
		{"server uni stream never opened", 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newQUICTestPeer(t, nil)
			p.send(quicAppendStopSendingFrame(nil, tc.streamID, 0))
			p.awaitClose(quicErrStreamState)
		})
	}
}

func TestQUICFrameEncodingErrors(t *testing.T) {
	cases := []struct {
		name   string
		frames []byte
	}{
		{"unknown frame type", []byte{0x21}},
		{"truncated RESET_STREAM", []byte{quicFrameResetStream, 0x00, 0x00}},
		{"truncated STOP_SENDING", []byte{quicFrameStopSending, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newQUICTestPeer(t, nil)
			p.send(tc.frames)
			p.awaitClose(quicErrFrameEncoding)
		})
	}
}

func TestQUICConnectionCloseCancelsHandlers(t *testing.T) {
	h := newBlockingHandler()
	p := newQUICTestPeer(t, h.route)
	p.send(quicStreamBytes(0, 0, h3TestRequest("/block"), true))
	h.awaitEntered(t)
	p.qc.close()
	h.awaitCause(t, ErrClientGone)
}

func TestQUICCompletedRequestIsNotCancelled(t *testing.T) {
	h := newBlockingHandler()
	p := newQUICTestPeer(t, h.route)
	p.send(quicStreamBytes(0, 0, h3TestRequest("/block"), true))
	h.awaitEntered(t)
	close(h.release)
	h.awaitCause(t, nil)
	p.awaitStreamCount(0)
	got := p.awaitSent("response", func(f quicSentFrames) bool {
		for _, s := range f.streams {
			if s.streamID == 0 && s.fin {
				return true
			}
		}
		return false
	})
	if len(got.resets) != 0 {
		t.Fatalf("completed request was reset: %+v", got.resets)
	}
}

func TestQUICStreamAbortAfterHandlerLeavesNoState(t *testing.T) {
	s := &QUICStream{recvFin: true}
	req := &Request{}
	if _, err := s.readRequest(); err != nil {
		t.Fatal(err)
	}
	s.beginHandler(req)
	s.endHandler(req)
	s.mu.Lock()
	s.handlerFinishedLocked()
	s.mu.Unlock()
	s.abortHandler(ErrClientGone)
	if s.cancel.p.Load() != nil {
		t.Fatal("abort after the handler returned left a cancel state behind")
	}
	if req.cancelSrc != nil {
		t.Fatal("endHandler kept the request attached to the stream")
	}

	early := &QUICStream{recvFin: true}
	earlyReq := &Request{}
	early.abortHandler(ErrClientGone)
	if _, err := early.readRequest(); err != nil {
		t.Fatal(err)
	}
	early.beginHandler(earlyReq)
	if !errors.Is(earlyReq.CancelCause(), ErrClientGone) || earlyReq.Context().Err() == nil {
		t.Fatal("a stream aborted before dispatch did not start its handler cancelled")
	}
	early.endHandler(earlyReq)
}

type countingRoutes struct {
	hits atomic.Int32
}

func (c *countingRoutes) route(r *Router) {
	r.GET("/count", func(req *Request, resp *Response) {
		c.hits.Add(1)
		resp.Status(200).String("counted")
	})
}

func (p *quicTestPeer) awaitFin(streamID uint64) {
	p.t.Helper()
	p.awaitSent("response FIN", func(f quicSentFrames) bool {
		for _, s := range f.streams {
			if s.streamID == streamID && s.fin {
				return true
			}
		}
		return false
	})
}

func TestQUICLateStreamFrameForFinishedRequestIsIgnored(t *testing.T) {
	c := &countingRoutes{}
	p := newQUICTestPeer(t, c.route)
	frame := quicStreamBytes(0, 0, h3TestRequest("/count"), true)
	p.send(frame)
	p.awaitFin(0)
	p.awaitStreamCount(0)
	p.send(frame)
	turbo.Sleep(150 * time.Millisecond)
	if got := c.hits.Load(); got != 1 {
		t.Fatalf("a retransmitted request ran the handler %d times", got)
	}
	if p.streamCount() != 0 {
		t.Fatalf("a late frame recreated a finished stream (%d tracked)", p.streamCount())
	}
}

func TestQUICOutOfOrderStreamOpenServesSkippedStreams(t *testing.T) {
	c := &countingRoutes{}
	p := newQUICTestPeer(t, c.route)
	p.send(quicStreamBytes(8, 0, h3TestRequest("/count"), true))
	p.awaitFin(8)
	p.send(quicStreamBytes(0, 0, h3TestRequest("/count"), true))
	p.send(quicStreamBytes(4, 0, h3TestRequest("/count"), true))
	p.awaitFin(0)
	p.awaitFin(4)
	if got := c.hits.Load(); got != 3 {
		t.Fatalf("served %d of 3 requests opened out of order", got)
	}
	p.awaitStreamCount(0)
	if n := len(p.qc.implicitRemote); n != 0 {
		t.Fatalf("%d implicitly opened streams still pending", n)
	}
}

func TestQUICPeerStreamRules(t *testing.T) {
	cases := []struct {
		name     string
		streamID uint64
		code     uint64
	}{
		{"bidi stream beyond MAX_STREAMS", quicMaxBidiStreams << 2, quicErrStreamLimit},
		{"uni stream beyond MAX_STREAMS", quicMaxUniStreams<<2 | 2, quicErrStreamLimit},
		{"server bidi stream", 1, quicErrStreamState},
		{"server uni stream", 3, quicErrStreamState},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newQUICTestPeer(t, nil)
			p.send(quicStreamBytes(tc.streamID, 0, []byte("x"), false))
			p.awaitClose(tc.code)
		})
	}
	p := newQUICTestPeer(t, nil)
	p.send(quicStreamBytes((quicMaxBidiStreams-1)<<2, 0, []byte("x"), false))
	if got := p.sent(); len(got.closes) != 0 {
		t.Fatalf("the last stream inside MAX_STREAMS was rejected: %+v", got.closes)
	}
	if n := len(p.qc.implicitRemote); n != quicMaxBidiStreams-1 {
		t.Fatalf("%d streams implicitly opened, want %d", n, quicMaxBidiStreams-1)
	}
}
