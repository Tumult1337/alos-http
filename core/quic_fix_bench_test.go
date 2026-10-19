//go:build linux && amd64

package core

import (
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

const (
	quicFixBenchUncachedBlocks = 4096
	quicFixUnlimitedCredit     = uint64(1) << 62
)

type quicFixDiscardConn struct{}

func (quicFixDiscardConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (quicFixDiscardConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, net.ErrClosed }
func (quicFixDiscardConn) Close() error                              { return nil }
func (quicFixDiscardConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (quicFixDiscardConn) SetDeadline(time.Time) error               { return nil }
func (quicFixDiscardConn) SetReadDeadline(time.Time) error           { return nil }
func (quicFixDiscardConn) SetWriteDeadline(time.Time) error          { return nil }

func newQUICFixBenchConn(b *testing.B) *QUICConn {
	b.Helper()
	srv := New(Config{})
	srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	srv.Router.Build()
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	qc := newQUICConn(srv, quicFixDiscardConn{}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}, dcid, dcid)
	qc.maxDataRemote = quicFixUnlimitedCredit
	qc.handshakeDone.Store(true)
	qc.addressValidated.Store(true)
	newH3Conn(qc)
	b.Cleanup(qc.close)
	return qc
}

func quicFixServeOnce(qc *QUICConn, request []byte) {
	s := getPooledStream(0, qc)
	s.refCount.Store(1)
	s.recvBuf = request
	s.recvFin = true
	s.maxSend = quicFixUnlimitedCredit
	qc.h3.handleRequestStream(s)
	qc.releaseStream(s)
}

func BenchmarkQUICFixH3RequestCached(b *testing.B) {
	qc := newQUICFixBenchConn(b)
	request := h3AppendHeadersFrame(nil, quicFixGET("/ok", [2]string{"user-agent", "bench"}, [2]string{"accept", "*/*"}))
	quicFixServeOnce(qc, request)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		quicFixServeOnce(qc, request)
	}
}

func BenchmarkQUICFixH3RequestUncached(b *testing.B) {
	qc := newQUICFixBenchConn(b)
	var dec QPACKDecoder
	for i := 0; i < qpackBlockCacheMaxEntries; i++ {
		block := quicFixGET("/fill?i=" + strconv.Itoa(i))
		fields, err := dec.Decode(block)
		if err != nil {
			b.Fatal(err)
		}
		qpackDecodedBlocks.put(block, fields)
	}
	requests := make([][]byte, quicFixBenchUncachedBlocks)
	for i := range requests {
		requests[i] = h3AppendHeadersFrame(nil, quicFixGET("/ok?miss="+strconv.Itoa(i), [2]string{"user-agent", "bench"}, [2]string{"accept", "*/*"}))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		quicFixServeOnce(qc, requests[i%len(requests)])
	}
}

const (
	quicFixBenchBodySize  = 64 << 10
	quicFixBenchFrameSize = 1100
)

func quicFixBodyFrames(reorder bool) []quicStreamFrame {
	body := make([]byte, quicFixBenchBodySize)
	var frames []quicStreamFrame
	for off := 0; off < len(body); off += quicFixBenchFrameSize {
		end := min(off+quicFixBenchFrameSize, len(body))
		frames = append(frames, quicStreamFrame{streamID: 0, offset: uint64(off), data: body[off:end], fin: end == len(body)})
	}
	if reorder {
		for i := 0; i+1 < len(frames); i += 2 {
			frames[i], frames[i+1] = frames[i+1], frames[i]
		}
	}
	return frames
}

func benchmarkQUICFixStreamBody(b *testing.B, reorder bool) {
	qc := newQUICFixBenchConn(b)
	frames := quicFixBodyFrames(reorder)
	b.ReportAllocs()
	b.SetBytes(quicFixBenchBodySize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := getPooledStream(0, qc)
		s.refCount.Store(1)
		for _, f := range frames {
			s.handleStreamFrame(f)
		}
		qc.releaseStream(s)
		qc.appendConnectionCredit(nil, quicFixBenchBodySize)
	}
}

func BenchmarkQUICFixStreamBodyInOrder(b *testing.B) { benchmarkQUICFixStreamBody(b, false) }

func BenchmarkQUICFixStreamBodyReordered(b *testing.B) { benchmarkQUICFixStreamBody(b, true) }

func BenchmarkQUICFixAckPacket(b *testing.B) {
	qc := newQUICFixBenchConn(b)
	ping := []byte{quicFixPingFrame}
	frames := make([]byte, 0, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pn := uint64(i)
		qc.sendPN[quicSpaceAppData] = pn + 1
		qc.loss.onPacketSent(quicSpaceAppData, pn, quicMaxPacketSize, true, ping)
		frames = quicAppendACKFrame(frames[:0], pn, 0, 0)
		qc.processFrames(quicSpaceAppData, pn, frames)
	}
}

const quicFixBenchInFlight = 200

func BenchmarkQUICFixPTOScanNoExpiry(b *testing.B) {
	ls := newQuicLossState()
	ping := []byte{quicFixPingFrame}
	for pn := uint64(0); pn < quicFixBenchInFlight; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, quicMaxPacketSize, true, ping)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if frames := ls.ptoExpiredFrames(quicSpaceAppData); frames != nil {
			b.Fatal("unexpected PTO expiry")
		}
	}
}

func BenchmarkQUICFixShortPacketReceive(b *testing.B) {
	qc := newQUICFixBenchConn(b)
	_, keys, err := quicDeriveInitialKeys([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		b.Fatal(err)
	}
	qc.keys[quicSpaceAppData] = keys
	payload := make([]byte, quicFixBenchFrameSize)
	payload[0] = quicFixPingFrame
	packet := quicBuildShortPacket(nil, qc.srcCID(), payload, 0, -1, keys, 0)
	scratch := make([]byte, len(packet))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(scratch, packet)
		qc.handleShortHeaderPacket(scratch)
	}
}

func BenchmarkQUICFixH3ResponseEncode(b *testing.B) {
	headers := [][2]string{{"Cache-Control", "no-store"}, {"X-Request-Id", "abc123"}, {"Vary", "Accept-Encoding"}}
	b.ReportAllocs()
	for b.Loop() {
		bp := qpackEncodeResponseHeaders(200, "text/plain", 128, headers, "alos")
		qpackEncodeBufPool.Put(bp)
	}
}

func BenchmarkQUICFixCoalescedDatagramReceive(b *testing.B) {
	qc := newQUICFixBenchConn(b)
	_, appKeys, err := quicDeriveInitialKeys([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		b.Fatal(err)
	}
	_, handshakeKeys, err := quicDeriveInitialKeys([]byte{0xee, 1, 2, 3, 4, 5, 6, 7})
	if err != nil {
		b.Fatal(err)
	}
	qc.keys[quicSpaceAppData] = appKeys
	qc.keys[quicSpaceHandshake] = handshakeKeys
	payload := make([]byte, quicFixBenchFrameSize/2)
	payload[0] = quicFixPingFrame
	datagram := quicBuildHandshakePacket(nil, qc.srcCID(), qc.srcCID(), payload, 0, -1, handshakeKeys)
	datagram = quicBuildShortPacket(datagram, qc.srcCID(), payload, 0, -1, appKeys, 0)
	from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 50000)
	scratch := make([]byte, len(datagram))
	b.ReportAllocs()
	for b.Loop() {
		copy(scratch, datagram)
		qc.processPacket(scratch, from)
	}
}
