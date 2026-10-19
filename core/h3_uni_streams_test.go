//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

const (
	clientControlStream = 2
	clientEncoderStream = 6
	clientDecoderStream = 10
	clientExtraUni      = 14
	h3GreaseType        = 0x21
)

func h3Settings(pairs ...uint64) []byte {
	var payload []byte
	for _, v := range pairs {
		payload = quicAppendVarint(payload, v)
	}
	return h3AppendFrame(nil, h3FrameSettings, payload)
}

func h3Frame(frameType uint64, payload []byte) []byte {
	return h3AppendFrame(nil, frameType, payload)
}

func uniStream(streamType uint64, frames ...[]byte) []byte {
	out := quicAppendVarint(nil, streamType)
	for _, f := range frames {
		out = append(out, f...)
	}
	return out
}

func (p *quicTestPeer) sendStream(id uint64, offset uint64, data []byte, fin bool) uint64 {
	p.send(quicStreamBytes(id, offset, data, fin))
	return offset + uint64(len(data))
}

func (p *quicTestPeer) expectOpen() {
	p.t.Helper()
	if got := p.pump(); len(got.closes) != 0 || p.qc.closed.Load() {
		p.t.Fatalf("connection closed: %+v", got.closes)
	}
}

func TestH3UniStreamsValidSetup(t *testing.T) {
	c := &countingRoutes{}
	p := newQUICTestPeer(t, c.route)
	grease := h3Frame(h3GreaseType, bytes.Repeat([]byte{0xAA}, 1000))
	control := uniStream(h3StreamControl,
		h3Settings(0x06, 16384, 0x21, 7, 0x01, 0),
		h3Frame(h3FrameGoaway, []byte{0x00}),
		h3Frame(h3FrameMaxPushID, []byte{0x04}),
		grease,
		h3Frame(h3FrameCancelPush, []byte{0x01}),
	)
	off := uint64(0)
	for _, cut := range []int{1, 2, 5, 40, 700, len(control)} {
		if uint64(cut) <= off {
			continue
		}
		off = p.sendStream(clientControlStream, off, control[off:cut], false)
	}
	p.sendStream(clientEncoderStream, 0, uniStream(h3StreamQPACKEnc, []byte{qpackSetCapacityZero}), false)
	p.sendStream(clientDecoderStream, 0, uniStream(h3StreamQPACKDec, []byte{0x41, 0x05}), false)
	p.expectOpen()
	h3 := p.qc.h3
	if !h3.peerControlSeen || !h3.peerEncoderSeen || !h3.peerDecoderSeen {
		t.Fatalf("peer streams not recognised: control=%v encoder=%v decoder=%v", h3.peerControlSeen, h3.peerEncoderSeen, h3.peerDecoderSeen)
	}
	if st := h3.peerStreams[clientControlStream]; st == nil || !st.settingsSeen || len(st.pending) != 0 || st.skip != 0 {
		t.Fatalf("control stream state after a complete frame sequence: %+v", st)
	}
	p.send(quicStreamBytes(0, 0, h3TestRequest("/count"), true))
	p.awaitFin(0)
	if c.hits.Load() != 1 {
		t.Fatal("request not served alongside the peer uni streams")
	}
	if s := p.qc.acquireStream(clientControlStream); s == nil {
		t.Fatal("control stream was dropped")
	} else {
		s.mu.Lock()
		buffered := len(s.recvBuf)
		s.mu.Unlock()
		p.qc.releaseStream(s)
		if buffered != 0 {
			t.Fatalf("control stream data left buffered: %d bytes", buffered)
		}
	}
}

func TestH3UniStreamTypeSplitAcrossFrames(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	data := append([]byte{0x40, 0x00}, h3Settings()...)
	p.sendStream(clientControlStream, 0, data[:1], false)
	if p.qc.h3.peerControlSeen {
		t.Fatal("stream typed before its varint was complete")
	}
	p.sendStream(clientControlStream, 1, data[1:], false)
	p.expectOpen()
	if !p.qc.h3.peerControlSeen || !p.qc.h3.peerStreams[clientControlStream].settingsSeen {
		t.Fatal("two-byte stream type split across frames was not recognised")
	}
}

func TestH3UniStreamErrors(t *testing.T) {
	settings := h3Settings(0x06, 100)
	cases := []struct {
		name  string
		setup func(p *quicTestPeer)
		code  uint64
	}{
		{"first control frame is not SETTINGS", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, h3Frame(h3FrameGoaway, []byte{0})), false)
		}, h3ErrMissingSettings},
		{"unknown frame before SETTINGS", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, h3Frame(h3GreaseType, nil)), false)
		}, h3ErrMissingSettings},
		{"second SETTINGS", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, settings, settings), false)
		}, h3ErrFrameUnexpected},
		{"DATA on control stream", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, settings, h3Frame(h3FrameData, []byte("x"))), false)
		}, h3ErrFrameUnexpected},
		{"HEADERS on control stream", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, settings, h3Frame(h3FrameHeaders, []byte{0, 0})), false)
		}, h3ErrFrameUnexpected},
		{"PUSH_PROMISE from client", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, settings, h3Frame(h3FramePushPromise, []byte{0})), false)
		}, h3ErrFrameUnexpected},
		{"HTTP/2 PING frame type", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, settings, h3Frame(0x06, nil)), false)
		}, h3ErrFrameUnexpected},
		{"HTTP/2 setting identifier", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, h3Settings(0x03, 100)), false)
		}, h3ErrSettings},
		{"duplicate setting", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, h3Settings(0x06, 1, 0x06, 2)), false)
		}, h3ErrSettings},
		{"truncated setting", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, h3Frame(h3FrameSettings, []byte{0x06})), false)
		}, h3ErrFrame},
		{"oversized SETTINGS", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, h3Frame(h3FrameSettings, make([]byte, h3MaxControlFramePayload+1))), false)
		}, h3ErrExcessiveLoad},
		{"GOAWAY with trailing bytes", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, settings, h3Frame(h3FrameGoaway, []byte{0, 0})), false)
		}, h3ErrFrame},
		{"second control stream", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, settings), false)
			p.sendStream(clientEncoderStream, 0, uniStream(h3StreamControl, settings), false)
		}, h3ErrStreamCreation},
		{"client push stream", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamPush, []byte{0}), false)
		}, h3ErrStreamCreation},
		{"second encoder stream", func(p *quicTestPeer) {
			p.sendStream(clientEncoderStream, 0, uniStream(h3StreamQPACKEnc), false)
			p.sendStream(clientDecoderStream, 0, uniStream(h3StreamQPACKEnc), false)
		}, h3ErrStreamCreation},
		{"second decoder stream", func(p *quicTestPeer) {
			p.sendStream(clientEncoderStream, 0, uniStream(h3StreamQPACKDec), false)
			p.sendStream(clientDecoderStream, 0, uniStream(h3StreamQPACKDec), false)
		}, h3ErrStreamCreation},
		{"dynamic table insert", func(p *quicTestPeer) {
			p.sendStream(clientEncoderStream, 0, uniStream(h3StreamQPACKEnc, []byte{0xC0 | 17}), false)
		}, qpackErrEncoderStream},
		{"control stream FIN", func(p *quicTestPeer) {
			p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, settings), true)
		}, h3ErrClosedCriticalStream},
		{"control stream reset", func(p *quicTestPeer) {
			n := p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, settings), false)
			p.send(quicAppendResetStreamFrame(nil, clientControlStream, 0, n))
		}, h3ErrClosedCriticalStream},
		{"encoder stream FIN", func(p *quicTestPeer) {
			p.sendStream(clientEncoderStream, 0, uniStream(h3StreamQPACKEnc), true)
		}, h3ErrClosedCriticalStream},
		{"decoder stream reset", func(p *quicTestPeer) {
			n := p.sendStream(clientDecoderStream, 0, uniStream(h3StreamQPACKDec), false)
			p.send(quicAppendResetStreamFrame(nil, clientDecoderStream, 0, n))
		}, h3ErrClosedCriticalStream},
		{"SETTINGS on a request stream", func(p *quicTestPeer) {
			p.send(quicStreamBytes(0, 0, append(h3Settings(), h3TestRequest("/")...), true))
		}, h3ErrFrameUnexpected},
		{"HTTP/2 frame type on a request stream", func(p *quicTestPeer) {
			p.send(quicStreamBytes(0, 0, append(h3Frame(0x08, nil), h3TestRequest("/")...), true))
		}, h3ErrFrameUnexpected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newQUICTestPeer(t, nil)
			tc.setup(p)
			p.awaitClose(tc.code)
			if !p.sent().closes[0].isApp {
				t.Fatal("HTTP/3 error sent as a transport CONNECTION_CLOSE")
			}
		})
	}
}

func TestH3UnknownUniStreamIsStoppedNotFatal(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	n := p.sendStream(clientExtraUni, 0, uniStream(h3GreaseType, []byte("ignored payload")), false)
	got := p.awaitSent("STOP_SENDING", func(f quicSentFrames) bool { return len(f.stops) > 0 })
	if s := got.stops[0]; s.streamID != clientExtraUni || s.errorCode != h3ErrStreamCreation {
		t.Fatalf("STOP_SENDING = %+v, want stream %d code %#x", s, clientExtraUni, h3ErrStreamCreation)
	}
	p.sendStream(clientExtraUni, n, []byte("more"), true)
	p.awaitStreamCount(0)
	got = p.awaitSent("MAX_STREAMS uni", func(f quicSentFrames) bool {
		for _, m := range f.maxStreams {
			if !m.bidi {
				return true
			}
		}
		return false
	})
	for _, m := range got.maxStreams {
		if !m.bidi && m.maxStreams != quicMaxUniStreams+1 {
			t.Fatalf("uni credit %d, want %d", m.maxStreams, quicMaxUniStreams+1)
		}
	}
	p.expectOpen()
}

func TestH3UnknownUniStreamResetIsRetired(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	n := p.sendStream(clientExtraUni, 0, uniStream(h3GreaseType), false)
	p.send(quicAppendResetStreamFrame(nil, clientExtraUni, h3ErrStreamCreation, n))
	p.awaitStreamCount(0)
	p.expectOpen()
}

func TestH3UniStreamClosedBeforeTypeIsTolerated(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.sendStream(clientExtraUni, 0, nil, true)
	p.send(quicAppendResetStreamFrame(nil, clientExtraUni+4, 0, 0))
	p.awaitStreamCount(0)
	p.expectOpen()
}

func TestH3PeerStreamsBufferedBeforeH3StartAreRead(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.qc.h3 = nil
	p.sendStream(clientControlStream, 0, uniStream(h3StreamControl, h3Settings(0x06, 1)), false)
	h3 := newH3Conn(p.qc)
	h3.start()
	if !h3.peerControlSeen || !h3.peerStreams[clientControlStream].settingsSeen {
		t.Fatal("control stream data that arrived before HTTP/3 started was never read")
	}
	p.expectOpen()
}

func controlStreamVerdict(data []byte, cuts []byte) (uint64, bool, uint64) {
	h3 := &H3Conn{}
	st := &h3PeerStream{kind: h3PeerStreamControl}
	pos := 0
	for _, c := range cuts {
		if pos >= len(data) {
			break
		}
		end := pos + int(c)%(len(data)-pos) + 1
		if err := h3.consumeControlStream(st, append([]byte(nil), data[pos:end]...)); err != nil {
			return err.code, st.settingsSeen, 0
		}
		pos = end
	}
	if pos < len(data) {
		if err := h3.consumeControlStream(st, append([]byte(nil), data[pos:]...)); err != nil {
			return err.code, st.settingsSeen, 0
		}
	}
	return 0, st.settingsSeen, uint64(len(st.pending)) + st.skip
}

func FuzzH3ControlStream(f *testing.F) {
	f.Add(append(h3Settings(0x06, 100, 0x21, 1), h3Frame(h3FrameGoaway, []byte{4})...), []byte{1, 3, 7})
	f.Add(append(h3Settings(), h3Frame(h3GreaseType, make([]byte, 300))...), []byte{2, 200})
	f.Add(h3Settings(0x03, 1), []byte{0})
	f.Add(append(h3Settings(), h3Settings()...), []byte{5})
	f.Add([]byte{0x04, 0x40}, []byte{1})
	f.Fuzz(func(t *testing.T, data []byte, cuts []byte) {
		wholeCode, wholeSettings, wholeLeft := controlStreamVerdict(data, nil)
		splitCode, splitSettings, splitLeft := controlStreamVerdict(data, cuts)
		if wholeCode != splitCode || wholeSettings != splitSettings || wholeLeft != splitLeft {
			t.Fatalf("control stream verdict depends on chunking: whole (%#x, %v, %d) split (%#x, %v, %d)", wholeCode, wholeSettings, wholeLeft, splitCode, splitSettings, splitLeft)
		}
	})
}
