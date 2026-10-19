package core

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/guno1928/turbo"
)

func emptyContinuationConn(t *testing.T) (*epollConn, *Server) {
	t.Helper()
	server := &Server{}
	conn := &epollConn{worker: &epollWorker{server: server, maxPendingWrite: 1 << 20}}
	conn.h2.decoder = &HpackDecoder{maxHeaderListSize: 16384, maxTableSize: 4096, protocolMaxSize: 4096}
	conn.h2.streams = make(map[uint32]*H2Stream)
	conn.h2.sending = make(map[uint32]*H2Stream)
	conn.h2.prefaceReceived = true
	conn.h2.expectContinuation = 1
	conn.h2.ctrlWindow = turbo.UnixNano()
	conn.h2.initialWindowSize = H2DefaultWindowSize
	conn.h2.maxFrameSize = H2DefaultMaxFrameSize
	t.Cleanup(func() {
		for streamID := range conn.h2.streams {
			epollReleaseH2Stream(&conn.h2, streamID)
		}
	})
	return conn, server
}

func emptyContinuationFeed(conn *epollConn, server *Server, tls bool, frameType, flags byte, streamID uint32, payload []byte) int {
	frame := appendH2Frame(nil, frameType, flags, streamID, payload)
	if tls {
		conn.appBuf = frame
		conn.appBufOff = 0
		return conn.epollProcessH2FramesTLS(server)
	}
	conn.readBuf = frame
	conn.readN = len(frame)
	conn.h2.appBufOff = 0
	return conn.epollProcessH2Frames(server)
}

func emptyContinuationWantGoAway(t *testing.T, conn *epollConn, code uint32) {
	t.Helper()
	out := conn.writeBuf
	if len(out) != 17 || out[3] != H2FrameGoAway || binary.BigEndian.Uint32(out[5:9]) != 0 {
		t.Fatalf("GOAWAY frame = %x", out)
	}
	if got := binary.BigEndian.Uint32(out[13:17]); got != code {
		t.Fatalf("GOAWAY code = %d, want %d", got, code)
	}
}

func TestH2EmptyContinuationControlBudget(t *testing.T) {
	if h2MaxCtrlPerWindow != 5000 || h2ResetWindowNanos != 1_000_000_000 {
		t.Fatal("existing control budget changed")
	}
	for _, transport := range []struct {
		name string
		tls  bool
	}{{"plain", false}, {"decrypted_tls", true}} {
		t.Run(transport.name, func(t *testing.T) {
			t.Run("boundary", func(t *testing.T) {
				conn, server := emptyContinuationConn(t)
				conn.h2.ctrlCount = 5000
				if action := emptyContinuationFeed(conn, server, transport.tls, H2FrameContinuation, 0, 1, nil); action != epollActionCloseAfterFlush || conn.h2.ctrlCount != 5001 {
					t.Fatalf("5001st control action=%d count=%d", action, conn.h2.ctrlCount)
				}
				emptyContinuationWantGoAway(t, conn, H2ErrEnhanceYourCalm)
			})
			t.Run("empty_tail_completes", func(t *testing.T) {
				conn, server := emptyContinuationConn(t)
				conn.h2.headerAccum = hpackBlock([2]string{":method", "POST"}, [2]string{":scheme", "http"}, [2]string{":path", "/fragmented"}, [2]string{":authority", "example.test"})
				conn.h2.ctrlCount = 4999
				if action := emptyContinuationFeed(conn, server, transport.tls, H2FrameContinuation, H2FlagEndHeaders, 1, nil); action != epollActionNeedRead || conn.h2.ctrlCount != 5000 || conn.h2.expectContinuation != 0 || len(conn.writeBuf) != 0 {
					t.Fatalf("tail action=%d count=%d continuation=%d output=%x", action, conn.h2.ctrlCount, conn.h2.expectContinuation, conn.writeBuf)
				}
				stream := conn.h2.streams[1]
				if stream == nil || stream.Method != "POST" || stream.Path != "/fragmented" || stream.Auth != "example.test" {
					t.Fatalf("decoded stream = %+v", stream)
				}
			})
			t.Run("nonempty_at_control_cap", func(t *testing.T) {
				conn, server := emptyContinuationConn(t)
				conn.h2.ctrlCount = 5000
				conn.h2.headerAccum = []byte{0x82}
				if action := emptyContinuationFeed(conn, server, transport.tls, H2FrameContinuation, 0, 1, []byte{0x86}); action != epollActionNeedRead || conn.h2.ctrlCount != 5000 || conn.h2.expectContinuation != 1 || !bytes.Equal(conn.h2.headerAccum, []byte{0x82, 0x86}) || len(conn.writeBuf) != 0 {
					t.Fatalf("progress action=%d count=%d continuation=%d bytes=%x output=%x", action, conn.h2.ctrlCount, conn.h2.expectContinuation, conn.h2.headerAccum, conn.writeBuf)
				}
			})
			t.Run("window_reset", func(t *testing.T) {
				conn, server := emptyContinuationConn(t)
				conn.h2.ctrlCount = 5000
				oldWindow := turbo.UnixNano() - 1_000_000_001
				conn.h2.ctrlWindow = oldWindow
				if action := emptyContinuationFeed(conn, server, transport.tls, H2FrameContinuation, 0, 1, nil); action != epollActionNeedRead || conn.h2.ctrlCount != 1 || conn.h2.ctrlWindow <= oldWindow || len(conn.writeBuf) != 0 {
					t.Fatalf("reset action=%d count=%d window=%d old=%d output=%x", action, conn.h2.ctrlCount, conn.h2.ctrlWindow, oldWindow, conn.writeBuf)
				}
			})
			t.Run("wrong_stream", func(t *testing.T) {
				conn, server := emptyContinuationConn(t)
				conn.h2.ctrlCount = 5000
				if action := emptyContinuationFeed(conn, server, transport.tls, H2FrameContinuation, 0, 3, nil); action != epollActionCloseAfterFlush || conn.h2.ctrlCount != 5000 {
					t.Fatalf("wrong stream action=%d count=%d", action, conn.h2.ctrlCount)
				}
				emptyContinuationWantGoAway(t, conn, H2ErrProtocol)
			})
			t.Run("interleaved_frame", func(t *testing.T) {
				conn, server := emptyContinuationConn(t)
				conn.h2.ctrlCount = 5000
				if action := emptyContinuationFeed(conn, server, transport.tls, H2FramePing, 0, 0, make([]byte, 8)); action != epollActionCloseAfterFlush || conn.h2.ctrlCount != 5000 {
					t.Fatalf("interleaving action=%d count=%d", action, conn.h2.ctrlCount)
				}
				emptyContinuationWantGoAway(t, conn, H2ErrProtocol)
			})
			t.Run("header_byte_budget", func(t *testing.T) {
				conn, server := emptyContinuationConn(t)
				conn.h2.decoder.maxHeaderListSize = 1
				conn.h2.headerAccum = []byte{0x82, 0x86, 0x84, 0x81}
				if action := emptyContinuationFeed(conn, server, transport.tls, H2FrameContinuation, 0, 1, []byte{0x88}); action != epollActionCloseAfterFlush || conn.h2.ctrlCount != 0 || conn.h2.expectContinuation != 0 {
					t.Fatalf("byte limit action=%d count=%d continuation=%d", action, conn.h2.ctrlCount, conn.h2.expectContinuation)
				}
				emptyContinuationWantGoAway(t, conn, H2ErrEnhanceYourCalm)
			})
		})
	}
}
