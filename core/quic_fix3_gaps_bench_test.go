//go:build linux && amd64

package core

import (
	"strconv"
	"testing"
)

const (
	quicFix3PacketPayload = 1200
	quicFix3BenchWindow   = 1 << 26
)

var quicFix3GapCounts = []int{256, 1024, 4096}

func quicFix3Packet(index int, payload []byte) quicStreamFrame {
	return quicStreamFrame{offset: uint64(index * len(payload)), data: payload}
}

func quicFix3LossyTailFrames(gaps int) []quicStreamFrame {
	payload := make([]byte, quicFix3PacketPayload)
	frames := make([]quicStreamFrame, 0, 2*gaps)
	for k := 0; k < gaps; k++ {
		frames = append(frames, quicFix3Packet(2*k+1, payload))
	}
	for k := 0; k < gaps; k++ {
		frames = append(frames, quicFix3Packet(2*k, payload))
	}
	return frames
}

func quicFix3MiddleInsertFrames(gaps int) []quicStreamFrame {
	payload := make([]byte, quicFix3PacketPayload)
	frames := make([]quicStreamFrame, 0, 3*gaps)
	for k := 0; k < gaps; k++ {
		frames = append(frames, quicFix3Packet(3*k+2, payload))
	}
	for k := gaps - 1; k >= 0; k-- {
		frames = append(frames, quicFix3Packet(3*k+1, payload))
	}
	for k := gaps - 1; k >= 0; k-- {
		frames = append(frames, quicFix3Packet(3*k, payload))
	}
	return frames
}

func quicFix3DescendingFrames(gaps int) []quicStreamFrame {
	payload := []byte{'x'}
	frames := make([]quicStreamFrame, 0, gaps)
	for k := gaps; k >= 1; k-- {
		frames = append(frames, quicStreamFrame{offset: uint64(2 * k), data: payload})
	}
	return frames
}

func newQUICFix3WideStream() *QUICStream {
	return &QUICStream{maxRecv: quicFix3BenchWindow, recvWindow: quicFix3BenchWindow, recvGranted: quicFix3BenchWindow}
}

func benchmarkQUICFix3Frames(b *testing.B, build func(int) []quicStreamFrame) {
	for _, gaps := range quicFix3GapCounts {
		frames := build(gaps)
		b.Run(strconv.Itoa(gaps), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				s := newQUICFix3WideStream()
				for _, f := range frames {
					if _, flags := s.handleStreamFrame(f); flags&quicRecvAccepted == 0 {
						b.Fatalf("frame at offset %d was refused (flags %#x)", f.offset, flags)
					}
				}
			}
		})
	}
}

func BenchmarkQUICFix3LossyTailThenHeadFill(b *testing.B) {
	benchmarkQUICFix3Frames(b, quicFix3LossyTailFrames)
}

func BenchmarkQUICFix3MiddleInsertFill(b *testing.B) {
	benchmarkQUICFix3Frames(b, quicFix3MiddleInsertFrames)
}

func BenchmarkQUICFix3DescendingGaps(b *testing.B) {
	benchmarkQUICFix3Frames(b, quicFix3DescendingFrames)
}

const (
	quicFix3InOrderFrameSize = 64
	quicFix3UnboundedWindow  = 1 << 62
)

func BenchmarkQUICFix3InOrderFrame(b *testing.B) {
	s := &QUICStream{maxRecv: quicFix3UnboundedWindow, recvWindow: quicFix3UnboundedWindow, recvGranted: quicFix3UnboundedWindow}
	payload := make([]byte, quicFix3InOrderFrameSize)
	b.ReportAllocs()
	for b.Loop() {
		s.handleStreamFrame(quicStreamFrame{offset: s.recvOff, data: payload})
		s.recvBuf = s.recvBuf[:0]
	}
}
