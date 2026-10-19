//go:build linux && amd64

package core

import (
	"strconv"
	"testing"
)

const quicFix3InvariantGaps = 5 * quicOOOChunkLen

func quicFix3CheckOOOList(t *testing.T, s *QUICStream, step int) {
	t.Helper()
	l := &s.recvOOO
	count, held := 0, uint64(0)
	prevEnd := s.recvOff
	for c, chunk := range l.chunks {
		if len(chunk) == 0 || len(chunk) > quicOOOChunkLen {
			t.Fatalf("step %d: chunk %d holds %d segments, want 1..%d", step, c, len(chunk), quicOOOChunkLen)
		}
		for i := range chunk {
			seg := &chunk[i]
			ordered := seg.off >= prevEnd
			if count == 0 {
				ordered = seg.off > s.recvOff
			}
			if len(seg.data) == 0 || !ordered {
				t.Fatalf("step %d: segment %d at [%d,%d) is empty or out of order (read offset %d, previous end %d)", step, count, seg.off, seg.end(), s.recvOff, prevEnd)
			}
			prevEnd = seg.end()
			held += uint64(len(seg.data))
			count++
		}
	}
	if count != l.len() || held != s.oooBytes {
		t.Fatalf("step %d: list reports %d segments and stream %d bytes, chunks hold %d segments and %d bytes", step, l.len(), s.oooBytes, count, held)
	}
	if count > s.oooSegmentCap() {
		t.Fatalf("step %d: %d segments exceed the cap %d", step, count, s.oooSegmentCap())
	}
	if count > 0 && l.last().end() != prevEnd {
		t.Fatalf("step %d: last() ends at %d, the list ends at %d", step, l.last().end(), prevEnd)
	}
}

func TestQUICFix3OOOListInvariantsHold(t *testing.T) {
	patterns := map[string]func(int) []quicStreamFrame{
		"lossy tail then head fill": quicFix3LossyTailFrames,
		"middle inserts":            quicFix3MiddleInsertFrames,
		"descending gaps":           quicFix3DescendingFrames,
	}
	for name, build := range patterns {
		t.Run(name, func(t *testing.T) {
			s := newQUICFix3WideStream()
			for step, f := range build(quicFix3InvariantGaps) {
				if _, flags := s.handleStreamFrame(f); flags&quicRecvAccepted == 0 {
					t.Fatalf("step %d: frame at offset %d refused (flags %#x)", step, f.offset, flags)
				}
				quicFix3CheckOOOList(t, s, step)
			}
		})
	}
}

func TestQUICFix3OOOListReusesStorageAfterDrain(t *testing.T) {
	s := newQUICFix3WideStream()
	payload := []byte{'x'}
	for round := 0; round < quicOOOChunkLen; round++ {
		base := uint64(2 * round)
		if _, flags := s.handleStreamFrame(quicStreamFrame{offset: base + 1, data: payload}); flags&quicRecvAccepted == 0 {
			t.Fatalf("round %d: gap frame refused", round)
		}
		if s.recvOOO.len() != 1 {
			t.Fatalf("round %d: %d segments, want 1", round, s.recvOOO.len())
		}
		if _, flags := s.handleStreamFrame(quicStreamFrame{offset: base, data: payload}); flags&quicRecvAccepted == 0 {
			t.Fatalf("round %d: fill frame refused", round)
		}
		quicFix3CheckOOOList(t, s, round)
		if s.recvOOO.len() != 0 || s.recvOOO.spare == nil {
			t.Fatalf("round %d: after the fill %d segments remain, spare kept %v", round, s.recvOOO.len(), s.recvOOO.spare != nil)
		}
	}
	if allocs := testing.AllocsPerRun(quicOOOChunkLen, func() {
		s.handleStreamFrame(quicStreamFrame{offset: s.recvOff + 1, data: payload})
		s.handleStreamFrame(quicStreamFrame{offset: s.recvOff, data: payload})
	}); allocs > 1 {
		t.Fatalf("a gap opened and filled on a drained list cost %v allocations, want at most 1 (the segment data)", allocs)
	}
}

func TestQUICFix3SegmentCapScalesWithWindow(t *testing.T) {
	cases := []struct {
		window uint64
		want   int
	}{
		{0, 256},
		{1 << 18, 256},
		{1 << 20, (1 << 20) / 1200},
		{16 << 20, (16 << 20) / 1200},
	}
	for _, c := range cases {
		t.Run(strconv.FormatUint(c.window, 10), func(t *testing.T) {
			s := &QUICStream{recvWindow: c.window}
			if got := s.oooSegmentCap(); got != c.want {
				t.Fatalf("window %d: cap %d, want %d", c.window, got, c.want)
			}
		})
	}
}
