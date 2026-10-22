//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

func TestH2DirectSendKeepsOnlyThePartialFrameAndRollsBackTheRest(t *testing.T) {
	hdr1 := appendH2FrameHeader(nil, H2FrameData, 0, 1, 100)
	hdr2 := appendH2FrameHeader(nil, H2FrameData, H2FlagEndStream, 1, 50)
	data1 := bytes.Repeat([]byte{'a'}, 100)
	data2 := bytes.Repeat([]byte{'b'}, 50)
	frame1 := append(append([]byte{}, hdr1...), data1...)
	frame2 := append(append([]byte{}, hdr2...), data2...)
	cases := []struct {
		sent       int
		wantBuf    []byte
		wantUnsent int
	}{
		{0, frame1, 50},
		{5, frame1[5:], 50},
		{9, data1, 50},
		{49, data1[40:], 50},
		{len(frame1), frame2, 0},
		{len(frame1) + 3, frame2[3:], 0},
		{len(frame1) + len(frame2), nil, 0},
	}
	for _, tc := range cases {
		c := &epollConn{}
		stream := &H2Stream{respOff: 150}
		segs := [][]byte{nil, hdr1, data1, hdr2, data2}
		from := c.h2KeepPartialFrame(segs, tc.sent)
		c.h2UnconsumeFrames(stream, segs[from:])
		if !bytes.Equal(c.writeBuf, tc.wantBuf) {
			t.Fatalf("sent %d: kept %d bytes, want %d", tc.sent, len(c.writeBuf), len(tc.wantBuf))
		}
		if stream.respOff != 150-tc.wantUnsent || c.h2.connWindow != int64(tc.wantUnsent) || stream.Window.Load() != int64(tc.wantUnsent) {
			t.Fatalf("sent %d: respOff %d connWindow %d window %d, want %d unsent bytes rolled back",
				tc.sent, stream.respOff, c.h2.connWindow, stream.Window.Load(), tc.wantUnsent)
		}
	}
}
