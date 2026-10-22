//go:build linux && amd64

package core

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

const (
	perfH2ParkStreams      = 100
	perfH2ParkPendingWrite = 2 << 20
	perfH2ParkReadBuffer   = 4096
)

func TestH2BudgetParkedResponseBytesAreCapped(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, func(c *Config) {
		c.H2MaxConcurrentStreams = perfH2ParkStreams + 1
		c.MaxPendingWriteBytes = perfH2ParkPendingWrite
	})
	rc := h2RawDial(t, addr, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), h2FixMaxWindow}))
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(h2FixMaxWindow-H2DefaultWindowSize))
	if tcp, ok := rc.conn.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(perfH2ParkReadBuffer)
	}
	for i := range perfH2ParkStreams {
		h2FixGet(rc, uint32(2*i+1), "/big")
	}
	time.Sleep(h2FixQuietWindow)
	_ = rc.conn.SetReadDeadline(wallDeadline(h2FixCeiling))
	ended := make(map[uint32]bool, perfH2ParkStreams)
	calmed, delivered := 0, 0
	for len(ended) < perfH2ParkStreams {
		f, err := rc.tryRead()
		if err != nil {
			t.Fatalf("read after %d/%d streams ended: %v", len(ended), perfH2ParkStreams, err)
		}
		switch f.typ {
		case H2FrameGoAway:
			t.Fatalf("connection closed with GOAWAY after %d/%d streams ended", len(ended), perfH2ParkStreams)
		case H2FrameRSTStream:
			ended[f.streamID] = true
			if len(f.payload) == 4 && binary.BigEndian.Uint32(f.payload) == H2ErrEnhanceYourCalm {
				calmed++
			}
		case H2FrameData:
			delivered += len(f.payload)
			if f.flags&H2FlagEndStream != 0 {
				ended[f.streamID] = true
			}
		case H2FrameHeaders:
			if f.flags&H2FlagEndStream != 0 {
				ended[f.streamID] = true
			}
		}
	}
	if calmed == 0 {
		t.Fatalf("a client that stopped reading kept all %d responses (%d bytes) parked on one connection with MaxPendingWriteBytes %d",
			perfH2ParkStreams, delivered, perfH2ParkPendingWrite)
	}
}
