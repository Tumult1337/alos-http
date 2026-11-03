//go:build linux && amd64

package core

import (
	"sync/atomic"
	"testing"
	"time"
)

const (
	perfH2ParkStreams      = 100
	perfH2ParkPendingWrite = 2 << 20
	perfH2ParkReadBuffer   = 4096
	perfH2ParkWriteTimeout = time.Second
	perfH2ParkCloseCeiling = 10 * time.Second
)

func TestH2BudgetParkedResponseBytesAreCapped(t *testing.T) {
	var started atomic.Int64
	big := h2FixBody(h2FixBigBody)
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.H2MaxConcurrentStreams = perfH2ParkStreams + 1
		c.MaxPendingWriteBytes = perfH2ParkPendingWrite
		c.WriteTimeout = perfH2ParkWriteTimeout
	}, func(srv *Server) {
		srv.Router.GET("/big", func(req *Request, resp *Response) {
			started.Add(1)
			resp.Status(200).Bytes(big)
		})
	})
	rc := h2RawDialRecvBuf(t, addr, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), h2FixMaxWindow}), perfH2ParkReadBuffer)
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(h2FixMaxWindow-H2DefaultWindowSize))
	for i := range perfH2ParkStreams {
		h2FixGet(rc, uint32(2*i+1), "/big")
	}
	bound := int64(perfH2ParkPendingWrite) + int64(srv.h2MaxRunningHandlers())*h2FixBigBody
	time.Sleep(h2FixQuietWindow)
	first := h2AdmissionProbe(t, srv)
	startedFirst := started.Load()
	time.Sleep(h2FixQuietWindow)
	second := h2AdmissionProbe(t, srv)
	for _, s := range []h2AdmissionState{first, second} {
		if s.parked > bound {
			t.Fatalf("a client that stopped reading made the connection hold %d parked response bytes, bound %d", s.parked, bound)
		}
	}
	if second.parked+second.sending < perfH2ParkPendingWrite {
		t.Fatalf("parked %d plus window-blocked %d bytes is below MaxPendingWriteBytes %d: the client did not stall the connection",
			second.parked, second.sending, perfH2ParkPendingWrite)
	}
	if got := started.Load(); got != startedFirst || got >= perfH2ParkStreams {
		t.Fatalf("handlers kept starting on a stalled connection: %d then %d of %d", startedFirst, got, perfH2ParkStreams)
	}
	if second.waiting == 0 {
		t.Fatal("no stream waits for admission on a stalled connection")
	}
	waitFor(t, perfH2ParkCloseCeiling, func() bool { return h2AdmissionProbe(t, srv).conns == 0 })
}
