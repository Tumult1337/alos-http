//go:build linux && amd64

package core

import (
	"bufio"
	"encoding/binary"
	"strings"
	"testing"
)

const (
	h2Fix2OversizedValueLen = 13000
	h2Fix2SaturationFlood   = h2MaxResetsPerWindow + 100
	h2Fix2DynamicIndex      = 0xbe
)

var h2Fix2PingData = [8]byte{'r', '3', 'f', 'i', 'x', '2', 'o', 'k'}

func h2Fix2AwaitShutdownGoAway(t *testing.T, br *bufio.Reader) uint32 {
	t.Helper()
	for {
		f := tlsEpollFixReadH2Frame(t, br)
		if f.typ == H2FrameGoAway {
			return binary.BigEndian.Uint32(f.payload) & 0x7fffffff
		}
	}
}

func h2Fix2AwaitStreamFrame(t *testing.T, br *bufio.Reader, stream uint32) tlsEpollFixH2Frame {
	t.Helper()
	for {
		f := tlsEpollFixReadH2Frame(t, br)
		if f.stream == stream || f.typ == H2FrameGoAway {
			return f
		}
	}
}

func h2Fix2StartShutdownWithBusyStream(t *testing.T) (*blockingHandler, *bufio.Reader, func([]byte), <-chan error) {
	t.Helper()
	h := newBlockingHandler()
	ts := newTestServer(t, testServerOptions{Routes: h.route})
	c, br := tlsEpollFixH2cConn(t, ts.addr)
	write := func(b []byte) {
		t.Helper()
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	write(tlsEpollFixH2Get(1, "/block"))
	h.awaitEntered(t)
	shutdown := tlsEpollFixShutdownAsync(ts.srv, tlsEpollFixShutdownCtx)
	if last := h2Fix2AwaitShutdownGoAway(t, br); last != 1 {
		t.Fatalf("shutdown GOAWAY last-stream %d, want 1", last)
	}
	return h, br, write, shutdown
}

func TestH2Fix2GoAwayLastStreamNeverIncreasesAfterShutdown(t *testing.T) {
	h, br, write, shutdown := h2Fix2StartShutdownWithBusyStream(t)
	write(tlsEpollFixH2Get(3, "/ok"))
	if f := h2Fix2AwaitStreamFrame(t, br, 3); f.typ != H2FrameRSTStream || binary.BigEndian.Uint32(f.payload) != H2ErrRefusedStream {
		t.Fatalf("stream 3 after the shutdown GOAWAY got frame type %d, want RST_STREAM(REFUSED_STREAM)", f.typ)
	}
	write(appendH2Frame(nil, H2FramePing, 0, 0, []byte{0, 0, 0, 0}))
	last := h2Fix2AwaitShutdownGoAway(t, br)
	close(h.release)
	if last != 1 {
		t.Fatalf("GOAWAY after the shutdown GOAWAY(last=1) carried last-stream %d: RFC 9113 6.8 forbids increasing it", last)
	}
	<-shutdown
}

func TestH2Fix2OversizedHeaderListDuringShutdownIsRefusedNotFatal(t *testing.T) {
	h, br, write, shutdown := h2Fix2StartShutdownWithBusyStream(t)
	block := append(h2FixRequestBlock("GET", "/ok"), h2FixLiteral("x-big", strings.Repeat("b", h2Fix2OversizedValueLen))...)
	write(appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, block))
	f := h2Fix2AwaitStreamFrame(t, br, 3)
	if f.typ == H2FrameGoAway {
		close(h.release)
		t.Fatalf("an oversized header list during the shutdown drain killed the connection with GOAWAY code %d", binary.BigEndian.Uint32(f.payload[4:]))
	}
	if f.typ != H2FrameRSTStream || binary.BigEndian.Uint32(f.payload) != H2ErrRefusedStream {
		close(h.release)
		t.Fatalf("oversized stream 3 during shutdown got frame type %d, want RST_STREAM(REFUSED_STREAM)", f.typ)
	}
	close(h.release)
	if f := h2Fix2AwaitStreamFrame(t, br, 1); f.typ != H2FrameHeaders {
		t.Fatalf("busy stream 1 got frame type %d instead of its response", f.typ)
	}
	if err := <-shutdown; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func (rc *h2RawConn) h2Fix2ReadTracking(ended map[uint32]bool) h2RawFrame {
	rc.t.Helper()
	f, err := rc.tryRead()
	if err != nil {
		rc.t.Fatalf("read frame: %v", err)
	}
	if f.flags&H2FlagEndStream != 0 && (f.typ == H2FrameHeaders || f.typ == H2FrameData) {
		ended[f.streamID] = true
	}
	return f
}

func (rc *h2RawConn) h2Fix2AwaitPingAck(ended map[uint32]bool) (h2RawFrame, bool) {
	rc.write(H2FramePing, 0, 0, h2Fix2PingData[:])
	for {
		f := rc.h2Fix2ReadTracking(ended)
		if f.typ == H2FrameGoAway {
			return f, false
		}
		if f.typ == H2FramePing && f.flags&H2FlagAck != 0 {
			return f, true
		}
	}
}

func TestH2Fix2TrailersCrossingRefusalAreIgnored(t *testing.T) {
	addr, p := startH2FixFlowServer(t, func(c *Config) { c.H2MaxConcurrentStreams = 2 })
	rc := h2RawDial(t, addr, nil)
	h2FixGet(rc, 1, "/slow")
	h2FixGet(rc, 3, "/slow")
	if !h2FixPollUntil(func() bool { return p.running.Load() == 2 }) {
		t.Fatal("slow handlers never started")
	}
	rc.write(H2FrameHeaders, H2FlagEndHeaders, 5, h2FixRequestBlock("POST", "/ok"))
	if f, err := rc.awaitStreamOutcome(5); err != nil || f.typ != H2FrameRSTStream || binary.BigEndian.Uint32(f.payload) != H2ErrRefusedStream {
		t.Fatalf("stream 5 on a saturated connection: frame %d err %v, want RST_STREAM(REFUSED_STREAM)", f.typ, err)
	}
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 5, h2FixIndexedLiteral("x-trailer", "crossed"))
	ended := map[uint32]bool{}
	if f, ok := rc.h2Fix2AwaitPingAck(ended); !ok {
		t.Fatalf("trailers that crossed the REFUSED_STREAM drew GOAWAY code %d; RFC 9113 5.1 requires them to be discarded", binary.BigEndian.Uint32(f.payload[4:8]))
	}
	for !ended[1] || !ended[3] {
		rc.h2Fix2ReadTracking(ended)
	}
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 7, append(h2FixRequestBlock("GET", "/ok"), h2Fix2DynamicIndex))
	if f, err := rc.awaitStreamOutcome(7); err != nil || f.typ != H2FrameHeaders {
		t.Fatalf("request referencing the entry the discarded trailers inserted: frame %d err %v (HPACK table out of sync)", f.typ, err)
	}
	rc.write(H2FrameHeaders, H2FlagEndHeaders, 5, h2FixRequestBlock("GET", "/ok"))
	code, err := rc.awaitGoAway()
	if err != nil || code != H2ErrProtocol {
		t.Fatalf("reopening refused stream 5 drew code %d err %v, want GOAWAY PROTOCOL_ERROR", code, err)
	}
}

func TestH2Fix2ClosedStreamHeadersFloodIsRateLimited(t *testing.T) {
	addr, p := startH2FixFlowServer(t, func(c *Config) { c.H2MaxConcurrentStreams = 2 })
	rc := h2RawDial(t, addr, nil)
	h2FixGet(rc, 1, "/hold")
	h2FixGet(rc, 3, "/hold")
	if !h2FixPollUntil(func() bool { return p.running.Load() == 2 }) {
		t.Fatal("hold handlers never started")
	}
	h2FixGet(rc, 5, "/ok")
	var flood []byte
	for range h2FixRefusedFloodCount {
		flood = appendH2Frame(flood, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 5, h2FixIndexedLiteral("x-trailer", "again"))
	}
	rc.writeRaw(flood)
	code, err := rc.awaitGoAway()
	if err != nil {
		t.Fatalf("%d HEADERS on closed stream 5 drew no GOAWAY: %v", h2FixRefusedFloodCount, err)
	}
	if code != H2ErrEnhanceYourCalm {
		t.Fatalf("GOAWAY code %d, want ENHANCE_YOUR_CALM for a flood of HEADERS on a closed stream", code)
	}
}

func TestH2Fix2RefusalsCausedByAbandonedHandlersDoNotKillConnection(t *testing.T) {
	addr, p := startH2FixFlowServer(t, func(c *Config) { c.H2MaxConcurrentStreams = 2 })
	rc := h2RawDial(t, addr, nil)
	h2FixGet(rc, 1, "/hold")
	h2FixGet(rc, 3, "/hold")
	if !h2FixPollUntil(func() bool { return p.running.Load() == 2 }) {
		t.Fatal("hold handlers never started")
	}
	rc.write(H2FrameRSTStream, 0, 1, rstPayload(H2ErrCancel))
	rc.write(H2FrameRSTStream, 0, 3, rstPayload(H2ErrCancel))
	var flood []byte
	for i := range h2Fix2SaturationFlood {
		flood = appendH2Frame(flood, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, uint32(5+2*i), h2FixRequestBlock("GET", "/hold"))
	}
	rc.writeRaw(flood)
	refused := 0
	rc.write(H2FramePing, 0, 0, h2Fix2PingData[:])
	for {
		f, err := rc.tryRead()
		if err != nil {
			t.Fatalf("no PING ACK after %d refusals: %v", refused, err)
		}
		if f.typ == H2FrameGoAway {
			t.Fatalf("connection killed with GOAWAY code %d after %d refusals caused only by handlers the client already reset", binary.BigEndian.Uint32(f.payload[4:8]), refused)
		}
		if f.typ == H2FrameRSTStream && binary.BigEndian.Uint32(f.payload) == H2ErrRefusedStream {
			refused++
		}
		if f.typ == H2FramePing && f.flags&H2FlagAck != 0 {
			break
		}
	}
	if n := p.running.Load(); n > 2*2 {
		t.Fatalf("%d handlers running on a connection limited to 2 streams", n)
	}
	if refused == 0 {
		t.Fatal("no stream was refused although both reset handlers were still running")
	}
}
