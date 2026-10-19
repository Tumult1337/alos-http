//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	h2FixHandlerDelay      = 150 * time.Millisecond
	h2FixQuietWindow       = 150 * time.Millisecond
	h2FixPollInterval      = 15 * time.Millisecond
	h2FixBigBody           = 200000
	h2FixMidBody           = 32768
	h2FixHugeBody          = 16 << 20
	h2FixMaxWindow         = 1<<31 - 1
	h2FixStreamLimit       = 4
	h2FixOverflowRounds    = 12
	h2FixRefusedFloodCount = h2MaxResetsPerWindow + 100
	h2FixHandlerCeiling    = 2 * h2FixCeiling
)

var h2FixHugePayload = sync.OnceValue(func() []byte { return h2FixBody(h2FixHugeBody) })

type h2FixProbe struct {
	running atomic.Int64
	done    chan uint32
	release chan struct{}
}

func newH2FixProbe() *h2FixProbe {
	return &h2FixProbe{done: make(chan uint32, 64), release: make(chan struct{})}
}

func h2FixBody(size int) []byte {
	return bytes.Repeat([]byte{'b'}, size)
}

func (p *h2FixProbe) routes(srv *Server) {
	big := h2FixBody(h2FixBigBody)
	mid := h2FixBody(h2FixMidBody)
	srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	srv.Router.GET("/big", func(req *Request, resp *Response) { resp.Status(200).Bytes(big) })
	srv.Router.GET("/mid", func(req *Request, resp *Response) { resp.Status(200).Bytes(mid) })
	srv.Router.GET("/huge", func(req *Request, resp *Response) { resp.Status(200).Bytes(h2FixHugePayload()) })
	srv.Router.GET("/slowbig", func(req *Request, resp *Response) {
		time.Sleep(h2FixHandlerDelay)
		resp.Status(200).Bytes(big)
	})
	srv.Router.GET("/slow", func(req *Request, resp *Response) {
		p.running.Add(1)
		time.Sleep(h2FixHandlerDelay)
		resp.Status(200).String("late-body")
		p.running.Add(-1)
		p.done <- req.StreamID
	})
	srv.Router.GET("/hold", func(req *Request, resp *Response) {
		p.running.Add(1)
		select {
		case <-p.release:
		case <-turbo.After(h2FixHandlerCeiling):
		}
		resp.Status(200).String("held")
		p.running.Add(-1)
	})
	srv.Router.GET("/stubborn", func(req *Request, resp *Response) {
		p.running.Add(1)
		defer p.running.Add(-1)
		sw := resp.EnsureStreamWriter()
		if sw == nil {
			resp.Status(500).String("no stream writer")
			return
		}
		resp.SetStreamer(sw)
		if err := sw.WriteHeader(200, nil, "text/event-stream"); err != nil {
			return
		}
		select {
		case <-p.release:
		case <-turbo.After(h2FixHandlerCeiling):
		}
	})
	srv.Router.GET("/sse", func(req *Request, resp *Response) {
		p.running.Add(1)
		defer p.running.Add(-1)
		sw := resp.EnsureStreamWriter()
		if sw == nil {
			resp.Status(500).String("no stream writer")
			return
		}
		resp.SetStreamer(sw)
		if err := sw.WriteHeader(200, nil, "text/event-stream"); err != nil {
			return
		}
		select {
		case <-req.Context().Done():
		case <-p.release:
		case <-turbo.After(h2FixHandlerCeiling):
		}
	})
}

func startH2FixFlowServer(t *testing.T, tune func(*Config)) (string, *h2FixProbe) {
	t.Helper()
	p := newH2FixProbe()
	addr := startH2FixServer(t, tune, p.routes)
	t.Cleanup(func() { close(p.release) })
	return addr, p
}

func h2FixGet(rc *h2RawConn, streamID uint32, path string) {
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, streamID, h2FixRequestBlock("GET", path))
}

func (rc *h2RawConn) readStreamBody(streamID uint32) (int, bool, error) {
	total := 0
	for {
		f, err := rc.tryRead()
		if err != nil {
			return total, false, err
		}
		if f.typ == H2FrameGoAway {
			return total, false, nil
		}
		if f.streamID != streamID {
			continue
		}
		switch f.typ {
		case H2FrameRSTStream:
			return total, false, nil
		case H2FrameHeaders:
			if f.flags&H2FlagEndStream != 0 {
				return total, true, nil
			}
		case H2FrameData:
			total += len(f.payload)
			if f.flags&H2FlagEndStream != 0 {
				return total, true, nil
			}
		}
	}
}

func (rc *h2RawConn) framesWithin(window time.Duration) []h2RawFrame {
	_ = rc.conn.SetReadDeadline(wallDeadline(window))
	var frames []h2RawFrame
	for {
		f, err := rc.tryRead()
		if err != nil {
			_ = rc.conn.SetReadDeadline(wallDeadline(h2FixCeiling))
			return frames
		}
		frames = append(frames, f)
	}
}

func (rc *h2RawConn) awaitHeaders(streamID uint32) {
	rc.t.Helper()
	for {
		f := rc.read()
		if f.streamID == streamID && f.typ == H2FrameHeaders {
			return
		}
		if f.typ == H2FrameGoAway || (f.streamID == streamID && f.typ == H2FrameRSTStream) {
			rc.t.Fatalf("stream %d ended with frame type %d before HEADERS", streamID, f.typ)
		}
	}
}

func h2FixPollUntil(cond func() bool) bool {
	deadline := turbo.Deadline(h2FixCeiling)
	for turbo.Until(deadline) > 0 {
		if cond() {
			return true
		}
		time.Sleep(h2FixPollInterval)
	}
	return cond()
}

func rstPayload(code uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, code)
}

func TestH2FixWindowOverflowOnStreamedResponseCancelsHandler(t *testing.T) {
	addr, p := startH2FixFlowServer(t, func(c *Config) { c.H2MaxConcurrentStreams = h2FixStreamLimit })
	rc := h2RawDial(t, addr, nil)
	for i := range h2FixOverflowRounds {
		id := uint32(2*i + 1)
		h2FixGet(rc, id, "/sse")
		f, err := rc.awaitStreamOutcome(id)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if f.typ != H2FrameHeaders {
			break
		}
		rc.write(H2FrameWindowUpdate, 0, id, h2FixWindowIncrement(h2FixMaxWindow))
	}
	if !h2FixPollUntil(func() bool { return p.running.Load() == 0 }) {
		t.Fatalf("%d streamed handlers still running after their streams were reset for window overflow (limit %d)", p.running.Load(), h2FixStreamLimit)
	}
}

func TestH2FixResetStreamedHandlersIgnoringContextAreBounded(t *testing.T) {
	addr, p := startH2FixFlowServer(t, func(c *Config) { c.H2MaxConcurrentStreams = h2FixStreamLimit })
	rc := h2RawDial(t, addr, nil)
	refused := 0
	for i := range h2FixOverflowRounds {
		id := uint32(2*i + 1)
		h2FixGet(rc, id, "/stubborn")
		f, err := rc.awaitStreamOutcome(id)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if f.typ != H2FrameHeaders {
			refused++
			continue
		}
		rc.write(H2FrameWindowUpdate, 0, id, h2FixWindowIncrement(h2FixMaxWindow))
	}
	if n := p.running.Load(); n > 2*h2FixStreamLimit {
		t.Fatalf("%d handlers that ignore their context are running on one connection (limit %d, refused %d)", n, h2FixStreamLimit, refused)
	}
	if refused == 0 {
		t.Fatal("no stream was refused although every reset handler kept running")
	}
}

func TestH2FixWindowUpdateOnBusyStreamIsApplied(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, nil)
	rc := h2RawDial(t, addr, nil)
	h2FixGet(rc, 1, "/slowbig")
	rc.write(H2FrameWindowUpdate, 0, 1, h2FixWindowIncrement(1<<20))
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(1<<20))
	got, ended, err := rc.readStreamBody(1)
	if err != nil || !ended || got != h2FixBigBody {
		t.Fatalf("received %d/%d DATA bytes (ended=%v err=%v): WINDOW_UPDATE sent while the handler ran was dropped", got, h2FixBigBody, ended, err)
	}
}

func TestH2FixLargeResponseWithHugeWindowCompletes(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, nil)
	rc := h2RawDial(t, addr, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), h2FixMaxWindow}))
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(h2FixMaxWindow-H2DefaultWindowSize))
	h2FixGet(rc, 1, "/huge")
	got, ended, err := rc.readStreamBody(1)
	if err != nil || !ended || got != h2FixHugeBody {
		t.Fatalf("received %d/%d DATA bytes (ended=%v err=%v)", got, h2FixHugeBody, ended, err)
	}
}

func TestH2FixLargeResponseWithHugeWindowCompletesOverTLS(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, func(c *Config) {
		c.PlainHTTP = false
		c.Certs = []CertConfig{{Domain: h2FixAuthority, Source: CertSelfSigned}}
	})
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: h2FixCeiling}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: h2FixAuthority, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	rc, _ := h2HandshakeCaptureSettings(t, conn)
	rc.write(H2FrameSettings, 0, 0, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), h2FixMaxWindow}))
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(h2FixMaxWindow-H2DefaultWindowSize))
	h2FixGet(rc, 1, "/huge")
	got, ended, err := rc.readStreamBody(1)
	if err != nil || !ended || got != h2FixHugeBody {
		t.Fatalf("received %d/%d DATA bytes over TLS (ended=%v err=%v)", got, h2FixHugeBody, ended, err)
	}
}

func TestH2FixClientResetOfBusyStreamSuppressesResponse(t *testing.T) {
	addr, p := startH2FixFlowServer(t, nil)
	rc := h2RawDial(t, addr, nil)
	h2FixGet(rc, 1, "/slow")
	rc.write(H2FrameRSTStream, 0, 1, rstPayload(H2ErrCancel))
	select {
	case <-p.done:
	case <-turbo.After(h2FixCeiling):
		t.Fatal("handler never finished")
	}
	for _, f := range rc.framesWithin(h2FixQuietWindow) {
		if f.streamID == 1 && (f.typ == H2FrameHeaders || f.typ == H2FrameData) {
			t.Fatalf("server sent frame type %d on stream 1 after the client reset it", f.typ)
		}
	}
	h2FixGet(rc, 3, "/ok")
	if f, err := rc.awaitStreamOutcome(3); err != nil || f.typ != H2FrameHeaders {
		t.Fatalf("follow-up request failed: frame %d err %v", f.typ, err)
	}
}

func TestH2FixClientResetOfStalledStreamReleasesIt(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, func(c *Config) { c.H2MaxConcurrentStreams = 1 })
	rc := h2RawDial(t, addr, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 1 << 20}))
	h2FixGet(rc, 3, "/big")
	got := 0
	for got < H2DefaultWindowSize {
		f := rc.read()
		if f.streamID == 3 && f.typ == H2FrameData {
			got += len(f.payload)
		}
	}
	rc.write(H2FrameRSTStream, 0, 3, rstPayload(H2ErrCancel))
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(1<<20))
	late := 0
	for _, f := range rc.framesWithin(h2FixQuietWindow) {
		if f.streamID == 3 && f.typ == H2FrameData {
			late += len(f.payload)
		}
	}
	if late > 0 {
		t.Fatalf("%d DATA bytes on stream 3 sent after the client reset it", late)
	}
	h2FixGet(rc, 5, "/ok")
	if f, err := rc.awaitStreamOutcome(5); err != nil || f.typ != H2FrameHeaders {
		t.Fatalf("next stream after resetting the stalled one got frame type %d (err %v): the reset stream still holds its concurrency slot", f.typ, err)
	}
}

func TestH2FixRefusedStreamIDIsRetired(t *testing.T) {
	addr, p := startH2FixFlowServer(t, func(c *Config) { c.H2MaxConcurrentStreams = 2 })
	rc := h2RawDial(t, addr, nil)
	h2FixGet(rc, 1, "/hold")
	h2FixGet(rc, 3, "/hold")
	if !h2FixPollUntil(func() bool { return p.running.Load() == 2 }) {
		t.Fatal("hold handlers never started")
	}
	var flood []byte
	for range h2FixRefusedFloodCount {
		flood = appendH2Frame(flood, H2FrameHeaders, H2FlagEndHeaders, 5, h2FixRequestBlock("GET", "/ok"))
	}
	rc.writeRaw(flood)
	refused := 0
	for {
		f, err := rc.tryRead()
		if err != nil {
			t.Fatalf("no GOAWAY after %d HEADERS reusing a refused stream id (%d refused): %v", h2FixRefusedFloodCount, refused, err)
		}
		if f.typ == H2FrameRSTStream && f.streamID == 5 {
			refused++
		}
		if f.typ == H2FrameGoAway {
			if code := binary.BigEndian.Uint32(f.payload[4:8]); code != H2ErrProtocol {
				t.Fatalf("GOAWAY code %d, want PROTOCOL_ERROR for a reused stream id", code)
			}
			if refused != 1 {
				t.Fatalf("stream id 5 was refused %d times, want once", refused)
			}
			return
		}
	}
}

func TestH2FixRefusedStreamsAreRateLimited(t *testing.T) {
	addr, p := startH2FixFlowServer(t, func(c *Config) { c.H2MaxConcurrentStreams = 2 })
	rc := h2RawDial(t, addr, nil)
	h2FixGet(rc, 1, "/hold")
	h2FixGet(rc, 3, "/hold")
	if !h2FixPollUntil(func() bool { return p.running.Load() == 2 }) {
		t.Fatal("hold handlers never started")
	}
	var flood []byte
	for i := range h2FixRefusedFloodCount {
		flood = appendH2Frame(flood, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, uint32(5+2*i), h2FixRequestBlock("GET", "/ok"))
	}
	rc.writeRaw(flood)
	code, err := rc.awaitGoAway()
	if err != nil {
		t.Fatalf("%d refused streams drew no GOAWAY: %v", h2FixRefusedFloodCount, err)
	}
	if code != H2ErrEnhanceYourCalm {
		t.Fatalf("GOAWAY code %d, want ENHANCE_YOUR_CALM", code)
	}
}

func TestH2FixInitialWindowIncreaseResumesStalledResponse(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, nil)
	rc := h2RawDial(t, addr, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0}))
	h2FixGet(rc, 1, "/mid")
	rc.awaitHeaders(1)
	rc.write(H2FrameSettings, 0, 0, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), H2DefaultWindowSize}))
	got, ended, err := rc.readStreamBody(1)
	if err != nil || !ended || got != h2FixMidBody {
		t.Fatalf("received %d/%d DATA bytes (ended=%v err=%v) after SETTINGS_INITIAL_WINDOW_SIZE was raised", got, h2FixMidBody, ended, err)
	}
}

func TestH2FixInitialWindowDecreaseAppliesToStalledResponse(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, nil)
	rc := h2RawDial(t, addr, nil)
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(1<<20))
	h2FixGet(rc, 1, "/big")
	got := 0
	for got < H2DefaultWindowSize {
		f := rc.read()
		if f.streamID == 1 && f.typ == H2FrameData {
			got += len(f.payload)
		}
	}
	rc.write(H2FrameSettings, 0, 0, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0}))
	rc.write(H2FrameWindowUpdate, 0, 1, h2FixWindowIncrement(H2DefaultWindowSize))
	over := 0
	for _, f := range rc.framesWithin(h2FixQuietWindow) {
		if f.streamID == 1 && f.typ == H2FrameData {
			over += len(f.payload)
		}
	}
	if over > 0 {
		t.Fatalf("server sent %d DATA bytes beyond the peer's reduced stream window", over)
	}
}

func TestH2FixHeadersBadPaddingIsConnectionError(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, nil)
	rc := h2RawDial(t, addr, nil)
	block := h2FixRequestBlock("GET", "/ok")
	padded := append([]byte{byte(len(block) + 10)}, block...)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream|H2FlagPadded, 1, padded)
	_ = rc.conn.SetReadDeadline(wallDeadline(h2FixCeiling))
	code, err := rc.awaitGoAway()
	if err != nil {
		t.Fatalf("HEADERS with padding longer than the frame drew no GOAWAY: %v", err)
	}
	if code != H2ErrProtocol {
		t.Fatalf("GOAWAY code %d, want PROTOCOL_ERROR", code)
	}
}

func TestH2FixHeadersShortPriorityIsConnectionError(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, nil)
	rc := h2RawDial(t, addr, nil)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream|H2FlagPriority, 1, []byte{0, 0, 0})
	_ = rc.conn.SetReadDeadline(wallDeadline(h2FixCeiling))
	code, err := rc.awaitGoAway()
	if err != nil {
		t.Fatalf("HEADERS with a truncated priority block drew no GOAWAY: %v", err)
	}
	if code != H2ErrFrameSize {
		t.Fatalf("GOAWAY code %d, want FRAME_SIZE_ERROR", code)
	}
}

func TestH2FixClientGoAwayLetsInFlightResponseFinish(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, nil)
	rc := h2RawDial(t, addr, nil)
	h2FixGet(rc, 1, "/slowbig")
	goAway := make([]byte, 8)
	binary.BigEndian.PutUint32(goAway, 0)
	rc.write(H2FrameGoAway, 0, 0, goAway)
	rc.write(H2FrameWindowUpdate, 0, 1, h2FixWindowIncrement(1<<20))
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(1<<20))
	got, ended, err := rc.readStreamBody(1)
	if err != nil || !ended || got != h2FixBigBody {
		t.Fatalf("after client GOAWAY(NO_ERROR) received %d/%d bytes (ended=%v err=%v)", got, h2FixBigBody, ended, err)
	}
	_ = rc.conn.SetReadDeadline(wallDeadline(h2FixCeiling))
	for {
		if _, err := rc.tryRead(); err != nil {
			if !h2FixConnClosed(err) {
				t.Fatalf("connection still open after the in-flight response drained: %v", err)
			}
			return
		}
	}
}

func TestH2FixMalformedClientGoAwayIsAnswered(t *testing.T) {
	cases := []struct {
		name     string
		streamID uint32
		payload  []byte
		want     uint32
	}{
		{"short", 0, []byte{0, 0, 0, 0}, H2ErrFrameSize},
		{"stream", 1, make([]byte, 8), H2ErrProtocol},
	}
	addr, _ := startH2FixFlowServer(t, nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := h2RawDial(t, addr, nil)
			rc.write(H2FrameGoAway, 0, tc.streamID, tc.payload)
			_ = rc.conn.SetReadDeadline(wallDeadline(h2FixCeiling))
			code, err := rc.awaitGoAway()
			if err != nil {
				t.Fatalf("malformed GOAWAY drew no GOAWAY reply: %v", err)
			}
			if code != tc.want {
				t.Fatalf("GOAWAY code %d, want %d", code, tc.want)
			}
		})
	}
}

func TestH2FixAbsoluteFormPathIsStreamError(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, nil)
	rc := h2RawDial(t, addr, nil)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "http://admin.internal/admin/secret"))
	f, err := rc.awaitStreamOutcome(1)
	if err != nil {
		t.Fatalf("await: %v", err)
	}
	if f.typ != H2FrameRSTStream || binary.BigEndian.Uint32(f.payload) != H2ErrProtocol {
		t.Fatalf("absolute-form :path answered with frame type %d, want RST_STREAM(PROTOCOL_ERROR)", f.typ)
	}
	h2FixGet(rc, 3, "/ok")
	if f, err := rc.awaitStreamOutcome(3); err != nil || f.typ != H2FrameHeaders {
		t.Fatalf("follow-up request: frame %d err %v", f.typ, err)
	}
}

func TestH2FixOversizedHeaderListIsRefusedAndTableStaysInSync(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, nil)
	rc := h2RawDial(t, addr, nil)
	seed := append(h2FixRequestBlock("GET", "/ok"), h2FixIndexedLiteral("x-a", strings.Repeat("v", 4000))...)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, seed)
	if f, err := rc.awaitStreamOutcome(1); err != nil || f.typ != H2FrameHeaders {
		t.Fatalf("seed request: frame %d err %v", f.typ, err)
	}
	amplified := append(h2FixRequestBlock("GET", "/ok"), bytes.Repeat([]byte{0xbe}, 120)...)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, amplified)
	if got := rc.h2Fix2Status(3); got != h2Fix2StatusTooLarge {
		t.Fatalf("header list of ~480 KB answered with %s, want :status 431", got)
	}
	follow := append(h2FixRequestBlock("GET", "/ok"), 0xbe)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 5, follow)
	if f, err := rc.awaitStreamOutcome(5); err != nil || f.typ != H2FrameHeaders {
		t.Fatalf("request after the refused one: frame %d err %v", f.typ, err)
	}
}
