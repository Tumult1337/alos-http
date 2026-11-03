//go:build linux && amd64

package core

import (
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	h2TunnelReadTimeout = 300 * time.Millisecond
	h2TunnelIdle        = 3*time.Duration(epollSweepIntervalMs)*time.Millisecond + 500*time.Millisecond
)

func TestH2IdleWebSocketTunnelOutlivesReadTimeout(t *testing.T) {
	s := startH2WSServer(t, func(cfg *Config) {
		cfg.ReadTimeout = h2TunnelReadTimeout
		cfg.WSReadTimeout = 20 * time.Second
	})
	rc, _ := h2DialCaptureSettings(t, s.ts.addr)
	_ = rc.conn.SetDeadline(time.Now().Add(h2TunnelIdle + 5*time.Second))
	ws, hdrs := openH2WebSocket(t, rc, 1, "/ws", [2]string{"sec-websocket-protocol", "chat"})
	if hdrs[":status"] != "200" {
		t.Fatalf("headers %v", hdrs)
	}
	ws.send(wsClientFrame(0x80|wsOpText, []byte("a")))
	if f, err := ws.next(); err != nil || string(f.payload) != "chat>a" {
		t.Fatalf("first echo %+v err %v", f, err)
	}
	time.Sleep(h2TunnelIdle)
	ws.send(wsClientFrame(0x80|wsOpText, []byte("b")))
	if f, err := ws.next(); err != nil || string(f.payload) != "chat>b" {
		t.Fatalf("idle tunnel did not survive %v with ReadTimeout %v: %+v err %v", h2TunnelIdle, h2TunnelReadTimeout, f, err)
	}
}

func TestH2PeerEOFAbortsStreamedBodyReader(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
	p.w.streamBodyAbove = 1
	entered := make(chan struct{})
	readErr := make(chan error, 1)
	p.w.server.Router.POST("/up", func(r *Request, resp *Response) {
		close(entered)
		_, err := io.ReadAll(r.BodyStream())
		readErr <- err
		resp.Status(200).String("ok")
	})
	p.w.server.Router.Build()
	p.w.server.computeFastDispatch()
	p.cleanupHandlers()
	p.open(nil, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up")))
	select {
	case <-entered:
	case <-time.After(h2FixCeiling):
		t.Fatal("streaming handler did not start")
	}
	if err := unix.Shutdown(p.peer, unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	p.w.readable(p.c, false)
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("handler read returned no error after the peer closed its side")
		}
	case <-time.After(h2FixCeiling):
		t.Fatal("handler stayed blocked on the body after the peer closed its side")
	}
}

func TestH2PeerEOFDropsWindowStalledResponse(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
	p.w.writeTO = int64(time.Hour)
	big := make([]byte, 1<<20)
	p.w.server.Router.GET("/big", func(_ *Request, r *Response) { r.Status(200).Bytes(big) })
	p.w.server.Router.Build()
	p.w.server.computeFastDispatch()
	settings := h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0})
	p.open(settings, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/big")))
	p.settleHandlers()
	if len(p.c.h2.sending) != 1 {
		t.Fatalf("response is not parked on the peer window: sending=%d", len(p.c.h2.sending))
	}
	if err := unix.Shutdown(p.peer, unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	p.w.readable(p.c, false)
	deadline := turbo.Deadline(h2FixCeiling)
	for p.c.fd >= 0 && turbo.Until(deadline) > 0 {
		p.w.flushPending()
		time.Sleep(time.Millisecond)
	}
	if p.c.fd >= 0 {
		t.Fatal("a response that waits for a WINDOW_UPDATE kept the connection open after peer EOF")
	}
}

const (
	h2EOFReadCap  = 40 << 10
	h2EOFStreams  = 6
	h2EOFBodySize = 15000
)

func TestH2PeerFINWithUnreadInputKeepsCompleteUploads(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
	p.w.server.config.MaxReadSize = h2EOFReadCap
	var ran atomic.Int64
	p.w.server.Router.POST("/up", func(r *Request, resp *Response) {
		ran.Add(1)
		resp.Status(200).String("ok")
	})
	p.w.server.Router.Build()
	p.w.server.computeFastDispatch()
	p.cleanupHandlers()
	req := append([]byte(nil), H2ClientPreface[:]...)
	req = appendH2Frame(req, H2FrameSettings, 0, 0, nil)
	for i := range h2EOFStreams {
		id := uint32(2*i + 1)
		req = appendH2Frame(req, H2FrameHeaders, H2FlagEndHeaders, id, h2FixRequestBlock("POST", "/up"))
		req = appendH2Frame(req, H2FrameData, H2FlagEndStream, id, make([]byte, h2EOFBodySize))
	}
	if len(req) <= h2EOFReadCap {
		t.Fatalf("fixture of %d bytes fits in one read of %d bytes", len(req), h2EOFReadCap)
	}
	if _, err := unix.Write(p.peer, req); err != nil {
		t.Fatal(err)
	}
	if err := unix.Shutdown(p.peer, unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	p.w.readable(p.c, true)
	deadline := turbo.Deadline(h2FixCeiling)
	for ran.Load() < h2EOFStreams && turbo.Until(deadline) > 0 {
		if p.w.taskPending.Load() {
			p.w.drainTasks()
		}
		p.w.flushPending()
		time.Sleep(time.Millisecond)
	}
	if got := ran.Load(); got != h2EOFStreams {
		t.Fatalf("%d of %d complete uploads ran after a FIN that arrived with unread input", got, h2EOFStreams)
	}
}

func TestH2PeerEOFReleasesWaitingBodyAndKeepsInFlightResponse(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
	entered, release := make(chan struct{}), make(chan struct{})
	p.w.server.Router.GET("/held", func(_ *Request, resp *Response) {
		close(entered)
		<-release
		resp.Status(200).String("held")
	})
	h2ProgressUploadRoutes(p.w)
	p.cleanupHandlers()
	frames := appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/held"))
	frames = appendH2Frame(frames, H2FrameHeaders, H2FlagEndHeaders, 3, h2FixRequestBlock("POST", "/up"))
	frames = appendH2Frame(frames, H2FrameData, 0, 3, []byte("partial"))
	p.open(nil, frames)
	select {
	case <-entered:
	case <-time.After(h2FixCeiling):
		t.Fatal("held handler did not start")
	}
	if len(p.c.h2.streams) != 1 {
		t.Fatalf("fixture: %d streams wait for body, want 1", len(p.c.h2.streams))
	}
	if err := unix.Shutdown(p.peer, unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	p.w.readable(p.c, false)
	if len(p.c.h2.streams) != 0 {
		t.Fatalf("%d streams still wait for body after peer EOF", len(p.c.h2.streams))
	}
	close(release)
	p.settleHandlers()
	if !p.ended[1] {
		t.Fatal("the in-flight response was not sent after peer EOF")
	}
}

func TestH2TrailersAfterServerResetDoNotKillConnection(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(h2ProgressTimeout)
	p.w.streamBodyAbove = 1
	release := make(chan struct{})
	p.w.server.Router.POST("/up", func(r *Request, resp *Response) {
		_, _ = io.ReadAll(r.BodyStream())
		<-release
		resp.Status(200).String("ok")
	})
	h2ProgressUploadRoutes(p.w)
	t.Cleanup(func() { close(release) })
	p.cleanupHandlers()
	p.open(nil, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up")))
	time.Sleep(h2ProgressTimeout + h2ProgressTimeout/4)
	p.sweep()
	if _, ok := p.resets[1]; !ok {
		t.Fatal("fixture: the stalled stream was not reset")
	}
	trailers := hpackBlock([2]string{"x-checksum", "abc"})
	p.send(appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, trailers))
	p.send(appendH2Frame(nil, H2FrameData, H2FlagEndStream, 1, []byte("late")))
	p.send(appendH2Frame(nil, H2FrameWindowUpdate, 0, 1, h2FixWindowIncrement(1024)))
	p.send(appendH2Frame(nil, H2FramePriority, 0, 1, []byte{0, 0, 0, 0, 16}))
	if p.c.fd < 0 {
		t.Fatal("frames the peer sent before it saw RST_STREAM closed the connection")
	}
	p.send(appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, h2FixRequestBlock("GET", "/held-none")))
	p.settleHandlers()
	if p.c.fd < 0 || !p.ended[3] {
		t.Fatalf("connection unusable after a late trailer: closed=%v stream3 ended=%v", p.c.fd < 0, p.ended[3])
	}
}

func TestH2PeerEOFMidFrameAbortsStreamedBodyReader(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
	p.w.streamBodyAbove = 1
	entered := make(chan struct{})
	readErr := make(chan error, 1)
	p.w.server.Router.POST("/up", func(r *Request, resp *Response) {
		close(entered)
		_, err := io.ReadAll(r.BodyStream())
		readErr <- err
		resp.Status(200).String("ok")
	})
	p.w.server.Router.Build()
	p.w.server.computeFastDispatch()
	p.cleanupHandlers()
	p.open(nil, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up")))
	select {
	case <-entered:
	case <-time.After(h2FixCeiling):
		t.Fatal("streaming handler did not start")
	}
	partial := appendH2Frame(nil, H2FrameData, 0, 1, make([]byte, 64))[:20]
	if _, err := unix.Write(p.peer, partial); err != nil {
		t.Fatal(err)
	}
	if err := unix.Shutdown(p.peer, unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	p.w.readable(p.c, true)
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("handler read returned no error after the peer closed mid-frame")
		}
	case <-time.After(h2FixCeiling):
		t.Fatal("a FIN inside a frame left the handler blocked on the body")
	}
}

func TestH2PeerEOFDropsWindowStalledStreamedResponse(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
	p.w.writeTO = int64(time.Hour)
	h2ProgressStreamedRoute(p, 100<<10)
	settings := h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0})
	p.open(settings, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/streamed")))
	p.settleHandlers()
	if len(p.c.h2Streaming) != 1 {
		t.Fatalf("streamed response is not waiting on the peer window: streaming=%d", len(p.c.h2Streaming))
	}
	if err := unix.Shutdown(p.peer, unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	p.w.readable(p.c, false)
	deadline := turbo.Deadline(h2FixCeiling)
	for p.c.fd >= 0 && turbo.Until(deadline) > 0 {
		p.w.flushPending()
		time.Sleep(time.Millisecond)
	}
	if p.c.fd >= 0 {
		t.Fatal("a streamed response that waits for a WINDOW_UPDATE kept the connection open after peer EOF")
	}
}
