//go:build linux && amd64

package core

import (
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	h2ProgressTimeout    = 200 * time.Millisecond
	h2ProgressTick       = 60 * time.Millisecond
	h2ProgressRounds     = 10
	h2ProgressBodyPart   = 16000
	h2ProgressBodyFrames = 4
	h2ProgressPingBurst  = epollReadBufCap/(2*(h2FrameHeaderLen+8)) + 10
	h2ProgressWindow     = 1024
)

type h2Progress struct {
	t      *testing.T
	w      *epollWorker
	c      *epollConn
	peer   int
	buf    []byte
	resets map[uint32]uint32
	ended  map[uint32]bool
}

func newH2Progress(t *testing.T) *h2Progress {
	t.Helper()
	w, c, peer := h2DeadlineFixture(t)
	return &h2Progress{t: t, w: w, c: c, peer: peer, resets: map[uint32]uint32{}, ended: map[uint32]bool{}}
}

func (p *h2Progress) drain() {
	chunk := make([]byte, 1<<16)
	for {
		n, err := unix.Read(p.peer, chunk)
		if n <= 0 || err != nil {
			break
		}
		p.buf = append(p.buf, chunk[:n]...)
	}
	for len(p.buf) >= 9 {
		size := int(p.buf[0])<<16 | int(p.buf[1])<<8 | int(p.buf[2])
		if len(p.buf) < 9+size {
			return
		}
		typ, flags := p.buf[3], p.buf[4]
		id := binary.BigEndian.Uint32(p.buf[5:9]) & 0x7fffffff
		payload := p.buf[9 : 9+size]
		switch {
		case typ == H2FrameRSTStream && size == 4:
			p.resets[id] = binary.BigEndian.Uint32(payload)
		case (typ == H2FrameData || typ == H2FrameHeaders) && flags&H2FlagEndStream != 0:
			p.ended[id] = true
		}
		p.buf = p.buf[9+size:]
	}
}

func (p *h2Progress) send(frames []byte) {
	p.t.Helper()
	if _, err := unix.Write(p.peer, frames); err != nil {
		p.t.Fatal(err)
	}
	p.w.readable(p.c, false)
	p.w.flushPending()
	p.drain()
}

func (p *h2Progress) sweep() {
	p.w.lastSweep = 0
	p.w.sweepDeadlines()
	p.w.flushPending()
	p.drain()
}

func (p *h2Progress) open(settings []byte, frames []byte) {
	p.t.Helper()
	req := append([]byte(nil), H2ClientPreface[:]...)
	req = appendH2Frame(req, H2FrameSettings, 0, 0, settings)
	p.send(append(req, frames...))
}

func (p *h2Progress) run(frame func() []byte) time.Duration {
	p.t.Helper()
	start := time.Now()
	for range h2ProgressRounds {
		time.Sleep(h2ProgressTick)
		if p.c.fd < 0 {
			return time.Since(start)
		}
		p.send(frame())
		p.sweep()
	}
	return time.Since(start)
}

func (p *h2Progress) settleHandlers() {
	deadline := turbo.Deadline(h2FixCeiling)
	for p.c.inFlight > 0 && turbo.Until(deadline) > 0 {
		if p.w.taskPending.Load() {
			p.w.drainTasks()
		}
		time.Sleep(time.Millisecond)
	}
	p.w.flushPending()
	p.drain()
}

func (p *h2Progress) wantReset(streamID uint32) {
	p.t.Helper()
	code, ok := p.resets[streamID]
	if !ok || code != H2ErrCancel {
		p.t.Fatalf("stream %d: RST_STREAM sent=%v code=%d, want CANCEL", streamID, ok, code)
	}
	if p.c.fd < 0 {
		p.t.Fatal("the stalled stream closed the whole connection")
	}
}

func h2ProgressPing() []byte {
	var burst []byte
	for range h2ProgressPingBurst {
		burst = appendH2Frame(burst, H2FramePing, 0, 0, make([]byte, 8))
	}
	return burst
}

func h2ProgressUploadRoutes(w *epollWorker) {
	w.server.Router.POST("/up", func(r *Request, resp *Response) {
		body := r.Body
		if s := r.BodyStream(); s != nil {
			body, _ = io.ReadAll(s)
		}
		resp.Status(200).String(string(rune('0' + len(body)%10)))
	})
	w.server.Router.Build()
	w.server.computeFastDispatch()
}

func (p *h2Progress) cleanupHandlers() {
	p.t.Cleanup(func() {
		if p.c.fd >= 0 {
			p.w.closeConn(p.c)
		}
		for p.c.inFlight > 0 {
			h2DeadlineTask(p.t, p.w)
		}
	})
}

func TestH2PingsDoNotKeepPartialBodyAlive(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(h2ProgressTimeout)
	h2ProgressUploadRoutes(p.w)
	frames := appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up"))
	for range h2ProgressBodyFrames {
		frames = appendH2Frame(frames, H2FrameData, 0, 1, make([]byte, h2ProgressBodyPart))
	}
	p.open(nil, frames)
	if got := p.w.server.inFlightBodyBytes.Load(); got != h2ProgressBodyFrames*h2ProgressBodyPart {
		t.Fatalf("partial body reservation = %d, want %d", got, h2ProgressBodyFrames*h2ProgressBodyPart)
	}
	if p.c.readN != 0 {
		t.Fatalf("read buffer holds %d bytes; a PING would not reach the empty-buffer read path", p.c.readN)
	}
	p.run(h2ProgressPing)
	p.wantReset(1)
	if got := p.w.server.inFlightBodyBytes.Load(); got != 0 {
		t.Fatalf("body reservation after the reset = %d, want 0", got)
	}
}

func TestH2BodyProgressKeepsUploadAlive(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(h2ProgressTimeout)
	h2ProgressUploadRoutes(p.w)
	p.open(nil, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up")))
	elapsed := p.run(func() []byte { return appendH2Frame(nil, H2FrameData, 0, 1, []byte("x")) })
	if elapsed < 2*h2ProgressTimeout {
		t.Fatalf("test ran %v, want at least %v", elapsed, 2*h2ProgressTimeout)
	}
	if _, reset := p.resets[1]; reset || p.c.fd < 0 {
		t.Fatalf("an upload that sends body bytes was ended: reset=%v closed=%v", reset, p.c.fd < 0)
	}
}

func TestH2StalledUploadResetWhileTricklingSiblingCompletes(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(h2ProgressTimeout)
	h2ProgressUploadRoutes(p.w)
	frames := appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up"))
	frames = appendH2Frame(frames, H2FrameData, 0, 1, []byte("stalled"))
	frames = appendH2Frame(frames, H2FrameHeaders, H2FlagEndHeaders, 3, h2FixRequestBlock("POST", "/up"))
	p.open(nil, frames)
	p.run(func() []byte { return appendH2Frame(nil, H2FrameData, 0, 3, []byte("t")) })
	p.wantReset(1)
	if _, reset := p.resets[3]; reset {
		t.Fatal("the trickling sibling stream was reset")
	}
	p.send(appendH2Frame(nil, H2FrameData, H2FlagEndStream, 3, []byte("t")))
	p.settleHandlers()
	if !p.ended[3] {
		t.Fatal("the trickling sibling stream got no complete response")
	}
}

func TestH2PingsDoNotKeepStalledResponseAlive(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
	p.w.writeTO = int64(h2ProgressTimeout)
	big := make([]byte, 1<<20)
	p.w.server.Router.GET("/big", func(_ *Request, r *Response) { r.Status(200).Bytes(big) })
	p.w.server.Router.Build()
	p.w.server.computeFastDispatch()
	settings := h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0})
	p.open(settings, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/big")))
	p.settleHandlers()
	if len(p.c.h2.sending) != 1 || p.c.h2.sendingBytes == 0 {
		t.Fatalf("response is not parked on the peer window: sending=%d stalled=%d", len(p.c.h2.sending), p.c.h2.sendingBytes)
	}
	p.run(h2ProgressPing)
	p.wantReset(1)
	if len(p.c.h2.sending) != 0 || p.c.h2.parkedBytes != 0 {
		t.Fatalf("reset response still parked: sending=%d parked=%d", len(p.c.h2.sending), p.c.h2.parkedBytes)
	}
}

func TestH2WindowUpdatesKeepSlowDownloadAlive(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
	p.w.writeTO = int64(h2ProgressTimeout)
	big := make([]byte, 1<<20)
	p.w.server.Router.GET("/big", func(_ *Request, r *Response) { r.Status(200).Bytes(big) })
	p.w.server.Router.Build()
	p.w.server.computeFastDispatch()
	settings := h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0})
	p.open(settings, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/big")))
	p.settleHandlers()
	elapsed := p.run(func() []byte { return appendH2Frame(nil, H2FrameWindowUpdate, 0, 1, h2FixWindowIncrement(1024)) })
	if elapsed < 2*h2ProgressTimeout {
		t.Fatalf("test ran %v, want at least %v", elapsed, 2*h2ProgressTimeout)
	}
	if _, reset := p.resets[1]; reset || p.c.fd < 0 {
		t.Fatalf("a download that the peer keeps crediting was ended: reset=%v closed=%v", reset, p.c.fd < 0)
	}
}

func h2ProgressStreamedRoute(p *h2Progress, size int) {
	chunk := make([]byte, size)
	p.w.server.Router.GET("/streamed", func(_ *Request, resp *Response) {
		sw := resp.EnsureStreamWriter()
		resp.SetStreamer(sw)
		_ = sw.WriteHeader(200, nil, "application/octet-stream")
		_ = sw.WriteChunk(chunk)
		_ = sw.Close()
	})
	p.w.server.Router.Build()
	p.w.server.computeFastDispatch()
}

func TestH2PingsDoNotKeepStalledStreamedResponseAlive(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
	p.w.writeTO = int64(h2ProgressTimeout)
	h2ProgressStreamedRoute(p, 100<<10)
	settings := h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0})
	p.open(settings, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/streamed")))
	p.settleHandlers()
	if len(p.c.h2Streaming) != 1 {
		t.Fatalf("streamed response is not waiting on the peer window: streaming=%d", len(p.c.h2Streaming))
	}
	p.run(h2ProgressPing)
	p.wantReset(1)
	if len(p.c.h2Streaming) != 0 {
		t.Fatalf("reset streamed response still registered: %d", len(p.c.h2Streaming))
	}
}

func TestH2WindowUpdatesKeepSlowStreamedDownloadAlive(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
	p.w.writeTO = int64(h2ProgressTimeout)
	h2ProgressStreamedRoute(p, 100<<10)
	settings := h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0})
	p.open(settings, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/streamed")))
	p.settleHandlers()
	elapsed := p.run(func() []byte { return appendH2Frame(nil, H2FrameWindowUpdate, 0, 1, h2FixWindowIncrement(1024)) })
	if elapsed < 2*h2ProgressTimeout {
		t.Fatalf("test ran %v, want at least %v", elapsed, 2*h2ProgressTimeout)
	}
	if _, reset := p.resets[1]; reset || p.c.fd < 0 {
		t.Fatalf("a streamed download that the peer keeps crediting was ended: reset=%v closed=%v", reset, p.c.fd < 0)
	}
}

func TestH2StreamedBodyHasReadDeadline(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(h2ProgressTimeout)
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
	if p.c.inFlight != 1 || len(p.c.h2BodyIn) != 1 {
		t.Fatalf("handler state: inFlight=%d bodyIn=%d", p.c.inFlight, len(p.c.h2BodyIn))
	}
	p.run(h2ProgressPing)
	p.wantReset(1)
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("handler read of the reset body returned no error")
		}
	case <-time.After(h2FixCeiling):
		t.Fatal("handler read did not return after the stream reset")
	}
}

func TestH2StreamedBodyProgressKeepsUploadAlive(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(h2ProgressTimeout)
	p.w.streamBodyAbove = 1
	entered := make(chan struct{})
	p.w.server.Router.POST("/up", func(r *Request, resp *Response) {
		close(entered)
		_, _ = io.Copy(io.Discard, r.BodyStream())
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
	elapsed := p.run(func() []byte { return appendH2Frame(nil, H2FrameData, 0, 1, []byte("x")) })
	if elapsed < 2*h2ProgressTimeout {
		t.Fatalf("test ran %v, want at least %v", elapsed, 2*h2ProgressTimeout)
	}
	if _, reset := p.resets[1]; reset || p.c.fd < 0 {
		t.Fatalf("a streamed upload that sends body bytes was ended: reset=%v closed=%v", reset, p.c.fd < 0)
	}
}

func TestH2StreamedBodyClosedWindowWaitsForReader(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(h2ProgressTimeout)
	p.w.streamBodyAbove = 1
	p.w.server.config.H2InitialWindowSize = h2ProgressWindow
	entered, release := make(chan struct{}), make(chan struct{})
	p.w.server.Router.POST("/up", func(r *Request, resp *Response) {
		close(entered)
		<-release
		_, _ = io.Copy(io.Discard, r.BodyStream())
		resp.Status(200).String("ok")
	})
	p.w.server.Router.Build()
	p.w.server.computeFastDispatch()
	released := false
	p.t.Cleanup(func() {
		if !released {
			close(release)
		}
	})
	p.cleanupHandlers()
	frames := appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up"))
	frames = appendH2Frame(frames, H2FrameData, 0, 1, make([]byte, h2ProgressWindow))
	p.open(nil, frames)
	select {
	case <-entered:
	case <-time.After(h2FixCeiling):
		t.Fatal("streaming handler did not start")
	}
	if in := p.c.h2BodyIn[1]; in == nil || in.recvWindow != 0 {
		t.Fatalf("fixture did not close the stream window: %+v", in)
	}
	p.run(h2ProgressPing)
	if _, reset := p.resets[1]; reset {
		t.Fatal("a stream whose window the server closed was reset for not sending")
	}
	close(release)
	released = true
	deadline := turbo.Deadline(h2FixCeiling)
	for turbo.Until(deadline) > 0 && p.c.h2BodyIn[1] != nil && p.c.h2BodyIn[1].recvWindow == 0 {
		if p.w.taskPending.Load() {
			p.w.drainTasks()
		}
		time.Sleep(time.Millisecond)
	}
	p.w.flushPending()
	p.drain()
	p.sweep()
	if _, reset := p.resets[1]; reset {
		t.Fatal("a stream was reset right after the reader reopened its window")
	}
}

func TestH2HeadersOnlyUploadIsReset(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(h2ProgressTimeout)
	h2ProgressUploadRoutes(p.w)
	p.open(nil, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up")))
	if len(p.c.h2.streams) != 1 {
		t.Fatalf("fixture did not buffer the request: streams=%d bodyIn=%d", len(p.c.h2.streams), len(p.c.h2BodyIn))
	}
	p.run(h2ProgressPing)
	p.wantReset(1)
}
