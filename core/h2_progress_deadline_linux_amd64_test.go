//go:build linux && amd64

package core

import (
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
)

func h2ProgressDrain(peer int) {
	buf := make([]byte, 1<<16)
	for {
		if n, err := unix.Read(peer, buf); n <= 0 || err != nil {
			return
		}
	}
}

func h2ProgressSend(t *testing.T, w *epollWorker, c *epollConn, peer int, frames []byte) {
	t.Helper()
	if _, err := unix.Write(peer, frames); err != nil {
		t.Fatal(err)
	}
	w.readable(c, false)
	w.flushPending()
	h2ProgressDrain(peer)
}

func h2ProgressSweep(w *epollWorker) {
	w.lastSweep = 0
	w.sweepDeadlines()
}

func h2ProgressOpen(t *testing.T, w *epollWorker, c *epollConn, peer int, settings []byte, frames []byte) {
	t.Helper()
	req := append([]byte(nil), H2ClientPreface[:]...)
	req = appendH2Frame(req, H2FrameSettings, 0, 0, settings)
	h2ProgressSend(t, w, c, peer, append(req, frames...))
}

func h2ProgressPing() []byte {
	var burst []byte
	for range h2ProgressPingBurst {
		burst = appendH2Frame(burst, H2FramePing, 0, 0, make([]byte, 8))
	}
	return burst
}

func h2ProgressRun(t *testing.T, w *epollWorker, c *epollConn, peer int, frame func() []byte) time.Duration {
	t.Helper()
	start := time.Now()
	for range h2ProgressRounds {
		time.Sleep(h2ProgressTick)
		if c.fd < 0 {
			return time.Since(start)
		}
		h2ProgressSend(t, w, c, peer, frame())
		h2ProgressSweep(w)
	}
	return time.Since(start)
}

func TestH2PingsDoNotKeepPartialBodyAlive(t *testing.T) {
	w, c, peer := h2DeadlineFixture(t)
	w.readTO = int64(h2ProgressTimeout)
	w.server.Router.POST("/up", func(_ *Request, r *Response) { r.Status(200).String("ok") })
	w.server.Router.Build()
	w.server.computeFastDispatch()
	frames := appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up"))
	for range h2ProgressBodyFrames {
		frames = appendH2Frame(frames, H2FrameData, 0, 1, make([]byte, h2ProgressBodyPart))
	}
	h2ProgressOpen(t, w, c, peer, nil, frames)
	if got := w.server.inFlightBodyBytes.Load(); got != h2ProgressBodyFrames*h2ProgressBodyPart {
		t.Fatalf("partial body reservation = %d, want %d", got, h2ProgressBodyFrames*h2ProgressBodyPart)
	}
	if c.readN != 0 {
		t.Fatalf("read buffer holds %d bytes; a PING would not reach the empty-buffer read path", c.readN)
	}
	elapsed := h2ProgressRun(t, w, c, peer, h2ProgressPing)
	if c.fd >= 0 {
		t.Fatalf("PINGs kept a partial request body open for %v with ReadTimeout %v", elapsed, h2ProgressTimeout)
	}
	if got := w.server.inFlightBodyBytes.Load(); got != 0 {
		t.Fatalf("body reservation after close = %d, want 0", got)
	}
}

func TestH2BodyProgressKeepsUploadAlive(t *testing.T) {
	w, c, peer := h2DeadlineFixture(t)
	w.readTO = int64(h2ProgressTimeout)
	w.server.Router.POST("/up", func(_ *Request, r *Response) { r.Status(200).String("ok") })
	w.server.Router.Build()
	w.server.computeFastDispatch()
	frames := appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up"))
	h2ProgressOpen(t, w, c, peer, nil, frames)
	elapsed := h2ProgressRun(t, w, c, peer, func() []byte {
		return appendH2Frame(nil, H2FrameData, 0, 1, []byte("x"))
	})
	if elapsed < 2*h2ProgressTimeout {
		t.Fatalf("test ran %v, want at least %v", elapsed, 2*h2ProgressTimeout)
	}
	if c.fd < 0 {
		t.Fatal("an upload that sends body bytes was closed")
	}
}

func TestH2PingsDoNotKeepStalledResponseAlive(t *testing.T) {
	w, c, peer := h2DeadlineFixture(t)
	w.readTO = int64(time.Hour)
	w.writeTO = int64(h2ProgressTimeout)
	big := make([]byte, 1<<20)
	w.server.Router.GET("/big", func(_ *Request, r *Response) { r.Status(200).Bytes(big) })
	w.server.Router.Build()
	w.server.computeFastDispatch()
	settings := h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0})
	frames := appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/big"))
	h2ProgressOpen(t, w, c, peer, settings, frames)
	deadline := turbo.Deadline(h2FixCeiling)
	for c.inFlight > 0 && turbo.Until(deadline) > 0 {
		if w.taskPending.Load() {
			w.drainTasks()
		}
		time.Sleep(time.Millisecond)
	}
	w.flushPending()
	h2ProgressDrain(peer)
	if len(c.h2.sending) != 1 || c.h2.sendingBytes == 0 {
		t.Fatalf("response is not parked on the peer window: sending=%d stalled=%d", len(c.h2.sending), c.h2.sendingBytes)
	}
	elapsed := h2ProgressRun(t, w, c, peer, h2ProgressPing)
	if c.fd >= 0 {
		t.Fatalf("PINGs kept a window-stalled response open for %v with WriteTimeout %v", elapsed, h2ProgressTimeout)
	}
}

func TestH2WindowUpdatesKeepSlowDownloadAlive(t *testing.T) {
	w, c, peer := h2DeadlineFixture(t)
	w.readTO = int64(time.Hour)
	w.writeTO = int64(h2ProgressTimeout)
	big := make([]byte, 1<<20)
	w.server.Router.GET("/big", func(_ *Request, r *Response) { r.Status(200).Bytes(big) })
	w.server.Router.Build()
	w.server.computeFastDispatch()
	settings := h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0})
	frames := appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/big"))
	h2ProgressOpen(t, w, c, peer, settings, frames)
	deadline := turbo.Deadline(h2FixCeiling)
	for c.inFlight > 0 && turbo.Until(deadline) > 0 {
		if w.taskPending.Load() {
			w.drainTasks()
		}
		time.Sleep(time.Millisecond)
	}
	w.flushPending()
	h2ProgressDrain(peer)
	elapsed := h2ProgressRun(t, w, c, peer, func() []byte {
		return appendH2Frame(nil, H2FrameWindowUpdate, 0, 1, h2FixWindowIncrement(1024))
	})
	if elapsed < 2*h2ProgressTimeout {
		t.Fatalf("test ran %v, want at least %v", elapsed, 2*h2ProgressTimeout)
	}
	if c.fd < 0 {
		t.Fatal("a download that the peer keeps crediting was closed")
	}
}

func TestH2StreamedBodyHasReadDeadline(t *testing.T) {
	w, c, peer := h2DeadlineFixture(t)
	w.readTO = int64(h2ProgressTimeout)
	w.streamBodyAbove = 1
	entered := make(chan struct{})
	readErr := make(chan error, 1)
	w.server.Router.POST("/up", func(r *Request, resp *Response) {
		close(entered)
		_, err := io.ReadAll(r.BodyStream())
		readErr <- err
		resp.Status(200).String("ok")
	})
	w.server.Router.Build()
	w.server.computeFastDispatch()
	t.Cleanup(func() {
		if c.fd >= 0 {
			w.closeConn(c)
		}
		for c.inFlight > 0 {
			h2DeadlineTask(t, w)
		}
	})
	frames := appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up"))
	h2ProgressOpen(t, w, c, peer, nil, frames)
	select {
	case <-entered:
	case <-time.After(h2FixCeiling):
		t.Fatal("streaming handler did not start")
	}
	if c.inFlight != 1 || len(c.h2BodyIn) != 1 {
		t.Fatalf("handler state: inFlight=%d bodyIn=%d", c.inFlight, len(c.h2BodyIn))
	}
	elapsed := h2ProgressRun(t, w, c, peer, h2ProgressPing)
	if c.fd >= 0 {
		t.Fatalf("a streamed body with no DATA stayed open for %v with ReadTimeout %v", elapsed, h2ProgressTimeout)
	}
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("handler read of the abandoned body returned no error")
		}
	case <-time.After(h2FixCeiling):
		t.Fatal("handler read did not return after the connection closed")
	}
}

func TestH2StreamedBodyProgressKeepsUploadAlive(t *testing.T) {
	w, c, peer := h2DeadlineFixture(t)
	w.readTO = int64(h2ProgressTimeout)
	w.streamBodyAbove = 1
	entered := make(chan struct{})
	w.server.Router.POST("/up", func(r *Request, resp *Response) {
		close(entered)
		_, _ = io.Copy(io.Discard, r.BodyStream())
		resp.Status(200).String("ok")
	})
	w.server.Router.Build()
	w.server.computeFastDispatch()
	t.Cleanup(func() {
		if c.fd >= 0 {
			w.closeConn(c)
		}
		for c.inFlight > 0 {
			h2DeadlineTask(t, w)
		}
	})
	frames := appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/up"))
	h2ProgressOpen(t, w, c, peer, nil, frames)
	select {
	case <-entered:
	case <-time.After(h2FixCeiling):
		t.Fatal("streaming handler did not start")
	}
	elapsed := h2ProgressRun(t, w, c, peer, func() []byte {
		return appendH2Frame(nil, H2FrameData, 0, 1, []byte("x"))
	})
	if elapsed < 2*h2ProgressTimeout {
		t.Fatalf("test ran %v, want at least %v", elapsed, 2*h2ProgressTimeout)
	}
	if c.fd < 0 {
		t.Fatal("a streamed upload that sends body bytes was closed")
	}
}
