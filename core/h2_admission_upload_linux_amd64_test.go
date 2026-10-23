//go:build linux && amd64

package core

import (
	"encoding/binary"
	"io"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	h2UploadStreams = 20
	h2UploadSize    = 4 << 20
	h2UploadWaiters = 8
)

func h2UploadHeaders(rc *h2RawConn, id uint32, path string, size int) {
	rc.write(H2FrameHeaders, H2FlagEndHeaders, id, hpackBlock(
		[2]string{":method", "POST"}, [2]string{":scheme", "http"}, [2]string{":path", path},
		[2]string{":authority", h2FixAuthority}, [2]string{"content-length", strconv.Itoa(size)}))
}

func (rc *h2RawConn) h2UploadOutcomes(t *testing.T, want map[uint32]bool) (map[uint32]string, map[uint32]uint32) {
	t.Helper()
	bodies, resets := map[uint32]string{}, map[uint32]uint32{}
	for done := 0; done < len(want); {
		f, err := rc.tryRead()
		if err != nil {
			t.Fatalf("read after %d/%d streams ended: %v", done, len(want), err)
		}
		if f.typ == H2FrameGoAway {
			t.Fatalf("GOAWAY after %d/%d streams ended", done, len(want))
		}
		if !want[f.streamID] {
			continue
		}
		switch {
		case f.typ == H2FrameRSTStream:
			resets[f.streamID] = binary.BigEndian.Uint32(f.payload)
			done++
		case f.typ == H2FrameData:
			bodies[f.streamID] += string(f.payload)
			if f.flags&H2FlagEndStream != 0 {
				done++
			}
		}
	}
	return bodies, resets
}

func TestH2AdmissionParallelUploadsInsideFlowControlSucceed(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	addr, srv := startH2FixServerWith(t, func(c *Config) { c.StreamBodyAbove = 1 }, func(srv *Server) {
		srv.Router.POST("/up", func(req *Request, resp *Response) {
			<-release
			n, _ := io.Copy(io.Discard, req.BodyStream())
			resp.Status(200).String(strconv.FormatInt(n, 10))
		})
	})
	if h2UploadStreams*h2UploadSize <= srv.config.MaxInFlightBodyBytes || h2UploadSize > int(srv.h2InitialWindow()) {
		t.Fatal("fixture must exceed the body budget and stay inside each stream window")
	}
	rc := h2RawDial(t, addr, h2FixSettings())
	_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
	want := make(map[uint32]bool, h2UploadStreams)
	for i := range h2UploadStreams {
		id := uint32(2*i + 1)
		want[id] = true
		h2UploadHeaders(rc, id, "/up", h2UploadSize)
		h2AdmitSendBody(rc, id, h2UploadSize, true)
	}
	time.Sleep(h2FixQuietWindow)
	close(release)
	bodies, resets := rc.h2UploadOutcomes(t, want)
	if len(resets) != 0 {
		t.Fatalf("server reset uploads that obey flow control: %v", resets)
	}
	for id := range want {
		if bodies[id] != strconv.Itoa(h2UploadSize) {
			t.Fatalf("stream %d delivered %q bytes, want %d", id, bodies[id], h2UploadSize)
		}
	}
}

func TestH2AdmissionWaitingUploadsOverBudgetAreRefused(t *testing.T) {
	b := newH2AdmitBlocker(t)
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.H2MaxRunningHandlers = 1
		c.StreamBodyAbove = 1
		c.MaxInFlightBodyBytes = h2AdmitBodyBudget
	}, b.routes)
	rc := h2RawDial(t, addr, h2FixSettings())
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(h2FixMaxWindow-H2DefaultWindowSize))
	_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
	h2FixGet(rc, 1, "/block")
	if !h2FixPollUntil(func() bool { return b.running.Load() == 1 }) {
		t.Fatal("blocking handler never started")
	}
	want := map[uint32]bool{1: true}
	for i := range h2UploadWaiters {
		id := uint32(2*i + 3)
		want[id] = true
		h2UploadHeaders(rc, id, "/echo", h2AdmitBodyPerStream)
		h2AdmitSendBody(rc, id, h2AdmitBodyPerStream, true)
	}
	time.Sleep(h2FixQuietWindow)
	if got := srv.inFlightBodyBytes.Load(); got > h2AdmitBodyBudget {
		t.Fatalf("waiting uploads hold %d budget bytes, MaxInFlightBodyBytes %d", got, h2AdmitBodyBudget)
	}
	b.open()
	bodies, resets := rc.h2UploadOutcomes(t, want)
	if len(resets) == 0 || len(resets) == h2UploadWaiters {
		t.Fatalf("%d of %d waiting uploads were refused, want some but not all", len(resets), h2UploadWaiters)
	}
	for id, code := range resets {
		if code != H2ErrRefusedStream {
			t.Fatalf("stream %d reset with code %d, want REFUSED_STREAM", id, code)
		}
		if bodies[id] != "" {
			t.Fatalf("refused stream %d also got a response %q", id, bodies[id])
		}
	}
	for id := range want {
		if _, refused := resets[id]; refused || id == 1 {
			continue
		}
		if bodies[id] != strconv.Itoa(h2AdmitBodyPerStream) {
			t.Fatalf("accepted stream %d echoed %q body bytes, want %d", id, bodies[id], h2AdmitBodyPerStream)
		}
	}
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
		t.Fatalf("budget still counts %d bytes", srv.inFlightBodyBytes.Load())
	}
}

func TestH2AdmissionClosedBodyReleasesBudget(t *testing.T) {
	cases := map[string]struct{ before, after int }{
		"close with buffered bytes": {before: h2AdmitBodyPerStream},
		"data after close":          {after: h2AdmitBodyPerStream},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			closed, hold := make(chan struct{}), make(chan struct{})
			t.Cleanup(func() { close(hold) })
			var closeNow atomic.Bool
			addr, srv := startH2FixServerWith(t, func(c *Config) { c.StreamBodyAbove = 1 }, func(srv *Server) {
				srv.Router.POST("/close", func(req *Request, resp *Response) {
					for !closeNow.Load() {
						turbo.Sleep(time.Millisecond)
					}
					_ = req.BodyStream().Close()
					close(closed)
					<-hold
					resp.Status(200).String("closed")
				})
			})
			rc := h2RawDial(t, addr, h2FixSettings())
			_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
			h2UploadHeaders(rc, 1, "/close", tc.before+tc.after+1)
			h2AdmitSendBody(rc, 1, tc.before, false)
			if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == int64(tc.before) }) {
				t.Fatalf("budget counts %d bytes before close, want %d", srv.inFlightBodyBytes.Load(), tc.before)
			}
			closeNow.Store(true)
			<-closed
			h2AdmitSendBody(rc, 1, tc.after, false)
			time.Sleep(h2FixQuietWindow)
			if got := srv.inFlightBodyBytes.Load(); got != 0 {
				t.Fatalf("closed body still holds %d budget bytes while the handler runs", got)
			}
			if got := h2AdmissionProbe(t, srv).body; got != 0 {
				t.Fatalf("connection body counter holds %d bytes", got)
			}
		})
	}
}

func TestH2AdmissionAbortedBodyDropsBufferedBytes(t *testing.T) {
	type result struct {
		n   int
		err error
	}
	aborted, read := make(chan struct{}), make(chan result, 1)
	running := make(chan struct{})
	addr, srv := startH2FixServerWith(t, func(c *Config) { c.StreamBodyAbove = 1 }, func(srv *Server) {
		srv.Router.POST("/late", func(req *Request, resp *Response) {
			close(running)
			<-aborted
			n, err := req.BodyStream().Read(make([]byte, h2AdmitBodyFrame))
			read <- result{n, err}
			resp.Status(200).String("late")
		})
	})
	rc := h2RawDial(t, addr, h2FixSettings())
	_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
	h2UploadHeaders(rc, 1, "/late", 2*h2AdmitBodyPerStream)
	h2AdmitSendBody(rc, 1, h2AdmitBodyPerStream, false)
	<-running
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == h2AdmitBodyPerStream }) {
		t.Fatalf("budget counts %d unread bytes, want %d", srv.inFlightBodyBytes.Load(), h2AdmitBodyPerStream)
	}
	rc.write(H2FrameRSTStream, 0, 1, rstPayload(H2ErrCancel))
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
		t.Fatalf("aborted body still holds %d budget bytes", srv.inFlightBodyBytes.Load())
	}
	close(aborted)
	got := <-read
	if got.n != 0 || got.err == nil {
		t.Fatalf("read of an aborted body returned %d bytes and error %v, want 0 bytes and an error", got.n, got.err)
	}
}

func TestH2AdmissionReadReleasesBudgetWhileHandlerRuns(t *testing.T) {
	consumed, hold := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(hold) })
	addr, srv := startH2FixServerWith(t, func(c *Config) { c.StreamBodyAbove = 1 }, func(srv *Server) {
		srv.Router.POST("/read", func(req *Request, resp *Response) {
			_, _ = io.ReadFull(req.BodyStream(), make([]byte, h2AdmitBodyPerStream))
			close(consumed)
			<-hold
			resp.Status(200).String("read")
		})
	})
	rc := h2RawDial(t, addr, h2FixSettings())
	_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
	h2UploadHeaders(rc, 1, "/read", 2*h2AdmitBodyPerStream)
	h2AdmitSendBody(rc, 1, h2AdmitBodyPerStream, false)
	<-consumed
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
		t.Fatalf("read body bytes still hold %d budget bytes while the handler runs", srv.inFlightBodyBytes.Load())
	}
}

func TestH2AdmissionStartedStreamKeepsFlowControlAfterWait(t *testing.T) {
	const window = 4 * h2AdmitBodyBudget
	const before, after = h2AdmitBodyPerStream, 2 * h2AdmitBodyBudget
	first, second := make(chan struct{}), make(chan struct{})
	started := make(chan struct{})
	t.Cleanup(func() {
		for _, ch := range []chan struct{}{first, second} {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
	})
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.H2MaxRunningHandlers = 1
		c.StreamBodyAbove = 1
		c.MaxInFlightBodyBytes = h2AdmitBodyBudget
		c.H2InitialWindowSize = window
		c.MaxBodySize = window
	}, func(srv *Server) {
		srv.Router.GET("/first", func(req *Request, resp *Response) {
			<-first
			resp.Status(200).String("first")
		})
		srv.Router.POST("/late", func(req *Request, resp *Response) {
			close(started)
			<-second
			n, _ := io.Copy(io.Discard, req.BodyStream())
			resp.Status(200).String(strconv.FormatInt(n, 10))
		})
	})
	rc := h2RawDial(t, addr, h2FixSettings())
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(h2FixMaxWindow-H2DefaultWindowSize))
	_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
	h2FixGet(rc, 1, "/first")
	h2UploadHeaders(rc, 3, "/late", before+after)
	h2AdmitSendBody(rc, 3, before, false)
	if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).waiting == 1 }) {
		t.Fatal("upload did not wait behind the running handler")
	}
	close(first)
	<-started
	h2AdmitSendBody(rc, 3, after, true)
	time.Sleep(h2FixQuietWindow)
	close(second)
	bodies, resets := rc.h2UploadOutcomes(t, map[uint32]bool{1: true, 3: true})
	if len(resets) != 0 || bodies[3] != strconv.Itoa(before+after) {
		t.Fatalf("started upload: resets %v, body %q, want no reset and %d bytes", resets, bodies[3], before+after)
	}
}
