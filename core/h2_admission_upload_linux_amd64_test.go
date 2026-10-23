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
	h2AdmitBudgetUpload = 3 * h2AdmitBodyPerStream
	h2UploadStreams     = 20
	h2UploadSize        = 4 << 20
	h2UploadWaiters     = 8
)

func h2UploadHeaders(rc *h2RawConn, id uint32, path string, size int) {
	rc.write(H2FrameHeaders, H2FlagEndHeaders, id, hpackBlock(
		[2]string{":method", "POST"}, [2]string{":scheme", "http"}, [2]string{":path", path},
		[2]string{":authority", h2FixAuthority}, [2]string{"content-length", strconv.Itoa(size)}))
}

func (rc *h2RawConn) h2UploadOutcomes(t *testing.T, want map[uint32]bool) (map[uint32]string, map[uint32]uint32) {
	t.Helper()
	bodies, resets := map[uint32]string{}, map[uint32]uint32{}
	ended := map[uint32]bool{}
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
		if _, reset := resets[f.streamID]; reset {
			t.Fatalf("server sent frame type %d on stream %d after it reset the stream", f.typ, f.streamID)
		}
		if ended[f.streamID] {
			if f.typ == H2FrameRSTStream && binary.BigEndian.Uint32(f.payload) == H2ErrNoError {
				continue
			}
			t.Fatalf("server sent frame type %d on stream %d after its response ended", f.typ, f.streamID)
		}
		switch {
		case f.typ == H2FrameRSTStream:
			resets[f.streamID] = binary.BigEndian.Uint32(f.payload)
			done++
		case f.typ == H2FrameData:
			bodies[f.streamID] += string(f.payload)
			if f.flags&H2FlagEndStream != 0 {
				ended[f.streamID] = true
				done++
			}
		}
	}
	return bodies, resets
}

type h2BudgetSampler struct {
	peakServer atomic.Int64
	peakConn   atomic.Int64
	stop       chan struct{}
	done       chan struct{}
}

func h2ConnBodyCounter(t *testing.T, srv *Server) *atomic.Int64 {
	t.Helper()
	var counter *atomic.Int64
	if !h2FixPollUntil(func() bool {
		srv.wakersMu.Lock()
		defer srv.wakersMu.Unlock()
		for waker := range srv.wakers {
			w, ok := waker.(*epollWorker)
			if !ok {
				continue
			}
			got := make(chan *atomic.Int64, 1)
			w.postTask(func(w *epollWorker) {
				for _, c := range w.conns {
					if c != nil && c.fd >= 0 && c.speaksH2() {
						got <- &c.h2.bodyReserved
						return
					}
				}
				got <- nil
			})
			if counter = <-got; counter != nil {
				return true
			}
		}
		return false
	}) {
		t.Fatal("no H2 connection to sample")
	}
	return counter
}

func startH2BudgetSampler(srv *Server, conn *atomic.Int64) *h2BudgetSampler {
	s := &h2BudgetSampler{stop: make(chan struct{}), done: make(chan struct{})}
	raise := func(peak *atomic.Int64, v int64) {
		for p := peak.Load(); v > p && !peak.CompareAndSwap(p, v); p = peak.Load() {
		}
	}
	go func() {
		defer close(s.done)
		for {
			raise(&s.peakServer, srv.inFlightBodyBytes.Load())
			raise(&s.peakConn, conn.Load())
			select {
			case <-s.stop:
				return
			default:
				time.Sleep(50 * time.Microsecond)
			}
		}
	}()
	return s
}

func (s *h2BudgetSampler) finish() (server, conn int64) {
	close(s.stop)
	<-s.done
	return s.peakServer.Load(), s.peakConn.Load()
}

func TestH2AdmissionParallelUploadsStayInsideBudget(t *testing.T) {
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
	budget := srv.config.MaxInFlightBodyBytes
	if h2UploadStreams*h2UploadSize <= budget || h2UploadSize > int(srv.h2InitialWindow()) {
		t.Fatal("fixture must exceed the body budget and stay inside each stream window")
	}
	rc := h2RawDial(t, addr, h2FixSettings())
	_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
	sampler := startH2BudgetSampler(srv, h2ConnBodyCounter(t, srv))
	want := make(map[uint32]bool, h2UploadStreams)
	for i := range h2UploadStreams {
		id := uint32(2*i + 1)
		want[id] = true
		h2UploadHeaders(rc, id, "/up", h2UploadSize)
		h2AdmitSendBody(rc, id, h2UploadSize, true)
	}
	time.Sleep(h2FixQuietWindow)
	if state := h2AdmissionProbe(t, srv); int64(state.held) > budget || int64(state.held) > srv.inFlightBodyBytes.Load() {
		t.Fatalf("readers buffer %d body bytes, budget counts %d, MaxInFlightBodyBytes %d", state.held, srv.inFlightBodyBytes.Load(), budget)
	}
	close(release)
	bodies, resets := rc.h2UploadOutcomes(t, want)
	peakServer, peakConn := sampler.finish()
	if peakServer > budget || peakConn > budget {
		t.Fatalf("body counters peaked at server %d and connection %d, MaxInFlightBodyBytes %d", peakServer, peakConn, budget)
	}
	for id, code := range resets {
		if code != H2ErrEnhanceYourCalm && code != H2ErrRefusedStream {
			t.Fatalf("stream %d reset with code %d, want ENHANCE_YOUR_CALM or REFUSED_STREAM", id, code)
		}
	}
	accepted := 0
	for id := range want {
		if _, refused := resets[id]; refused {
			continue
		}
		accepted++
		if bodies[id] != strconv.Itoa(h2UploadSize) {
			t.Fatalf("stream %d delivered %q bytes, want %d", id, bodies[id], h2UploadSize)
		}
	}
	if accepted == 0 {
		t.Fatal("server refused every upload")
	}
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
		t.Fatalf("budget still counts %d bytes", srv.inFlightBodyBytes.Load())
	}
}

func TestH2AdmissionIdleBodyStreamsHoldNoBudget(t *testing.T) {
	const idleStreams = 20
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	var idleRunning atomic.Int64
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.StreamBodyAbove = 1
		c.MaxInFlightBodyBytes = h2AdmitBodyBudget
	}, func(srv *Server) {
		srv.Router.POST("/idle", func(req *Request, resp *Response) {
			idleRunning.Add(1)
			<-hold
			resp.Status(200).String("idle")
		})
		srv.Router.POST("/read", func(req *Request, resp *Response) {
			n, err := io.Copy(io.Discard, req.BodyStream())
			resp.Status(200).String(strconv.FormatInt(n, 10) + " " + h2AdmitErrText(err))
		})
	})
	idle := h2RawDial(t, addr, h2FixSettings())
	for i := range idleStreams {
		h2UploadHeaders(idle, uint32(2*i+1), "/idle", h2AdmitBodyPerStream)
	}
	if !h2FixPollUntil(func() bool { return idleRunning.Load() == idleStreams }) {
		t.Fatalf("%d of %d idle upload handlers run", idleRunning.Load(), idleStreams)
	}
	if got := srv.inFlightBodyBytes.Load(); got != 0 {
		t.Fatalf("%d idle upload streams with no data hold %d budget bytes", idleStreams, got)
	}
	busy := h2RawDial(t, addr, h2FixSettings())
	_ = busy.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
	h2UploadHeaders(busy, 1, "/read", h2AdmitBudgetUpload)
	h2AdmitSendBody(busy, 1, h2AdmitBudgetUpload, true)
	bodies, resets := busy.h2UploadOutcomes(t, map[uint32]bool{1: true})
	if want := strconv.Itoa(h2AdmitBudgetUpload) + " nil"; len(resets) != 0 || bodies[1] != want {
		t.Fatalf("upload beside idle streams: resets %v, body %q, want no reset and %q", resets, bodies[1], want)
	}
}

func h2AdmitErrText(err error) string {
	if err == nil {
		return "nil"
	}
	return err.Error()
}

func TestH2AdmissionRunningStreamOverBudgetIsReset(t *testing.T) {
	const window = 2 * h2AdmitBodyBudget
	readNow := make(chan struct{})
	result := make(chan error, 1)
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.StreamBodyAbove = 1
		c.MaxInFlightBodyBytes = h2AdmitBodyBudget
		c.H2InitialWindowSize = window
		c.MaxBodySize = window
	}, func(srv *Server) {
		srv.Router.POST("/late", func(req *Request, resp *Response) {
			<-readNow
			_, err := io.Copy(io.Discard, req.BodyStream())
			result <- err
			resp.Status(200).String("late")
		})
	})
	rc := h2RawDial(t, addr, h2FixSettings())
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(h2FixMaxWindow-H2DefaultWindowSize))
	_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
	sampler := startH2BudgetSampler(srv, h2ConnBodyCounter(t, srv))
	h2UploadHeaders(rc, 1, "/late", window)
	h2AdmitSendBody(rc, 1, h2AdmitBodyBudget+h2AdmitBodyPerStream, false)
	f, err := rc.awaitStreamOutcome(1)
	if err != nil || f.typ != H2FrameRSTStream || binary.BigEndian.Uint32(f.payload) != H2ErrEnhanceYourCalm {
		t.Fatalf("running upload over budget got frame type %d err %v, want RST_STREAM ENHANCE_YOUR_CALM", f.typ, err)
	}
	close(readNow)
	if got := <-result; got == nil {
		t.Fatal("handler read a reset body without an error")
	}
	for _, f := range rc.framesWithin(h2FixQuietWindow) {
		if f.streamID == 1 {
			t.Fatalf("server sent frame type %d on stream 1 after it reset the stream", f.typ)
		}
	}
	if peakServer, peakConn := sampler.finish(); peakServer > h2AdmitBodyBudget || peakConn > h2AdmitBodyBudget {
		t.Fatalf("body counters peaked at server %d and connection %d, MaxInFlightBodyBytes %d", peakServer, peakConn, h2AdmitBodyBudget)
	}
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
		t.Fatalf("budget still counts %d bytes", srv.inFlightBodyBytes.Load())
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

func TestH2AdmissionStreamedBodyBudgetAccounting(t *testing.T) {
	cases := map[string]struct {
		endStream bool
		trailers  bool
		closeBody bool
		readBody  bool
		after     int
		want      func(window int64) int64
	}{
		"trailers end holds buffered bytes":       {trailers: true, want: func(int64) int64 { return h2AdmitBodyPerStream }},
		"read of an open body releases":           {readBody: true, want: func(int64) int64 { return 0 }},
		"open body holds its buffered bytes":      {want: func(int64) int64 { return h2AdmitBodyPerStream }},
		"ended body holds only buffered bytes":    {endStream: true, want: func(int64) int64 { return h2AdmitBodyPerStream }},
		"close after end releases buffered bytes": {endStream: true, closeBody: true, want: func(int64) int64 { return 0 }},
		"data after close holds no budget":        {closeBody: true, after: h2AdmitBodyPerStream, want: func(int64) int64 { return 0 }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			closed, hold := make(chan struct{}), make(chan struct{})
			t.Cleanup(func() { close(hold) })
			var closeNow atomic.Bool
			addr, srv := startH2FixServerWith(t, func(c *Config) { c.StreamBodyAbove = 1 }, func(srv *Server) {
				srv.Router.POST("/body", func(req *Request, resp *Response) {
					for tc.closeBody && !closeNow.Load() {
						turbo.Sleep(time.Millisecond)
					}
					if tc.closeBody {
						_ = req.BodyStream().Close()
					}
					if tc.readBody {
						_, _ = io.ReadFull(req.BodyStream(), make([]byte, h2AdmitBodyPerStream))
					}
					close(closed)
					<-hold
					resp.Status(200).String("done")
				})
			})
			rc := h2RawDial(t, addr, h2FixSettings())
			_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
			declared := h2AdmitBodyPerStream + tc.after
			if !tc.endStream && !tc.trailers {
				declared++
			}
			h2UploadHeaders(rc, 1, "/body", declared)
			h2AdmitSendBody(rc, 1, h2AdmitBodyPerStream, tc.endStream)
			if tc.trailers {
				rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, hpackBlock([2]string{"x-checksum", "1"}))
			}
			window := int64(srv.h2InitialWindow())
			if !h2FixPollUntil(func() bool {
				if tc.endStream || tc.trailers {
					return srv.inFlightBodyBytes.Load() == h2AdmitBodyPerStream
				}
				return h2AdmissionProbe(t, srv).held == h2AdmitBodyPerStream || tc.readBody
			}) {
				t.Fatal("upload bytes did not reach the body reader")
			}
			closeNow.Store(true)
			<-closed
			h2AdmitSendBody(rc, 1, tc.after, false)
			want := tc.want(window)
			if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == want }) {
				t.Fatalf("budget counts %d bytes while the handler runs, want %d", srv.inFlightBodyBytes.Load(), want)
			}
			time.Sleep(h2FixQuietWindow)
			if got := srv.inFlightBodyBytes.Load(); got != want {
				t.Fatalf("budget moved to %d bytes, want %d", got, want)
			}
			if got := h2AdmissionProbe(t, srv).body; got != want {
				t.Fatalf("connection body counter holds %d bytes, want %d", got, want)
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
	if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).held == h2AdmitBodyPerStream }) {
		t.Fatal("upload bytes did not reach the body reader")
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
	h2UploadHeaders(rc, 1, "/read", h2AdmitBodyPerStream)
	h2AdmitSendBody(rc, 1, h2AdmitBodyPerStream, true)
	<-consumed
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
		t.Fatalf("read body bytes still hold %d budget bytes while the handler runs", srv.inFlightBodyBytes.Load())
	}
}

func TestH2AdmissionStartedStreamKeepsFlowControlAfterWait(t *testing.T) {
	const budget = 6 << 20
	const before, after = h2AdmitBodyPerStream, 3 * h2AdmitBodyPerStream
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
		c.MaxInFlightBodyBytes = budget
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
	if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).waiting == 1 && srv.inFlightBodyBytes.Load() == before }) {
		t.Fatalf("waiting upload holds %d budget bytes, want %d", srv.inFlightBodyBytes.Load(), before)
	}
	close(first)
	<-started
	if got := srv.inFlightBodyBytes.Load(); got != before {
		t.Fatalf("started upload holds %d budget bytes, want its %d buffered bytes", got, before)
	}
	h2AdmitSendBody(rc, 3, after, true)
	time.Sleep(h2FixQuietWindow)
	close(second)
	bodies, resets := rc.h2UploadOutcomes(t, map[uint32]bool{1: true, 3: true})
	if len(resets) != 0 || bodies[3] != strconv.Itoa(before+after) {
		t.Fatalf("started upload: resets %v, body %q, want no reset and %d bytes", resets, bodies[3], before+after)
	}
}

func TestH2AdmissionHandlerEndReleasesUnreadBody(t *testing.T) {
	addr, srv := startH2FixServerWith(t, func(c *Config) { c.StreamBodyAbove = 1 }, func(srv *Server) {
		srv.Router.POST("/ignore", func(req *Request, resp *Response) {
			for srv.inFlightBodyBytes.Load() != h2AdmitBodyPerStream {
				turbo.Sleep(time.Millisecond)
			}
			resp.Status(200).String("ignored")
		})
	})
	rc := h2RawDial(t, addr, h2FixSettings())
	_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
	h2UploadHeaders(rc, 1, "/ignore", h2AdmitBodyPerStream)
	h2AdmitSendBody(rc, 1, h2AdmitBodyPerStream, true)
	rc.h2AdmitCollect(t, map[uint32]bool{1: true}, 0)
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
		t.Fatalf("handler ended but its unread body holds %d budget bytes", srv.inFlightBodyBytes.Load())
	}
}

func TestBodyReaderReservePushIntoClosedReaderReleases(t *testing.T) {
	srv := New(Config{HTTPAddr: "-", MaxInFlightBodyBytes: h2AdmitBodyBudget})
	var conn atomic.Int64
	reader := newBodyReader(func() {})
	reader.chargeBudget(srv, &conn)
	_ = reader.Close()
	if !reader.reservePush(h2FixBody(h2AdmitBodyFrame)) {
		t.Fatal("budget refused a push into a closed reader")
	}
	if srv.inFlightBodyBytes.Load() != 0 || conn.Load() != 0 {
		t.Fatalf("push into a closed reader holds server %d and connection %d budget bytes", srv.inFlightBodyBytes.Load(), conn.Load())
	}
}

func TestH2AdmissionServerResetOfRunningStreamSendsNoResponse(t *testing.T) {
	const smallWindow = 1 << 16
	cases := map[string]struct {
		declared, sent int
		wantCode       uint32
	}{
		"body longer than content-length": {declared: 10, sent: 20, wantCode: H2ErrProtocol},
		"body beyond the stream window":   {declared: 2 * smallWindow, sent: smallWindow + h2AdmitBodyFrame, wantCode: H2ErrFlowControl},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			running, respond := make(chan struct{}), make(chan struct{})
			returned := make(chan struct{})
			addr, srv := startH2FixServerWith(t, func(c *Config) {
				c.StreamBodyAbove = 1
				c.H2InitialWindowSize = smallWindow
			}, func(srv *Server) {
				srv.Router.POST("/late", func(req *Request, resp *Response) {
					close(running)
					<-respond
					resp.Status(200).String("late")
					close(returned)
				})
			})
			rc := h2RawDial(t, addr, h2FixSettings())
			rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(h2FixMaxWindow-H2DefaultWindowSize))
			_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
			h2UploadHeaders(rc, 1, "/late", tc.declared)
			<-running
			h2AdmitSendBody(rc, 1, tc.sent, false)
			f, err := rc.awaitStreamOutcome(1)
			if err != nil || f.typ != H2FrameRSTStream || binary.BigEndian.Uint32(f.payload) != tc.wantCode {
				t.Fatalf("got frame type %d err %v, want RST_STREAM code %d", f.typ, err, tc.wantCode)
			}
			close(respond)
			<-returned
			for _, f := range rc.framesWithin(h2FixQuietWindow) {
				if f.streamID == 1 {
					t.Fatalf("server sent frame type %d on stream 1 after it reset the stream", f.typ)
				}
			}
			if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
				t.Fatalf("budget still counts %d bytes", srv.inFlightBodyBytes.Load())
			}
		})
	}
}
