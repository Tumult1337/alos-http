//go:build linux && amd64

package core

import (
	"encoding/binary"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	h2AdmitStreams       = 100
	h2AdmitRunningLimit  = 8
	h2AdmitBodyLen       = 3000
	h2AdmitBurstDeadline = 20 * time.Second
	h2AdmitBurstRounds   = 3
)

type h2AdmissionState struct {
	conns   int
	parked  int64
	sending int64
	waiting int
	running int
	body    int64
	held    int
	orphans int
}

func h2AdmissionProbe(t *testing.T, srv *Server) h2AdmissionState {
	t.Helper()
	srv.wakersMu.Lock()
	var workers []*epollWorker
	for waker := range srv.wakers {
		if w, ok := waker.(*epollWorker); ok {
			workers = append(workers, w)
		}
	}
	srv.wakersMu.Unlock()
	var total h2AdmissionState
	for _, worker := range workers {
		got := make(chan h2AdmissionState, 1)
		worker.postTask(func(w *epollWorker) {
			var s h2AdmissionState
			for _, c := range w.conns {
				if c == nil || c.fd < 0 || !c.speaksH2() {
					continue
				}
				s.conns++
				s.parked += c.h2.parkedBytes
				s.sending += c.h2.sendingBytes
				s.waiting += len(c.h2.waiting)
				s.running += c.inFlight
				s.body += c.h2.bodyReserved.Load()
				for _, in := range c.h2BodyIn {
					s.held += in.reader.buffered()
				}
				for _, stream := range c.h2.waiting {
					if in := stream.waitBody; in != nil && c.h2BodyIn[in.streamID] != in {
						s.held += in.reader.buffered()
						s.orphans++
					}
				}
			}
			got <- s
		})
		select {
		case s := <-got:
			total.conns += s.conns
			total.parked += s.parked
			total.sending += s.sending
			total.waiting += s.waiting
			total.running += s.running
			total.body += s.body
			total.held += s.held
			total.orphans += s.orphans
		case <-turbo.After(h2FixCeiling):
			t.Fatal("epoll worker did not answer the admission probe")
		}
	}
	return total
}

type h2AdmitBlocker struct {
	started atomic.Int64
	running atomic.Int64
	peak    atomic.Int64
	release chan struct{}
	open    func()
}

func newH2AdmitBlocker(t *testing.T) *h2AdmitBlocker {
	b := &h2AdmitBlocker{release: make(chan struct{})}
	b.open = sync.OnceFunc(func() { close(b.release) })
	t.Cleanup(b.open)
	return b
}

func (b *h2AdmitBlocker) handle(req *Request, resp *Response) {
	b.started.Add(1)
	n := b.running.Add(1)
	for {
		p := b.peak.Load()
		if n <= p || b.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case <-b.release:
	case <-turbo.After(h2FixHandlerCeiling):
	}
	b.running.Add(-1)
	resp.Status(200).String("released")
}

func (b *h2AdmitBlocker) routes(srv *Server) {
	srv.Router.GET("/block", b.handle)
	srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	srv.Router.POST("/echo", func(req *Request, resp *Response) {
		n := len(req.Body)
		if bs := req.BodyStream(); bs != nil {
			data, err := io.ReadAll(bs)
			if err != nil {
				resp.Status(500).String(err.Error())
				return
			}
			n = len(data)
		}
		resp.Status(200).String(strconv.Itoa(n))
	})
}

func h2AdmitPost(rc *h2RawConn, streamID uint32, size int) {
	block := hpackBlock(
		[2]string{":method", "POST"},
		[2]string{":scheme", "http"},
		[2]string{":path", "/echo"},
		[2]string{":authority", h2FixAuthority},
		[2]string{"content-length", strconv.Itoa(size)},
	)
	rc.write(H2FrameHeaders, H2FlagEndHeaders, streamID, block)
	rc.write(H2FrameData, H2FlagEndStream, streamID, h2FixBody(size))
}

func (rc *h2RawConn) h2AdmitCollect(t *testing.T, want map[uint32]bool, forbidden uint32) map[uint32]string {
	t.Helper()
	bodies := make(map[uint32]string, len(want))
	ended := 0
	for ended < len(want) {
		f, err := rc.tryRead()
		if err != nil {
			t.Fatalf("read after %d/%d streams ended: %v", ended, len(want), err)
		}
		if forbidden != 0 && f.streamID == forbidden {
			t.Fatalf("server answered stream %d with frame type %d after the peer reset it", forbidden, f.typ)
		}
		switch f.typ {
		case H2FrameGoAway:
			t.Fatalf("GOAWAY after %d/%d streams ended", ended, len(want))
		case H2FrameRSTStream:
			t.Fatalf("server reset stream %d with code %d", f.streamID, binary.BigEndian.Uint32(f.payload))
		case H2FrameData:
			bodies[f.streamID] += string(f.payload)
		}
		if (f.typ == H2FrameData || f.typ == H2FrameHeaders) && f.flags&H2FlagEndStream != 0 && want[f.streamID] {
			ended++
		}
	}
	return bodies
}

func TestH2MaxRunningHandlersBounds(t *testing.T) {
	cases := []struct {
		name    string
		value   int
		streams uint32
		want    int
	}{
		{name: "zero applies default", value: 0, want: 32},
		{name: "negative applies default", value: -7, want: 32},
		{name: "one", value: 1, want: 1},
		{name: "explicit", value: 50, want: 50},
		{name: "above protocol stream limit", value: 1000, want: int(H2MaxConcurrentStream)},
		{name: "above configured stream limit", value: 64, streams: 40, want: 40},
		{name: "default above small stream limit", value: 0, streams: 10, want: 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{config: Config{H2MaxRunningHandlers: tc.value, H2MaxConcurrentStreams: tc.streams}}
			if got := srv.h2MaxRunningHandlers(); got != tc.want {
				t.Fatalf("H2MaxRunningHandlers %d with stream limit %d gives %d, want %d", tc.value, tc.streams, got, tc.want)
			}
		})
	}
}

func TestH2AdmissionLegitimateBurstCompletes(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run(perfH2Scheme(useTLS), func(t *testing.T) {
			addr := perfH2TestServer(t, useTLS)
			blocks := perfH2EncodeRequest(perfH2W5b, perfH2Scheme(useTLS))
			cl := perfH2Dial(t, addr, useTLS)
			cl.fail = t.Fatalf
			_ = cl.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
			cl.prepare(perfH2W5b, blocks.warm, 1)
			cl.roundTrip(1)
			cl.prepare(perfH2W5b, blocks.steady, perfH2Streams)
			for range h2AdmitBurstRounds {
				cl.roundTrip(perfH2Streams)
			}
		})
	}
}

func TestH2AdmissionCapsRunningHandlers(t *testing.T) {
	b := newH2AdmitBlocker(t)
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.H2MaxConcurrentStreams = h2AdmitStreams + 1
		c.H2MaxRunningHandlers = h2AdmitRunningLimit
	}, b.routes)
	rc := h2RawDial(t, addr, h2FixSettings())
	want := make(map[uint32]bool, h2AdmitStreams)
	for i := range h2AdmitStreams {
		id := uint32(2*i + 1)
		want[id] = true
		h2FixGet(rc, id, "/block")
	}
	if !h2FixPollUntil(func() bool { return b.running.Load() >= h2AdmitRunningLimit }) {
		t.Fatalf("only %d handlers started, want %d", b.running.Load(), h2AdmitRunningLimit)
	}
	time.Sleep(h2FixQuietWindow)
	if got := b.peak.Load(); got != h2AdmitRunningLimit {
		t.Fatalf("%d handlers ran at once on one connection, want %d", got, h2AdmitRunningLimit)
	}
	state := h2AdmissionProbe(t, srv)
	if state.running != h2AdmitRunningLimit || state.waiting != h2AdmitStreams-h2AdmitRunningLimit {
		t.Fatalf("connection state running=%d waiting=%d, want running=%d waiting=%d",
			state.running, state.waiting, h2AdmitRunningLimit, h2AdmitStreams-h2AdmitRunningLimit)
	}
	b.open()
	bodies := rc.h2AdmitCollect(t, want, 0)
	for id := range want {
		if bodies[id] != "released" {
			t.Fatalf("stream %d body %q, want %q", id, bodies[id], "released")
		}
	}
	if got := b.peak.Load(); got > h2AdmitRunningLimit {
		t.Fatalf("%d handlers ran at once after release, want at most %d", got, h2AdmitRunningLimit)
	}
	if got := b.started.Load(); got != h2AdmitStreams {
		t.Fatalf("%d handlers started, want %d", got, h2AdmitStreams)
	}
}

func TestH2AdmissionResetWaitingStreamReleasesIt(t *testing.T) {
	for _, streamAbove := range []int64{0, 1} {
		t.Run("StreamBodyAbove="+strconv.FormatInt(streamAbove, 10), func(t *testing.T) {
			h2AdmissionResetWaitingStream(t, streamAbove)
		})
	}
}

func h2AdmissionResetWaitingStream(t *testing.T, streamAbove int64) {
	b := newH2AdmitBlocker(t)
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.H2MaxRunningHandlers = 1
		c.StreamBodyAbove = streamAbove
	}, b.routes)
	rc := h2RawDial(t, addr, h2FixSettings())
	h2FixGet(rc, 1, "/block")
	if !h2FixPollUntil(func() bool { return b.running.Load() == 1 }) {
		t.Fatal("blocking handler never started")
	}
	h2AdmitPost(rc, 3, h2AdmitBodyLen)
	h2FixGet(rc, 5, "/ok")
	var state h2AdmissionState
	if !h2FixPollUntil(func() bool {
		state = h2AdmissionProbe(t, srv)
		return state.waiting == 2 && state.body >= h2AdmitBodyLen
	}) {
		t.Fatalf("connection state waiting=%d body=%d, want 2 waiting streams holding %d body bytes", state.waiting, state.body, h2AdmitBodyLen)
	}
	rc.write(H2FrameRSTStream, 0, 3, rstPayload(H2ErrCancel))
	if !h2FixPollUntil(func() bool {
		state = h2AdmissionProbe(t, srv)
		return state.waiting == 1 && state.body == 0 && srv.inFlightBodyBytes.Load() == 0
	}) {
		t.Fatalf("after RST_STREAM waiting=%d conn body=%d server body=%d, want 1, 0, 0", state.waiting, state.body, srv.inFlightBodyBytes.Load())
	}
	b.open()
	bodies := rc.h2AdmitCollect(t, map[uint32]bool{1: true, 5: true}, 3)
	if bodies[1] != "released" || bodies[5] != "ok" {
		t.Fatalf("bodies %q and %q, want %q and %q", bodies[1], bodies[5], "released", "ok")
	}
	for _, f := range rc.framesWithin(h2FixQuietWindow) {
		if f.streamID == 3 {
			t.Fatalf("server answered reset stream 3 with frame type %d", f.typ)
		}
	}
}

func TestH2AdmissionWaitingStreamKeepsStreamedBody(t *testing.T) {
	b := newH2AdmitBlocker(t)
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.H2MaxRunningHandlers = 1
		c.StreamBodyAbove = 1
	}, b.routes)
	rc := h2RawDial(t, addr, h2FixSettings())
	h2FixGet(rc, 1, "/block")
	if !h2FixPollUntil(func() bool { return b.running.Load() == 1 }) {
		t.Fatal("blocking handler never started")
	}
	h2AdmitPost(rc, 3, h2AdmitBodyLen)
	if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).waiting == 1 }) {
		t.Fatal("streamed-body request did not wait behind the running handler")
	}
	b.open()
	bodies := rc.h2AdmitCollect(t, map[uint32]bool{1: true, 3: true}, 0)
	if want := strconv.Itoa(h2AdmitBodyLen); bodies[3] != want {
		t.Fatalf("streamed body length %q, want %q", bodies[3], want)
	}
}

func TestH2AdmissionWaitingStreamKeepsWindowCredit(t *testing.T) {
	const smallWindow = 100
	credits := map[string]func(rc *h2RawConn){
		"window update": func(rc *h2RawConn) {
			rc.write(H2FrameWindowUpdate, 0, 3, h2FixWindowIncrement(h2FixMidBody))
		},
		"initial window setting": func(rc *h2RawConn) {
			rc.write(H2FrameSettings, 0, 0, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), h2FixMidBody + smallWindow}))
		},
	}
	for name, credit := range credits {
		t.Run(name, func(t *testing.T) {
			b := newH2AdmitBlocker(t)
			addr, srv := startH2FixServerWith(t, func(c *Config) { c.H2MaxRunningHandlers = 1 }, func(srv *Server) {
				b.routes(srv)
				mid := h2FixBody(h2FixMidBody)
				srv.Router.GET("/mid", func(req *Request, resp *Response) { resp.Status(200).Bytes(mid) })
			})
			rc := h2RawDial(t, addr, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), smallWindow}))
			h2FixGet(rc, 1, "/block")
			if !h2FixPollUntil(func() bool { return b.running.Load() == 1 }) {
				t.Fatal("blocking handler never started")
			}
			h2FixGet(rc, 3, "/mid")
			if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).waiting == 1 }) {
				t.Fatal("stream 3 did not wait behind the running handler")
			}
			credit(rc)
			time.Sleep(h2FixQuietWindow)
			b.open()
			bodies := rc.h2AdmitCollect(t, map[uint32]bool{1: true, 3: true}, 0)
			if got := len(bodies[3]); got != h2FixMidBody {
				t.Fatalf("stream 3 delivered %d bytes, want %d", got, h2FixMidBody)
			}
		})
	}
}

func TestH2AdmissionWaitingStreamsCountAgainstStreamLimit(t *testing.T) {
	const streamLimit = 4
	b := newH2AdmitBlocker(t)
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.H2MaxConcurrentStreams = streamLimit
		c.H2MaxRunningHandlers = 1
	}, b.routes)
	rc := h2RawDial(t, addr, h2FixSettings())
	h2FixGet(rc, 1, "/block")
	if !h2FixPollUntil(func() bool { return b.running.Load() == 1 }) {
		t.Fatal("blocking handler never started")
	}
	want := map[uint32]bool{1: true}
	for id := uint32(3); id < 2*streamLimit; id += 2 {
		want[id] = true
		h2FixGet(rc, id, "/ok")
	}
	if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).waiting == streamLimit-1 }) {
		t.Fatalf("want %d waiting streams behind the running handler", streamLimit-1)
	}
	over := uint32(2*streamLimit + 1)
	h2FixGet(rc, over, "/ok")
	f, err := rc.awaitStreamOutcome(over)
	if err != nil {
		t.Fatalf("stream %d over the limit: %v", over, err)
	}
	if f.typ != H2FrameRSTStream || binary.BigEndian.Uint32(f.payload) != H2ErrRefusedStream {
		t.Fatalf("stream %d over the limit got frame type %d, want RST_STREAM REFUSED_STREAM", over, f.typ)
	}
	b.open()
	rc.h2AdmitCollect(t, want, over)
}

func TestH2AdmissionCloseReleasesWaitingStreams(t *testing.T) {
	b := newH2AdmitBlocker(t)
	addr, srv := startH2FixServerWith(t, func(c *Config) { c.H2MaxRunningHandlers = 1 }, b.routes)
	rc := h2RawDial(t, addr, h2FixSettings())
	h2FixGet(rc, 1, "/block")
	if !h2FixPollUntil(func() bool { return b.running.Load() == 1 }) {
		t.Fatal("blocking handler never started")
	}
	h2AdmitPost(rc, 3, h2AdmitBodyLen)
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == h2AdmitBodyLen }) {
		t.Fatalf("waiting stream holds %d body bytes, want %d", srv.inFlightBodyBytes.Load(), h2AdmitBodyLen)
	}
	_ = rc.conn.Close()
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
		t.Fatalf("closed connection still holds %d body bytes of a waiting stream", srv.inFlightBodyBytes.Load())
	}
	if got := b.started.Load(); got != 1 {
		t.Fatalf("%d handlers started, want only the blocking one", got)
	}
}

func TestH2AdmissionNewStreamQueuesBehindWaiting(t *testing.T) {
	w, c, _ := h2DeadlineFixture(t)
	c.protocol = plainConnProtoH2
	c.h2.init(w.server.h2HeaderTableSize(), w.server.h2HeaderListLimit())
	w.h2MaxRunning = 1
	queued := StreamPool.Get().(*H2Stream)
	queued.Reset()
	queued.ID = 1
	c.h2.waiting = append(c.h2.waiting, queued)
	next := StreamPool.Get().(*H2Stream)
	next.Reset()
	next.ID, next.Method, next.Path = 3, "GET", "/"
	t.Cleanup(c.h2.releaseWaiting)
	if !c.h2AdmitsHandler() {
		t.Fatal("fixture gates are closed; the test needs open gates")
	}
	c.epollH2DispatchStream(w.server, next.ID, next, false, false)
	if c.inFlight != 0 || len(c.h2.waiting) != 2 || c.h2.waiting[1] != next {
		t.Fatalf("new stream passed a waiting stream: inFlight=%d waiting=%d", c.inFlight, len(c.h2.waiting))
	}
}

func TestH2IdleCountsWaitingStreams(t *testing.T) {
	c := &epollConn{fd: 1, protocol: plainConnProtoH2}
	if !c.idle() {
		t.Fatal("fixture connection is not idle")
	}
	c.h2.waiting = []*H2Stream{{}}
	if c.idle() {
		t.Fatal("a connection with a waiting stream reports idle")
	}
}

func TestH2InitReleasesWaitingStreams(t *testing.T) {
	var st tlsWorkerH2State
	stream := StreamPool.Get().(*H2Stream)
	stream.Reset()
	stream.ID = 7
	st.waiting = append(st.waiting, stream)
	st.init(H2HeaderTableSize, H2MaxHeaderListSize)
	if len(st.waiting) != 0 || stream.ID != 0 {
		t.Fatalf("init kept %d waiting streams; released stream ID %d", len(st.waiting), stream.ID)
	}
}
