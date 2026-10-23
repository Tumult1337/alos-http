//go:build linux && amd64

package core

import (
	"encoding/binary"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	h2AdmitBodyBudget    = 4 << 20
	h2AdmitBodyStreams   = 16
	h2AdmitBodyPerStream = 1 << 20
	h2AdmitBodyFrame     = H2DefaultMaxFrameSize
	h2AdmitStallPending  = 1 << 20
	h2AdmitStallRequests = 20
)

func h2AdmitSendBody(rc *h2RawConn, streamID uint32, size int, endStream bool) {
	chunk := h2FixBody(h2AdmitBodyFrame)
	for sent := 0; sent < size; sent += h2AdmitBodyFrame {
		n := min(h2AdmitBodyFrame, size-sent)
		flags := byte(0)
		if endStream && sent+n == size {
			flags = H2FlagEndStream
		}
		rc.write(H2FrameData, flags, streamID, chunk[:n])
	}
}

func h2AdmitStallConn(t *testing.T, rc *h2RawConn, srv *Server) uint32 {
	t.Helper()
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(h2FixMaxWindow-H2DefaultWindowSize))
	for i := range h2AdmitStallRequests {
		h2FixGet(rc, uint32(2*i+1), "/big")
	}
	var state h2AdmissionState
	if !h2FixPollUntil(func() bool {
		state = h2AdmissionProbe(t, srv)
		return state.parked+state.sending >= h2AdmitStallPending
	}) {
		t.Fatalf("connection did not stall: %+v", state)
	}
	return uint32(2*h2AdmitStallRequests + 1)
}

func h2AdmitBigRoute(srv *Server) {
	big := h2FixBody(h2FixBigBody)
	srv.Router.GET("/big", func(req *Request, resp *Response) { resp.Status(200).Bytes(big) })
}

func TestH2AdmissionWaitingTunnelBodiesStayInBodyBudget(t *testing.T) {
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.MaxInFlightBodyBytes = h2AdmitBodyBudget
		c.MaxPendingWriteBytes = h2AdmitStallPending
	}, h2AdmitBigRoute)
	rc := h2RawDialRecvBuf(t, addr, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), h2FixMaxWindow}), perfH2ParkReadBuffer)
	_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
	first := h2AdmitStallConn(t, rc, srv)
	sampler := startH2BudgetSampler(srv, h2ConnBodyCounter(t, srv))
	for i := range h2AdmitBodyStreams {
		id := first + uint32(2*i)
		rc.write(H2FrameHeaders, H2FlagEndHeaders, id, hpackBlock(
			[2]string{":method", "CONNECT"}, [2]string{":protocol", "websocket"}, [2]string{":scheme", "http"},
			[2]string{":path", "/ws"}, [2]string{":authority", h2FixAuthority}, [2]string{"sec-websocket-version", "13"}))
		h2AdmitSendBody(rc, id, h2AdmitBodyPerStream, false)
	}
	var state h2AdmissionState
	h2FixPollUntil(func() bool {
		state = h2AdmissionProbe(t, srv)
		return state.held >= h2AdmitBodyStreams*h2AdmitBodyPerStream
	})
	if state.waiting == 0 || state.orphans != 0 {
		t.Fatalf("waiting tunnel streams %d, of them %d with an aborted body still queued", state.waiting, state.orphans)
	}
	if state.held > h2AdmitBodyBudget || srv.inFlightBodyBytes.Load() > h2AdmitBodyBudget {
		t.Fatalf("waiting streams hold %d body bytes, budget counts %d, MaxInFlightBodyBytes %d",
			state.held, srv.inFlightBodyBytes.Load(), h2AdmitBodyBudget)
	}
	if int64(state.held) != srv.inFlightBodyBytes.Load() {
		t.Fatalf("held %d body bytes but the budget counts %d", state.held, srv.inFlightBodyBytes.Load())
	}
	if peakServer, peakConn := sampler.finish(); peakServer > h2AdmitBodyBudget || peakConn > h2AdmitBodyBudget {
		t.Fatalf("body counters peaked at server %d and connection %d, MaxInFlightBodyBytes %d", peakServer, peakConn, h2AdmitBodyBudget)
	}
}

func TestH2AdmissionStreamedBodyBudgetReleasesOnRead(t *testing.T) {
	const total = 3 * h2AdmitBodyBudget
	const step = h2AdmitBodyPerStream / 4
	var got atomic.Int64
	addr, srv := startH2FixServerWith(t, func(c *Config) {
		c.MaxInFlightBodyBytes = h2AdmitBodyBudget
		c.StreamBodyAbove = 1
		c.MaxBodySize = 2 * total
	}, func(srv *Server) {
		srv.Router.POST("/read", func(req *Request, resp *Response) {
			buf := make([]byte, h2AdmitBodyFrame)
			for {
				n, err := req.BodyStream().Read(buf)
				got.Add(int64(n))
				if err != nil {
					break
				}
			}
			resp.Status(200).String(strconv.FormatInt(got.Load(), 10))
		})
	})
	rc := h2RawDial(t, addr, h2FixSettings())
	_ = rc.conn.SetDeadline(wallDeadline(h2AdmitBurstDeadline))
	rc.write(H2FrameHeaders, H2FlagEndHeaders, 1, hpackBlock(
		[2]string{":method", "POST"}, [2]string{":scheme", "http"},
		[2]string{":path", "/read"}, [2]string{":authority", h2FixAuthority}))
	conn := rc.conn
	sender, stop := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sender)
		chunk := h2FixBody(h2AdmitBodyFrame)
		for sent := 0; sent < total; sent += h2AdmitBodyFrame {
			for got.Load() < int64(sent-step) {
				select {
				case <-stop:
					return
				case <-turbo.After(time.Millisecond):
				}
			}
			flags := byte(0)
			if sent+h2AdmitBodyFrame >= total {
				flags = H2FlagEndStream
			}
			if _, err := conn.Write(appendH2Frame(nil, H2FrameData, flags, 1, chunk)); err != nil {
				return
			}
		}
	}()
	body := rc.h2AdmitCollectAcceptingUpdates(t, 1)
	close(stop)
	<-sender
	if want := strconv.Itoa(total); body != want {
		t.Fatalf("reading handler got %q bytes, want %s", body, want)
	}
	if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
		t.Fatalf("read body still holds %d budget bytes", srv.inFlightBodyBytes.Load())
	}
}

func (rc *h2RawConn) h2AdmitCollectAcceptingUpdates(t *testing.T, streamID uint32) string {
	t.Helper()
	body := ""
	for {
		f, err := rc.tryRead()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch {
		case f.typ == H2FrameGoAway:
			t.Fatalf("GOAWAY code %d", binary.BigEndian.Uint32(f.payload[4:8]))
		case f.typ == H2FrameRSTStream && f.streamID == streamID:
			t.Fatalf("server reset stream %d with code %d", streamID, binary.BigEndian.Uint32(f.payload))
		case f.typ == H2FrameData && f.streamID == streamID:
			body += string(f.payload)
			if f.flags&H2FlagEndStream != 0 {
				return body
			}
		}
	}
}

func TestH2AdmissionServerResetOfWaitingStreamDropsIt(t *testing.T) {
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
	rc.write(H2FrameHeaders, H2FlagEndHeaders, 3, hpackBlock(
		[2]string{":method", "POST"}, [2]string{":scheme", "http"}, [2]string{":path", "/echo"},
		[2]string{":authority", h2FixAuthority}, [2]string{"content-length", "10"}))
	if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).waiting == 1 }) {
		t.Fatal("stream 3 did not wait")
	}
	rc.write(H2FrameData, 0, 3, h2FixBody(20))
	f, err := rc.awaitStreamOutcome(3)
	if err != nil || f.typ != H2FrameRSTStream {
		t.Fatalf("oversized body: frame %+v err %v, want RST_STREAM", f.typ, err)
	}
	if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).waiting == 0 }) {
		t.Fatal("server reset stream 3 but it still waits")
	}
	b.open()
	rc.h2AdmitCollect(t, map[uint32]bool{1: true}, 3)
	for _, f := range rc.framesWithin(h2FixQuietWindow) {
		if f.streamID == 3 {
			t.Fatalf("server sent frame type %d on stream 3 after it reset it", f.typ)
		}
	}
}

func TestH2AdmissionResetOfStalledSendingStreamAdmitsWaiting(t *testing.T) {
	const pending = 64 << 10
	body := h2FixBody(pending)
	addr, srv := startH2FixServerWith(t, func(c *Config) { c.MaxPendingWriteBytes = pending }, func(srv *Server) {
		srv.Router.GET("/stall", func(req *Request, resp *Response) { resp.Status(200).Bytes(body) })
		srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	})
	rc := h2RawDial(t, addr, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0}))
	h2FixGet(rc, 1, "/stall")
	var st h2AdmissionState
	if !h2FixPollUntil(func() bool { st = h2AdmissionProbe(t, srv); return st.sending == pending }) {
		t.Fatalf("stream 1 not window-stalled: %+v", st)
	}
	h2FixGet(rc, 3, "/ok")
	if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).waiting == 1 }) {
		t.Fatalf("stream 3 did not wait: %+v", h2AdmissionProbe(t, srv))
	}
	rc.write(H2FrameRSTStream, 0, 1, rstPayload(H2ErrCancel))
	rc.write(H2FrameWindowUpdate, 0, 3, h2FixWindowIncrement(16))
	if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).waiting == 0 }) {
		t.Fatalf("reset of the stalled stream freed the pending budget but stream 3 still waits: %+v", h2AdmissionProbe(t, srv))
	}
}

func TestH2AdmissionHeadersOnWaitingStreamIsConnectionError(t *testing.T) {
	b := newH2AdmitBlocker(t)
	addr, srv := startH2FixServerWith(t, func(c *Config) { c.H2MaxRunningHandlers = 1 }, b.routes)
	rc := h2RawDial(t, addr, h2FixSettings())
	h2FixGet(rc, 1, "/block")
	if !h2FixPollUntil(func() bool { return b.running.Load() == 1 }) {
		t.Fatal("blocking handler never started")
	}
	h2FixGet(rc, 3, "/ok")
	if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).waiting == 1 }) {
		t.Fatal("stream 3 did not wait")
	}
	h2FixGet(rc, 3, "/ok")
	code, err := rc.awaitGoAway()
	if err != nil || code != H2ErrProtocol {
		t.Fatalf("second HEADERS on a waiting stream: GOAWAY code %d err %v, want PROTOCOL_ERROR", code, err)
	}
}

func TestH2AdmissionConnectionErrorStartsNoWaitingHandler(t *testing.T) {
	var late atomic.Int64
	addr, srv := startH2FixServerWith(t, func(c *Config) { c.MaxPendingWriteBytes = h2AdmitStallPending }, func(srv *Server) {
		h2AdmitBigRoute(srv)
		srv.Router.GET("/late", func(req *Request, resp *Response) {
			late.Add(1)
			resp.Status(200).String("late")
		})
	})
	rc := h2RawDialRecvBuf(t, addr, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), h2FixMaxWindow}), perfH2ParkReadBuffer)
	next := h2AdmitStallConn(t, rc, srv)
	h2FixGet(rc, next, "/late")
	if !h2FixPollUntil(func() bool { return h2AdmissionProbe(t, srv).waiting > 0 }) {
		t.Fatal("no stream waits behind the stalled connection")
	}
	rc.write(H2FramePing, 0, 1, make([]byte, 8))
	_ = rc.conn.SetReadDeadline(wallDeadline(h2AdmitBurstDeadline))
	goAway := false
	for {
		f, err := rc.tryRead()
		if err != nil {
			break
		}
		goAway = goAway || f.typ == H2FrameGoAway
	}
	if !goAway {
		t.Fatal("PING on a stream did not end the connection with GOAWAY")
	}
	turbo.Sleep(h2FixQuietWindow)
	if got := late.Load(); got != 0 {
		t.Fatalf("server started %d waiting handlers after a connection error", got)
	}
}

func TestH2AdmissionAbortReleasesUnreadStreamedBody(t *testing.T) {
	ends := map[string]func(rc *h2RawConn){
		"peer reset":       func(rc *h2RawConn) { rc.write(H2FrameRSTStream, 0, 1, rstPayload(H2ErrCancel)) },
		"connection close": func(rc *h2RawConn) { _ = rc.conn.Close() },
	}
	for name, end := range ends {
		t.Run(name, func(t *testing.T) {
			b := newH2AdmitBlocker(t)
			addr, srv := startH2FixServerWith(t, func(c *Config) {
				c.MaxInFlightBodyBytes = h2AdmitBodyBudget
				c.StreamBodyAbove = 1
			}, func(srv *Server) { srv.Router.POST("/sink", b.handle) })
			rc := h2RawDial(t, addr, h2FixSettings())
			rc.write(H2FrameHeaders, H2FlagEndHeaders, 1, hpackBlock(
				[2]string{":method", "POST"}, [2]string{":scheme", "http"},
				[2]string{":path", "/sink"}, [2]string{":authority", h2FixAuthority}))
			h2AdmitSendBody(rc, 1, h2AdmitBodyPerStream, false)
			if !h2FixPollUntil(func() bool {
				return srv.inFlightBodyBytes.Load() == h2AdmitBodyPerStream && b.running.Load() == 1 && h2AdmissionProbe(t, srv).held == h2AdmitBodyPerStream
			}) {
				t.Fatalf("running upload holds %d budget bytes, want %d", srv.inFlightBodyBytes.Load(), h2AdmitBodyPerStream)
			}
			end(rc)
			if !h2FixPollUntil(func() bool { return srv.inFlightBodyBytes.Load() == 0 }) {
				t.Fatalf("aborted body still holds %d budget bytes while the handler runs", srv.inFlightBodyBytes.Load())
			}
			if b.running.Load() != 1 {
				t.Fatal("handler returned; the test needs it to keep running")
			}
		})
	}
}
