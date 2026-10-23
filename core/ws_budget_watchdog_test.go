//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	wsBudgetLimit      = 4096
	wsBudgetSettle     = 50 * time.Millisecond
	wsBudgetStallLimit = 2 * time.Second
)

type wsProbe struct {
	mu          sync.Mutex
	events      []string
	messages    [][]byte
	mismatches  int
	overlaps    int
	running     atomic.Int32
	entered     chan struct{}
	release     chan struct{}
	blockFirst  int
	closeInside bool
	calls       atomic.Int32
	closes      atomic.Int32
	heldInside  atomic.Int64
	srv         *Server
	lastLetter  map[*WSConn]string
}

func newWSProbe(blockFirst int) *wsProbe {
	return &wsProbe{entered: make(chan struct{}, 16), release: make(chan struct{}), blockFirst: blockFirst, lastLetter: map[*WSConn]string{}}
}

func (p *wsProbe) record(event string) {
	p.mu.Lock()
	p.events = append(p.events, event)
	p.mu.Unlock()
}

func (p *wsProbe) snapshotEvents() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.events...)
}

func (p *wsProbe) handler() WSEventHandler {
	return WSEventHandler{
		OnMessage: func(ws *WSConn, op byte, msg []byte) {
			if p.running.Add(1) > 1 {
				p.mu.Lock()
				p.overlaps++
				p.mu.Unlock()
			}
			defer p.running.Add(-1)
			call := int(p.calls.Add(1))
			want := bytes.Clone(msg)
			letter := string(want[:min(len(want), 1)])
			p.mu.Lock()
			p.lastLetter[ws] = letter
			p.mu.Unlock()
			p.record("message:" + letter)
			if p.srv != nil {
				p.heldInside.Store(p.srv.inFlightBodyBytes.Load())
			}
			if call <= p.blockFirst {
				if p.closeInside {
					_ = ws.Close()
				}
				p.entered <- struct{}{}
				<-p.release
			}
			p.mu.Lock()
			if !bytes.Equal(msg, want) {
				p.mismatches++
			}
			p.messages = append(p.messages, want)
			p.mu.Unlock()
			_ = ws.WriteMessage(op, msg)
			p.record("returned:" + letter)
		},
		OnClose: func(ws *WSConn, code uint16) {
			p.closes.Add(1)
			p.mu.Lock()
			letter := p.lastLetter[ws]
			p.mu.Unlock()
			p.record("close:" + letter)
		},
	}
}

func (p *wsProbe) awaitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-p.entered:
	case <-time.After(wsBudgetStallLimit):
		t.Fatal("OnMessage was not entered")
	}
}

func wsProbeServer(t *testing.T, useTLS bool, probe *wsProbe, opts WSUpgradeOptions, cfgFn func(*Config)) *testServer {
	t.Helper()
	ts := newTestServer(t, testServerOptions{
		TLS: useTLS,
		Config: func(cfg *Config) {
			cfg.PlainHTTP = !useTLS
			cfg.WebSocketOriginMode = WSOriginOff
			if cfgFn != nil {
				cfgFn(cfg)
			}
		},
		Routes: func(r *Router) {
			r.GET("/probe", func(req *Request, resp *Response) {
				ServeWebSocketEvents(req, resp, opts, probe.handler())
			})
			r.GET("/plain", func(req *Request, resp *Response) {
				resp.Status(200).String("plain")
			})
		},
		Setup: func(s *Server) { probe.srv = s },
	})
	return ts
}

func wsAwaitInFlight(t *testing.T, srv *Server, what string, cond func(int64) bool) {
	t.Helper()
	deadline := turbo.Deadline(wsBudgetStallLimit)
	for turbo.Until(deadline) > 0 {
		if cond(srv.inFlightBodyBytes.Load()) {
			return
		}
		turbo.Sleep(harnessPollInterval)
	}
	t.Fatalf("%s: inFlightBodyBytes=%d", what, srv.inFlightBodyBytes.Load())
}

func wsPlainGet(t *testing.T, ts *testServer) string {
	t.Helper()
	c := ts.dial(t)
	_ = c.SetDeadline(wallDeadline(wsBudgetStallLimit))
	if _, err := c.Write([]byte("GET /plain HTTP/1.1\r\nHost: " + ts.domain + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("plain write: %v", err)
	}
	body, err := io.ReadAll(c)
	if err != nil && !bytes.Contains(body, []byte("plain")) {
		t.Fatalf("plain read: %v (got %q)", err, body)
	}
	return string(body)
}

func TestWSEventsPartialFragmentHoldsBudgetUntilTeardown(t *testing.T) {
	cases := []struct {
		name   string
		writes func() []byte
	}{
		{name: "whole-fragment", writes: func() []byte {
			return wsClientFrame(wsOpText, bytes.Repeat([]byte("f"), 1000))
		}},
		{name: "split-fragment", writes: func() []byte {
			return wsClientFrame(wsOpText, bytes.Repeat([]byte("s"), 3000))[:1500]
		}},
	}
	for _, tr := range perfTransports {
		for _, tc := range cases {
			t.Run(tr.name+"/"+tc.name, func(t *testing.T) {
				probe := newWSProbe(0)
				ts := wsProbeServer(t, tr.tls, probe, WSUpgradeOptions{}, nil)
				c, _, _ := wsEvDial(t, ts, "/probe")
				if _, err := c.Write(tc.writes()); err != nil {
					t.Fatal(err)
				}
				wsAwaitInFlight(t, ts.srv, "partial fragment must be reserved", func(n int64) bool { return n > 0 && n <= 3000 })
				_ = c.Close()
				waitFor(t, wsEvCloseWait, func() bool { return probe.closes.Load() == 1 })
				wsAwaitInFlight(t, ts.srv, "teardown must release the fragment", func(n int64) bool { return n == 0 })
				if probe.calls.Load() != 0 {
					t.Fatalf("OnMessage ran %d times for an unfinished message", probe.calls.Load())
				}
			})
		}
	}
}

func TestWSEventsBudgetExhaustedClosesTryAgainLater(t *testing.T) {
	cases := []struct {
		name   string
		opts   WSUpgradeOptions
		header []string
		frames func(t *testing.T) [][]byte
	}{
		{name: "fragments", frames: func(t *testing.T) [][]byte {
			return [][]byte{
				wsClientFrame(wsOpBinary, bytes.Repeat([]byte("a"), 3000)),
				wsClientFrame(0x80|wsOpContinuation, bytes.Repeat([]byte("b"), 3000)),
			}
		}},
		{name: "single-frame", frames: func(t *testing.T) [][]byte {
			return [][]byte{wsClientFrame(0x80|wsOpBinary, bytes.Repeat([]byte("c"), 6000))}
		}},
		{name: "inflated", opts: WSUpgradeOptions{Compression: true}, header: []string{wsEvExtraHeaderKey}, frames: func(t *testing.T) [][]byte {
			compressed := wsClientDeflate(t, bytes.Repeat([]byte("d"), 60000))
			if len(compressed) >= wsBudgetLimit/2 {
				t.Fatalf("compressed payload %d bytes is not below the budget", len(compressed))
			}
			return [][]byte{wsClientFrame(0x80|wsRSV1|wsOpBinary, compressed)}
		}},
	}
	for _, tr := range perfTransports {
		for _, tc := range cases {
			t.Run(tr.name+"/"+tc.name, func(t *testing.T) {
				probe := newWSProbe(0)
				ts := wsProbeServer(t, tr.tls, probe, tc.opts, func(cfg *Config) { cfg.MaxInFlightBodyBytes = wsBudgetLimit })
				c, br, _ := wsEvDial(t, ts, "/probe", tc.header...)
				for _, f := range tc.frames(t) {
					if _, err := c.Write(f); err != nil {
						t.Fatal(err)
					}
				}
				wsEvExpectClose(wsStatusTryAgainLater)(t, wsEvReadAll(br))
				waitFor(t, wsEvCloseWait, func() bool { return probe.closes.Load() == 1 })
				if probe.calls.Load() != 0 {
					t.Fatalf("OnMessage ran %d times for a message over the budget", probe.calls.Load())
				}
				wsAwaitInFlight(t, ts.srv, "budget must return to zero", func(n int64) bool { return n == 0 })
			})
		}
	}
}

func TestWSEventsCallbackHoldsBudgetUntilReturn(t *testing.T) {
	probe := newWSProbe(1)
	ts := wsProbeServer(t, false, probe, WSUpgradeOptions{}, nil)
	c, br, _ := wsEvDial(t, ts, "/probe")
	payload := bytes.Repeat([]byte("h"), 1000)
	if _, err := c.Write(wsClientFrame(0x80|wsOpText, payload)); err != nil {
		t.Fatal(err)
	}
	probe.awaitEntered(t)
	if held := probe.heldInside.Load(); held != int64(len(payload)) {
		t.Fatalf("budget during OnMessage = %d, want %d", held, len(payload))
	}
	close(probe.release)
	if f, err := wsReadServerFrame(br); err != nil || !bytes.Equal(f.payload, payload) {
		t.Fatalf("echo len %d err %v", len(f.payload), err)
	}
	wsAwaitInFlight(t, ts.srv, "budget must return after OnMessage", func(n int64) bool { return n == 0 })
}

func TestWSEventsBlockedCallbackDoesNotStallWorker(t *testing.T) {
	for _, tr := range perfTransports {
		t.Run(tr.name, func(t *testing.T) {
			probe := newWSProbe(2)
			ts := wsProbeServer(t, tr.tls, probe, WSUpgradeOptions{}, func(cfg *Config) {
				cfg.Listeners = 1
				cfg.DisableInlineHandlers = true
			})
			c, br, _ := wsEvDial(t, ts, "/probe")
			handoffs := inlineHandoffs.Load()
			for round := 0; round < 2; round++ {
				if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte{byte('0' + round)})); err != nil {
					t.Fatal(err)
				}
				probe.awaitEntered(t)
				if body := wsPlainGet(t, ts); !bytes.Contains([]byte(body), []byte("plain")) {
					t.Fatalf("round %d: worker stalled behind a blocked OnMessage: %q", round, body)
				}
				probe.release <- struct{}{}
				if f, err := wsReadServerFrame(br); err != nil || len(f.payload) != 1 || f.payload[0] != byte('0'+round) {
					t.Fatalf("round %d: echo %q err %v", round, f.payload, err)
				}
			}
			if got := inlineHandoffs.Load() - handoffs; got != 1 {
				t.Fatalf("handoffs = %d, want 1 (later callbacks of a demoted handler run on the pool)", got)
			}
		})
	}
}

func TestWSEventsPendingCallbackPausesParsing(t *testing.T) {
	for _, tr := range perfTransports {
		t.Run(tr.name, func(t *testing.T) {
			probe := newWSProbe(1)
			ts := wsProbeServer(t, tr.tls, probe, WSUpgradeOptions{}, nil)
			c, br, _ := wsEvDial(t, ts, "/probe")
			first := bytes.Repeat([]byte("A"), 1000)
			if _, err := c.Write(wsClientFrame(0x80|wsOpBinary, first)); err != nil {
				t.Fatal(err)
			}
			probe.awaitEntered(t)
			more := append(wsClientFrame(0x80|wsOpBinary, bytes.Repeat([]byte("B"), 1000)), wsClientFrame(0x80|wsOpBinary, bytes.Repeat([]byte("C"), 1000))...)
			if _, err := c.Write(more); err != nil {
				t.Fatal(err)
			}
			turbo.Sleep(wsBudgetSettle)
			if got := probe.calls.Load(); got != 1 {
				t.Fatalf("OnMessage calls while the first is pending = %d, want 1", got)
			}
			close(probe.release)
			for _, want := range []byte("ABC") {
				f, err := wsReadServerFrame(br)
				if err != nil || len(f.payload) != 1000 || f.payload[0] != want || f.payload[999] != want {
					t.Fatalf("echo for %c: len %d err %v", want, len(f.payload), err)
				}
			}
			probe.mu.Lock()
			defer probe.mu.Unlock()
			if probe.mismatches != 0 || probe.overlaps != 0 {
				t.Fatalf("mismatches %d overlaps %d", probe.mismatches, probe.overlaps)
			}
		})
	}
}

func TestWSEventsTeardownWhileCallbackPending(t *testing.T) {
	for _, tr := range perfTransports {
		t.Run(tr.name, func(t *testing.T) {
			probe := newWSProbe(1)
			probe.closeInside = true
			ts := wsProbeServer(t, tr.tls, probe, WSUpgradeOptions{}, nil)
			c, br, _ := wsEvDial(t, ts, "/probe")
			payload := bytes.Repeat([]byte("P"), 1000)
			if _, err := c.Write(wsClientFrame(0x80|wsOpBinary, payload)); err != nil {
				t.Fatal(err)
			}
			probe.awaitEntered(t)
			wsEvExpectBareClose(t, wsEvReadAll(br))
			_ = c.Close()
			waitFor(t, wsEvCloseWait, func() bool { return ts.srv.activeConns.Load() == 0 })
			other, otherBr, _ := wsEvDial(t, ts, "/probe")
			if _, err := other.Write(wsClientFrame(0x80|wsOpBinary, bytes.Repeat([]byte("Z"), 1000))); err != nil {
				t.Fatal(err)
			}
			turbo.Sleep(wsBudgetSettle)
			if probe.closes.Load() != 0 {
				t.Fatal("OnClose ran before the pending OnMessage returned")
			}
			if n := ts.srv.inFlightBodyBytes.Load(); n < int64(len(payload)) {
				t.Fatalf("budget released while OnMessage still holds the message: %d", n)
			}
			close(probe.release)
			if f, err := wsReadServerFrame(otherBr); err != nil || f.payload[0] != 'Z' {
				t.Fatalf("second conn echo err %v", err)
			}
			waitFor(t, wsEvCloseWait, func() bool { return probe.closes.Load() == 1 })
			_ = other.Close()
			waitFor(t, wsEvCloseWait, func() bool { return probe.closes.Load() == 2 })
			wsAwaitInFlight(t, ts.srv, "budget must return after teardown", func(n int64) bool { return n == 0 })
			events := probe.snapshotEvents()
			if wsEventIndex(events, "close:P") < wsEventIndex(events, "returned:P") || wsEventIndex(events, "returned:P") < 0 {
				t.Fatalf("OnClose must follow the pending OnMessage return: %v", events)
			}
			probe.mu.Lock()
			defer probe.mu.Unlock()
			if probe.mismatches != 0 {
				t.Fatalf("message changed under a pending callback after teardown: %d mismatches", probe.mismatches)
			}
		})
	}
}

func wsBudgetPipe(t *testing.T, opts WSUpgradeOptions, headers ...[2]string) (*wsPipe, *Server) {
	t.Helper()
	srv := New(Config{MaxInFlightBodyBytes: wsBudgetLimit})
	p := newWSPipe(t, opts, headers...)
	p.server.server = srv
	return p, srv
}

func TestWSReadMessageReservesFragmentsAndCloses1013(t *testing.T) {
	p, srv := wsBudgetPipe(t, WSUpgradeOptions{})
	frames := p.collectServerFrames()
	result := make(chan error, 1)
	go func() {
		_, _, err := p.server.ReadMessage()
		result <- err
	}()
	if _, err := p.client.Write(wsClientFrame(wsOpBinary, bytes.Repeat([]byte("a"), 3000))); err != nil {
		t.Fatal(err)
	}
	wsAwaitInFlight(t, srv, "goroutine reader must reserve the partial message", func(n int64) bool { return n == 3000 })
	go func() { _, _ = p.client.Write(wsClientFrame(0x80|wsOpContinuation, bytes.Repeat([]byte("b"), 3000))) }()
	if err := <-result; err == nil {
		t.Fatal("ReadMessage accepted a message over the budget")
	}
	got := <-frames
	if len(got) == 0 || wsCloseCode(got[len(got)-1]) != wsStatusTryAgainLater {
		t.Fatalf("server frames %s, want close 1013", wsEvDescribe(got))
	}
	if n := srv.inFlightBodyBytes.Load(); n != 0 {
		t.Fatalf("budget after ReadMessage error = %d", n)
	}
}

func TestWSReadMessageInflatedOverBudgetCloses1013(t *testing.T) {
	p, srv := wsBudgetPipe(t, WSUpgradeOptions{Compression: true}, wsDeflateOffer)
	frames := p.collectServerFrames()
	compressed := wsClientDeflate(t, bytes.Repeat([]byte("d"), 60000))
	p.send(t, wsClientFrame(0x80|wsRSV1|wsOpBinary, compressed))
	if _, _, err := p.server.ReadMessage(); err == nil {
		t.Fatal("ReadMessage accepted an inflated message over the budget")
	}
	got := <-frames
	if len(got) == 0 || wsCloseCode(got[len(got)-1]) != wsStatusTryAgainLater {
		t.Fatalf("server frames %s, want close 1013", wsEvDescribe(got))
	}
	if n := srv.inFlightBodyBytes.Load(); n != 0 {
		t.Fatalf("budget after inflate failure = %d", n)
	}
}

func TestWSBlockingEventsHoldBudgetDuringCallback(t *testing.T) {
	p, srv := wsBudgetPipe(t, WSUpgradeOptions{})
	payload := bytes.Repeat([]byte("e"), 1000)
	var held atomic.Int64
	called := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		serveWSEventsBlocking(srv, p.server, WSEventHandler{OnMessage: func(ws *WSConn, op byte, msg []byte) {
			held.Store(srv.inFlightBodyBytes.Load())
			called <- struct{}{}
		}})
		close(done)
	}()
	p.send(t, wsClientFrame(0x80|wsOpBinary, payload))
	<-called
	if got := held.Load(); got != int64(len(payload)) {
		t.Fatalf("budget during blocking OnMessage = %d, want %d", got, len(payload))
	}
	wsAwaitInFlight(t, srv, "blocking reader must release after the callback", func(n int64) bool { return n == 0 })
	_ = p.client.Close()
	<-done
	if n := srv.inFlightBodyBytes.Load(); n != 0 {
		t.Fatalf("budget after close = %d", n)
	}
}

func wsEventIndex(events []string, want string) int {
	for i, e := range events {
		if e == want {
			return i
		}
	}
	return -1
}

func TestWSEventsTCPHalfCloseDuringCallbackKeepsReply(t *testing.T) {
	probe := newWSProbe(1)
	ts := wsProbeServer(t, false, probe, WSUpgradeOptions{}, nil)
	c, br, _ := wsEvDial(t, ts, "/probe")
	payload := bytes.Repeat([]byte("H"), 1000)
	if _, err := c.Write(wsClientFrame(0x80|wsOpBinary, payload)); err != nil {
		t.Fatal(err)
	}
	probe.awaitEntered(t)
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	turbo.Sleep(wsBudgetSettle)
	close(probe.release)
	f, err := wsReadServerFrame(br)
	if err != nil || !bytes.Equal(f.payload, payload) {
		t.Fatalf("reply after half-close: len %d err %v", len(f.payload), err)
	}
	waitFor(t, wsEvCloseWait, func() bool { return probe.closes.Load() == 1 })
	wsAwaitInFlight(t, ts.srv, "budget must return after close", func(n int64) bool { return n == 0 })
}

func TestWSEventsSlowCallbackOutlivesReadTimeout(t *testing.T) {
	const sweepInterval = time.Duration(epollSweepIntervalMs) * time.Millisecond
	const readTimeout = sweepInterval + sweepInterval/5
	const callbackHold = sweepInterval + readTimeout + sweepInterval/4
	probe := newWSProbe(1)
	ts := wsProbeServer(t, false, probe, WSUpgradeOptions{}, func(cfg *Config) { cfg.WSReadTimeout = readTimeout })
	c, br, _ := wsEvDial(t, ts, "/probe")
	_ = c.SetDeadline(wallDeadline(callbackHold + readTimeout + sweepInterval + wsEvCloseWait))
	payload := bytes.Repeat([]byte("T"), 100)
	if _, err := c.Write(wsClientFrame(0x80|wsOpBinary, payload)); err != nil {
		t.Fatal(err)
	}
	probe.awaitEntered(t)
	turbo.Sleep(callbackHold)
	if probe.closes.Load() != 0 {
		t.Fatal("the read timeout closed the connection while OnMessage was running")
	}
	close(probe.release)
	f, err := wsReadServerFrame(br)
	if err != nil || !bytes.Equal(f.payload, payload) {
		t.Fatalf("reply after slow callback: op %#x len %d err %v", f.opcode(), len(f.payload), err)
	}
	start := turbo.Now()
	wsEvExpectBareClose(t, wsEvReadAll(br))
	if el := turbo.Since(start); el < readTimeout-epollDeadlineSlack {
		t.Fatalf("closed %v after the reply, before a fresh %v read timeout", el, readTimeout)
	}
}

func TestWSEventsShutdownWaitsForPendingCallback(t *testing.T) {
	probe := newWSProbe(1)
	ts := wsProbeServer(t, false, probe, WSUpgradeOptions{}, nil)
	c, _, _ := wsEvDial(t, ts, "/probe")
	if _, err := c.Write(wsClientFrame(0x80|wsOpBinary, []byte("S"))); err != nil {
		t.Fatal(err)
	}
	probe.awaitEntered(t)
	stopped := make(chan struct{})
	go func() {
		stopServer(ts.srv)
		close(stopped)
	}()
	_ = c.Close()
	turbo.Sleep(wsBudgetSettle)
	if probe.closes.Load() != 0 {
		t.Fatal("OnClose ran before the pending OnMessage returned")
	}
	close(probe.release)
	waitFor(t, wsEvCloseWait, func() bool { return probe.closes.Load() == 1 })
	<-stopped
	wsAwaitInFlight(t, ts.srv, "budget must return after shutdown", func(n int64) bool { return n == 0 })
}

func TestWSBlockingEventsControlFramesHoldNoBudget(t *testing.T) {
	p, srv := wsBudgetPipe(t, WSUpgradeOptions{})
	payload := bytes.Repeat([]byte("m"), 100)
	var held atomic.Int64
	called := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		serveWSEventsBlocking(srv, p.server, WSEventHandler{OnMessage: func(ws *WSConn, op byte, msg []byte) {
			held.Store(srv.inFlightBodyBytes.Load())
			called <- struct{}{}
		}})
		close(done)
	}()
	pong := wsClientFrame(0x80|wsOpPong, bytes.Repeat([]byte("p"), wsMaxControlPayload))
	frames := bytes.Repeat(pong, 40)
	frames = append(frames, wsClientFrame(0x80|wsOpBinary, payload)...)
	p.send(t, frames)
	select {
	case <-called:
	case <-time.After(wsBudgetStallLimit):
		t.Fatal("OnMessage was not called after 40 pongs")
	}
	if got := held.Load(); got != int64(len(payload)) {
		t.Fatalf("budget during OnMessage after 40 pongs = %d, want %d", got, len(payload))
	}
	_ = p.client.Close()
	<-done
}

func TestWSBlockingEventsReleaseOnDisconnectMidFragment(t *testing.T) {
	p, srv := wsBudgetPipe(t, WSUpgradeOptions{})
	done := make(chan struct{})
	go func() {
		serveWSEventsBlocking(srv, p.server, WSEventHandler{})
		close(done)
	}()
	p.send(t, wsClientFrame(wsOpBinary, bytes.Repeat([]byte("q"), 1000)))
	wsAwaitInFlight(t, srv, "partial fragment must be reserved", func(n int64) bool { return n == 1000 })
	_ = p.client.Close()
	<-done
	if n := srv.inFlightBodyBytes.Load(); n != 0 {
		t.Fatalf("budget after disconnect mid-fragment = %d", n)
	}
}

func TestWSEventsSplitControlFrameHoldsNoBudget(t *testing.T) {
	probe := newWSProbe(0)
	ts := wsProbeServer(t, false, probe, WSUpgradeOptions{}, nil)
	c, br, _ := wsEvDial(t, ts, "/probe")
	ping := wsClientFrame(0x80|wsOpPing, bytes.Repeat([]byte("i"), 100))
	if _, err := c.Write(ping[:20]); err != nil {
		t.Fatal(err)
	}
	turbo.Sleep(wsBudgetSettle)
	if _, err := c.Write(ping[20:]); err != nil {
		t.Fatal(err)
	}
	if f, err := wsReadServerFrame(br); err != nil || f.opcode() != wsOpPong || len(f.payload) != 100 {
		t.Fatalf("pong op %#x len %d err %v", f.opcode(), len(f.payload), err)
	}
	if n := ts.srv.inFlightBodyBytes.Load(); n != 0 {
		t.Fatalf("a split ping holds %d budget bytes", n)
	}
}

func TestWSEventsTLSCloseNotifyDuringCallbackKeepsReply(t *testing.T) {
	probe := newWSProbe(1)
	ts := wsProbeServer(t, true, probe, WSUpgradeOptions{}, nil)
	c, br, _ := wsEvDial(t, ts, "/probe")
	payload := bytes.Repeat([]byte("N"), 1000)
	if _, err := c.Write(wsClientFrame(0x80|wsOpBinary, payload)); err != nil {
		t.Fatal(err)
	}
	probe.awaitEntered(t)
	if err := c.(*tls.Conn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	turbo.Sleep(wsBudgetSettle)
	if probe.closes.Load() != 0 {
		t.Fatal("close_notify tore the connection down while OnMessage was pending")
	}
	close(probe.release)
	f, err := wsReadServerFrame(br)
	if err != nil || !bytes.Equal(f.payload, payload) {
		t.Fatalf("reply after close_notify: len %d err %v", len(f.payload), err)
	}
	waitFor(t, wsEvCloseWait, func() bool { return probe.closes.Load() == 1 })
	wsAwaitInFlight(t, ts.srv, "budget must return after close", func(n int64) bool { return n == 0 })
}

func TestWSEventsHandedOffCallbackWritesStayFramed(t *testing.T) {
	const writesPerSide = 200
	const frameSize = 8 << 10
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	ts := newTestServer(t, testServerOptions{
		Config: func(cfg *Config) { cfg.PlainHTTP = true; cfg.WebSocketOriginMode = WSOriginOff },
		Routes: func(r *Router) {
			r.GET("/probe", func(req *Request, resp *Response) {
				ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, WSEventHandler{
					OnMessage: func(ws *WSConn, op byte, msg []byte) {
						entered <- struct{}{}
						<-release
						other := make(chan struct{})
						go func() {
							defer close(other)
							side := bytes.Repeat([]byte("G"), frameSize)
							for range writesPerSide {
								if ws.WriteMessage(wsOpBinary, side) != nil {
									return
								}
							}
						}()
						own := bytes.Repeat([]byte("C"), frameSize)
						for range writesPerSide {
							if ws.WriteMessage(wsOpBinary, own) != nil {
								break
							}
						}
						<-other
					},
				})
			})
		},
	})
	c, br, _ := wsEvDial(t, ts, "/probe")
	_ = c.SetDeadline(wallDeadline(4 * wsEvCloseWait))
	handoffs := inlineHandoffs.Load()
	if _, err := c.Write(wsClientFrame(0x80|wsOpBinary, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	<-entered
	waitFor(t, wsBudgetStallLimit, func() bool { return inlineHandoffs.Load() != handoffs })
	close(release)
	counts := map[byte]int{}
	for i := 0; i < 2*writesPerSide; i++ {
		f, err := wsReadServerFrame(br)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if f.first != 0x80|wsOpBinary || len(f.payload) != frameSize || bytes.Count(f.payload, f.payload[:1]) != frameSize {
			t.Fatalf("frame %d corrupt: first %#x len %d", i, f.first, len(f.payload))
		}
		counts[f.payload[0]]++
	}
	if counts['C'] != writesPerSide || counts['G'] != writesPerSide {
		t.Fatalf("frame counts %v", counts)
	}
}

func wsDirectState(ev *wsLoopConn) bool {
	ev.mu.Lock()
	defer ev.mu.Unlock()
	return ev.direct
}

func TestWSDirectSendOffForDemotedCallback(t *testing.T) {
	srv := New(Config{})
	w := &epollWorker{server: srv, handlers: newHandlerPool(1)}
	t.Cleanup(w.handlers.close)
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	ev := &wsLoopConn{w: w, h: WSEventHandler{OnMessage: func(ws *WSConn, op byte, msg []byte) {
		entered <- struct{}{}
		<-release
	}}}
	ev.ws = &WSConn{ev: ev}
	srv.Router.demoteInline(ev.callbackIdentity(wsCallbackMessage), false)
	ev.direct = true
	w.queueWSCallback(ev, wsCallbackMessage)
	<-entered
	directWhileRunning := wsDirectState(ev)
	close(release)
	if directWhileRunning {
		t.Fatal("a demoted pool callback runs with direct send on")
	}
}

func TestWSDirectSendOffWhileCallbackPending(t *testing.T) {
	c := &epollConn{fd: -1}
	ev := &wsLoopConn{c: c}
	ev.takeOutbox(c, nil, false)
	if !wsDirectState(ev) {
		t.Fatal("control: direct send must be on for an idle conn with nothing pending")
	}
	ev.cbPending = true
	ev.takeOutbox(c, nil, false)
	if wsDirectState(ev) {
		t.Fatal("takeOutbox turned direct send on while a callback is pending")
	}
}

func TestWSRevokeLoopTurnsDirectSendOff(t *testing.T) {
	ev := &wsLoopConn{holding: true, direct: true}
	ev.revokeLoop()
	ev.mu.Lock()
	defer ev.mu.Unlock()
	if ev.direct || ev.holding {
		t.Fatalf("after revoke: direct=%v holding=%v", ev.direct, ev.holding)
	}
}
