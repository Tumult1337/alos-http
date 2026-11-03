//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	wsEvSplitPause     = 20 * time.Millisecond
	wsEvSmallMax       = 1024
	wsEvCloseWait      = 3 * time.Second
	wsEvShortTimeout   = 150 * time.Millisecond
	wsEvOffLoopCount   = 200
	wsEvBulkChunk      = 64 << 10
	wsEvBulkChunks     = 64
	wsEvFloodChunks    = 112
	wsEvExtraHeaderKey = "Sec-WebSocket-Extensions: permessage-deflate"
)

type wsEvProfile struct {
	name    string
	opts    WSUpgradeOptions
	headers []string
}

var wsEvProfiles = []wsEvProfile{
	{name: "default"},
	{name: "deflate", opts: WSUpgradeOptions{Compression: true}, headers: []string{wsEvExtraHeaderKey}},
	{name: "small", opts: WSUpgradeOptions{MaxMessageSize: wsEvSmallMax}},
}

type wsEvCloseLog struct {
	mu    sync.Mutex
	codes []uint16
}

func (l *wsEvCloseLog) add(code uint16) {
	l.mu.Lock()
	l.codes = append(l.codes, code)
	l.mu.Unlock()
}

func (l *wsEvCloseLog) snapshot() []uint16 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]uint16(nil), l.codes...)
}

func wsEvEchoBlocking(ws *WSConn) {
	for {
		op, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if ws.WriteMessage(op, msg) != nil {
			return
		}
	}
}

func wsEvEchoHandler(log *wsEvCloseLog) WSEventHandler {
	return WSEventHandler{
		OnMessage: func(ws *WSConn, op byte, msg []byte) { _ = ws.WriteMessage(op, msg) },
		OnClose:   func(ws *WSConn, code uint16) { log.add(code) },
	}
}

func wsEvStartServer(t testing.TB, useTLS bool, cfgFn func(*Config), log *wsEvCloseLog, extra func(*Router)) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		TLS: useTLS,
		Config: func(cfg *Config) {
			cfg.PlainHTTP = !useTLS
			if cfgFn != nil {
				cfgFn(cfg)
			}
		},
		Routes: func(r *Router) {
			for _, p := range wsEvProfiles {
				opts := p.opts
				r.GET("/blocking/"+p.name, func(req *Request, resp *Response) {
					ServeWebSocketWith(req, resp, opts, wsEvEchoBlocking)
				})
				r.GET("/events/"+p.name, func(req *Request, resp *Response) {
					ServeWebSocketEvents(req, resp, opts, wsEvEchoHandler(log))
				})
			}
			if extra != nil {
				extra(r)
			}
		},
	})
}

func wsEvUpgradeRequest(domain, path string, extra ...string) string {
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\nHost: " + domain + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + wsSampleKey + "\r\n")
	for _, h := range extra {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

func wsEvDial(t *testing.T, ts *testServer, path string, extra ...string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	c := ts.dial(t)
	_ = c.SetDeadline(wallDeadline(wsEvCloseWait))
	br := bufio.NewReader(c)
	if _, err := c.Write([]byte(wsEvUpgradeRequest(ts.domain, path, extra...))); err != nil {
		t.Fatalf("upgrade write: %v", err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("upgrade read: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", resp.StatusCode)
	}
	return c, br, resp
}

func wsEvReadAll(br *bufio.Reader) []wsServerFrame {
	var frames []wsServerFrame
	for {
		f, err := wsReadServerFrame(br)
		if err != nil {
			return frames
		}
		frames = append(frames, f)
	}
}

func wsEvRawFrame(first, second byte, mask bool, payload []byte) []byte {
	frame := []byte{first, second}
	if mask {
		frame[1] |= 0x80
		frame = append(frame, wsTestMaskKey[:]...)
	}
	start := len(frame)
	frame = append(frame, payload...)
	if mask {
		maskXOR(frame[start:], wsTestMaskKey)
	}
	return frame
}

func wsEvCloseFrame(code uint16, reason string) []byte {
	payload := binary.BigEndian.AppendUint16(nil, code)
	return wsClientFrame(0x80|wsOpClose, append(payload, reason...))
}

type wsEvScenario struct {
	name    string
	profile string
	writes  [][]byte
	split   bool
	check   func(t *testing.T, frames []wsServerFrame)
}

func wsEvExpectClose(code uint16) func(t *testing.T, frames []wsServerFrame) {
	return func(t *testing.T, frames []wsServerFrame) {
		t.Helper()
		if len(frames) == 0 {
			t.Fatal("no frames")
		}
		last := frames[len(frames)-1]
		if last.opcode() != wsOpClose || wsCloseCode(last) != code {
			t.Fatalf("last frame op %#x code %d, want close %d", last.opcode(), wsCloseCode(last), code)
		}
	}
}

func wsEvExpectBareClose(t *testing.T, frames []wsServerFrame) {
	t.Helper()
	if len(frames) == 0 {
		t.Fatal("no frames")
	}
	last := frames[len(frames)-1]
	if last.opcode() != wsOpClose || len(last.payload) != 0 {
		t.Fatalf("last frame op %#x payload %q, want bare close", last.opcode(), last.payload)
	}
}

func wsEvExpectEchoes(want ...string) func(t *testing.T, frames []wsServerFrame) {
	return func(t *testing.T, frames []wsServerFrame) {
		t.Helper()
		if len(frames) < len(want) {
			t.Fatalf("got %d frames, want at least %d", len(frames), len(want))
		}
		for i, w := range want {
			if string(frames[i].payload) != w {
				t.Fatalf("frame %d payload %q, want %q", i, frames[i].payload, w)
			}
		}
	}
}

func wsEvScenarios() []wsEvScenario {
	text := func(s string) []byte { return wsClientFrame(0x80|wsOpText, []byte(s)) }
	normalClose := wsEvCloseFrame(1000, "bye")
	big16k := strings.Repeat("b", 16<<10)
	big70k := strings.Repeat("c", 70000)
	compressible := strings.Repeat("deflate me please ", 40)
	return []wsEvScenario{
		{name: "text-echo", writes: [][]byte{text("hello"), normalClose}, check: wsEvExpectEchoes("hello")},
		{name: "empty-text", writes: [][]byte{text(""), normalClose}, check: wsEvExpectEchoes("")},
		{name: "binary-16k", writes: [][]byte{wsClientFrame(0x80|wsOpBinary, []byte(big16k)), normalClose}, check: wsEvExpectEchoes(big16k)},
		{name: "text-70k", writes: [][]byte{text(big70k), normalClose}, check: wsEvExpectEchoes(big70k)},
		{name: "pipelined", writes: [][]byte{bytes.Join([][]byte{text("a"), text("b"), text("c"), normalClose}, nil)}, check: wsEvExpectEchoes("a", "b", "c")},
		{name: "split-frame", split: true, writes: [][]byte{text("split")[:3], text("split")[3:], normalClose}, check: wsEvExpectEchoes("split")},
		{name: "split-large", split: true, writes: [][]byte{text(big16k)[:5000], text(big16k)[5000:], normalClose}, check: wsEvExpectEchoes(big16k)},
		{name: "fragmented-with-ping", writes: [][]byte{
			wsClientFrame(wsOpText, []byte("fr")),
			wsClientFrame(0x80|wsOpPing, []byte("p")),
			wsClientFrame(wsOpContinuation, []byte("ag")),
			wsClientFrame(0x80|wsOpContinuation, []byte("ment")),
			normalClose,
		}, check: wsEvExpectEchoes("p", "fragment")},
		{name: "ping-pong", writes: [][]byte{wsClientFrame(0x80|wsOpPing, []byte("hi")), normalClose}, check: wsEvExpectEchoes("hi")},
		{name: "pong-ignored", writes: [][]byte{wsClientFrame(0x80|wsOpPong, []byte("x")), text("after"), normalClose}, check: wsEvExpectEchoes("after")},
		{name: "close-normal", writes: [][]byte{normalClose}, check: wsEvExpectClose(1000)},
		{name: "close-empty", writes: [][]byte{wsClientFrame(0x80|wsOpClose, nil)}, check: wsEvExpectBareClose},
		{name: "close-one-byte", writes: [][]byte{wsClientFrame(0x80|wsOpClose, []byte{3})}, check: wsEvExpectClose(wsStatusProtocolError)},
		{name: "close-invalid-code", writes: [][]byte{wsEvCloseFrame(1005, "")}, check: wsEvExpectClose(wsStatusProtocolError)},
		{name: "close-bad-utf8", writes: [][]byte{wsEvCloseFrame(1000, "\xff\xfe")}, check: wsEvExpectClose(wsStatusInvalidPayload)},
		{name: "unmasked", writes: [][]byte{wsEvRawFrame(0x80|wsOpText, 2, false, []byte("hi"))}, check: wsEvExpectBareClose},
		{name: "rsv2", writes: [][]byte{wsClientFrame(0x80|0x20|wsOpText, []byte("hi"))}, check: wsEvExpectBareClose},
		{name: "rsv1-uncompressed", writes: [][]byte{wsClientFrame(0x80|wsRSV1|wsOpText, []byte("hi"))}, check: wsEvExpectBareClose},
		{name: "reserved-data-opcode", writes: [][]byte{wsClientFrame(0x80|0x3, []byte("hi"))}, check: wsEvExpectClose(wsStatusProtocolError)},
		{name: "reserved-control-opcode", writes: [][]byte{wsClientFrame(0x80|0xB, []byte("hi"))}, check: wsEvExpectClose(wsStatusProtocolError)},
		{name: "control-not-fin", writes: [][]byte{wsClientFrame(wsOpPing, []byte("hi"))}, check: wsEvExpectClose(wsStatusProtocolError)},
		{name: "control-too-long", writes: [][]byte{wsClientFrame(0x80|wsOpPing, bytes.Repeat([]byte{1}, 126))}, check: wsEvExpectClose(wsStatusProtocolError)},
		{name: "continuation-without-start", writes: [][]byte{wsClientFrame(0x80|wsOpContinuation, []byte("x"))}, check: wsEvExpectBareClose},
		{name: "data-during-fragment", writes: [][]byte{wsClientFrame(wsOpText, []byte("a")), wsClientFrame(0x80|wsOpText, []byte("b"))}, check: wsEvExpectBareClose},
		{name: "bad-utf8-text", writes: [][]byte{text("\xff\xfe\xfd")}, check: wsEvExpectClose(wsStatusInvalidPayload)},
		{name: "bad-utf8-across-fragments", writes: [][]byte{wsClientFrame(wsOpText, []byte{0xe2, 0x82}), wsClientFrame(0x80|wsOpContinuation, []byte{0xac}), normalClose}, check: wsEvExpectEchoes("€")},
		{name: "ping-flood", writes: [][]byte{wsClientFrame(0x80|wsOpPing, nil), wsClientFrame(0x80|wsOpPing, nil)}, check: wsEvExpectClose(wsStatusProtocolError)},
		{name: "oversize-length-63bit", writes: [][]byte{append(wsEvRawFrame(0x80|wsOpBinary, 0x80|127, false, nil), 0xff, 0, 0, 0, 0, 0, 0, 1)}, check: wsEvExpectBareClose},
		{name: "huge-declared", writes: [][]byte{append(wsEvRawFrame(0x80|wsOpBinary, 0x80|127, false, nil), 0, 0, 0, 1, 0, 0, 0, 0)}, check: wsEvExpectClose(wsStatusMessageTooBig)},
		{name: "small-at-limit", profile: "small", writes: [][]byte{text(strings.Repeat("l", wsEvSmallMax)), normalClose}, check: wsEvExpectEchoes(strings.Repeat("l", wsEvSmallMax))},
		{name: "small-over-limit", profile: "small", writes: [][]byte{text(strings.Repeat("l", wsEvSmallMax+1))}, check: wsEvExpectClose(wsStatusMessageTooBig)},
		{name: "small-fragments-over-limit", profile: "small", writes: [][]byte{
			wsClientFrame(wsOpText, []byte(strings.Repeat("f", wsEvSmallMax-10))),
			wsClientFrame(0x80|wsOpContinuation, []byte(strings.Repeat("f", 11))),
		}, check: wsEvExpectClose(wsStatusMessageTooBig)},
		{name: "deflate-roundtrip", profile: "deflate", writes: [][]byte{
			wsClientFrame(0x80|wsRSV1|wsOpText, nil),
			normalClose,
		}},
		{name: "deflate-compressed", profile: "deflate", writes: [][]byte{text(compressible), normalClose}},
		{name: "deflate-continuation-rsv1", profile: "deflate", writes: [][]byte{wsClientFrame(wsOpText, []byte("a")), wsClientFrame(0x80|wsRSV1|wsOpContinuation, []byte("b"))}, check: wsEvExpectBareClose},
		{name: "deflate-garbage", profile: "deflate", writes: [][]byte{wsClientFrame(0x80|wsRSV1|wsOpBinary, []byte{0xff, 0xff, 0xff, 0xff})}},
	}
}

func wsEvRunScenario(t *testing.T, ts *testServer, mode string, sc wsEvScenario) []wsServerFrame {
	t.Helper()
	profile := sc.profile
	if profile == "" {
		profile = "default"
	}
	var extra []string
	for _, p := range wsEvProfiles {
		if p.name == profile {
			extra = p.headers
		}
	}
	c, br, _ := wsEvDial(t, ts, "/"+mode+"/"+profile, extra...)
	for i, w := range sc.writes {
		if i > 0 && sc.split {
			turbo.Sleep(wsEvSplitPause)
		}
		if _, err := c.Write(w); err != nil {
			break
		}
	}
	return wsEvReadAll(br)
}

func wsEvFramesEqual(a, b []wsServerFrame) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].first != b[i].first || !bytes.Equal(a[i].payload, b[i].payload) {
			return false
		}
	}
	return true
}

func wsEvDescribe(frames []wsServerFrame) string {
	var b strings.Builder
	for _, f := range frames {
		fmt.Fprintf(&b, "[%#x len=%d code=%d] ", f.first, len(f.payload), wsCloseCode(f))
	}
	return b.String()
}

func TestWSEventsMatchBlockingFrames(t *testing.T) {
	for _, tr := range perfTransports {
		t.Run(tr.name, func(t *testing.T) {
			log := &wsEvCloseLog{}
			ts := wsEvStartServer(t, tr.tls, func(cfg *Config) { cfg.WebSocketOriginMode = WSOriginOff }, log, nil)
			for _, sc := range wsEvScenarios() {
				t.Run(sc.name, func(t *testing.T) {
					blocking := wsEvRunScenario(t, ts, "blocking", sc)
					events := wsEvRunScenario(t, ts, "events", sc)
					if !wsEvFramesEqual(blocking, events) {
						t.Fatalf("frames differ\nblocking: %s\nevents:   %s", wsEvDescribe(blocking), wsEvDescribe(events))
					}
					if sc.check != nil {
						sc.check(t, events)
					}
				})
			}
		})
	}
}

func TestWSEventsHandshakeMatchesBlocking(t *testing.T) {
	log := &wsEvCloseLog{}
	ts := wsEvStartServer(t, false, nil, log, nil)
	cases := []struct {
		name   string
		raw    func(path string) string
		status int
	}{
		{"bad-version", func(p string) string {
			return strings.Replace(wsEvUpgradeRequest(ts.domain, p), "Version: 13", "Version: 8", 1)
		}, 426},
		{"missing-key", func(p string) string {
			return strings.Replace(wsEvUpgradeRequest(ts.domain, p), "Sec-WebSocket-Key: "+wsSampleKey+"\r\n", "", 1)
		}, 400},
		{"bad-key", func(p string) string {
			return strings.Replace(wsEvUpgradeRequest(ts.domain, p), wsSampleKey, "c2hvcnQ=", 1)
		}, 400},
		{"no-upgrade", func(p string) string {
			return strings.Replace(wsEvUpgradeRequest(ts.domain, p), "Upgrade: websocket\r\n", "", 1)
		}, 400},
		{"no-connection-upgrade", func(p string) string {
			return strings.Replace(wsEvUpgradeRequest(ts.domain, p), "Connection: Upgrade", "Connection: keep-alive", 1)
		}, 400},
		{"cross-origin", func(p string) string {
			return wsEvUpgradeRequest(ts.domain, p, "Origin: https://evil.example")
		}, 403},
		{"same-origin", func(p string) string {
			return wsEvUpgradeRequest(ts.domain, p, "Origin: https://"+ts.domain)
		}, 101},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"blocking", "events"} {
				c := ts.dial(t)
				if _, err := io.WriteString(c, tc.raw("/"+mode+"/default")); err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(bufio.NewReader(c), nil)
				if err != nil {
					t.Fatalf("%s: %v", mode, err)
				}
				if resp.StatusCode != tc.status {
					t.Fatalf("%s: status %d, want %d", mode, resp.StatusCode, tc.status)
				}
				_ = c.Close()
			}
		})
	}
}

func TestWSEventsNegotiatedHeadersMatchBlocking(t *testing.T) {
	log := &wsEvCloseLog{}
	ts := wsEvStartServer(t, false, nil, log, func(r *Router) {
		opts := WSUpgradeOptions{Subprotocols: []string{"chat.v2", "chat.v1"}, Compression: true}
		r.GET("/neg/blocking", func(req *Request, resp *Response) { ServeWebSocketWith(req, resp, opts, wsEvEchoBlocking) })
		r.GET("/neg/events", func(req *Request, resp *Response) { ServeWebSocketEvents(req, resp, opts, wsEvEchoHandler(log)) })
	})
	var heads []http.Header
	for _, mode := range []string{"blocking", "events"} {
		_, _, resp := wsEvDial(t, ts, "/neg/"+mode, "Sec-WebSocket-Protocol: chat.v1, chat.v2", "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits")
		heads = append(heads, resp.Header)
	}
	for _, k := range []string{"Upgrade", "Connection", "Sec-WebSocket-Accept", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
		if heads[0].Get(k) != heads[1].Get(k) || heads[1].Get(k) == "" {
			t.Fatalf("header %s: blocking %q events %q", k, heads[0].Get(k), heads[1].Get(k))
		}
	}
}

func wsEvWaitCodes(t *testing.T, log *wsEvCloseLog, want ...uint16) {
	t.Helper()
	deadline := turbo.Deadline(wsEvCloseWait)
	for turbo.Until(deadline) > 0 {
		if got := log.snapshot(); len(got) >= len(want) {
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("OnClose codes %v, want %v", got, want)
				}
			}
			if len(got) != len(want) {
				t.Fatalf("OnClose codes %v, want exactly %v", got, want)
			}
			return
		}
		turbo.Sleep(harnessPollInterval)
	}
	t.Fatalf("OnClose codes %v, want %v", log.snapshot(), want)
}

func TestWSEventsOnCloseCodes(t *testing.T) {
	cases := []struct {
		name  string
		write []byte
		abort bool
		want  uint16
	}{
		{name: "client-close", write: wsEvCloseFrame(4001, "x"), want: 4001},
		{name: "client-close-empty", write: wsClientFrame(0x80|wsOpClose, nil), want: wsStatusNoStatus},
		{name: "protocol-error", write: wsEvRawFrame(0x80|wsOpText, 1, false, []byte("x")), want: wsStatusProtocolError},
		{name: "invalid-payload", write: wsClientFrame(0x80|wsOpText, []byte{0xff}), want: wsStatusInvalidPayload},
		{name: "abort", abort: true, want: wsStatusAbnormal},
	}
	for _, tr := range perfTransports {
		for _, tc := range cases {
			t.Run(tr.name+"/"+tc.name, func(t *testing.T) {
				log := &wsEvCloseLog{}
				ts := wsEvStartServer(t, tr.tls, nil, log, nil)
				c, br, _ := wsEvDial(t, ts, "/events/default")
				if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte("ping"))); err != nil {
					t.Fatal(err)
				}
				if f, err := wsReadServerFrame(br); err != nil || string(f.payload) != "ping" {
					t.Fatalf("echo %+v err %v", f, err)
				}
				if tc.abort {
					_ = c.Close()
				} else if _, err := c.Write(tc.write); err != nil {
					t.Fatal(err)
				}
				wsEvWaitCodes(t, log, tc.want)
			})
		}
	}
}

func TestWSEventsShutdownSendsGoingAway(t *testing.T) {
	for _, tr := range perfTransports {
		t.Run(tr.name, func(t *testing.T) {
			log := &wsEvCloseLog{}
			ts := wsEvStartServer(t, tr.tls, nil, log, nil)
			c, br, _ := wsEvDial(t, ts, "/events/default")
			if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte("a"))); err != nil {
				t.Fatal(err)
			}
			if _, err := wsReadServerFrame(br); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				stopServer(ts.srv)
				close(done)
			}()
			frames := wsEvReadAll(br)
			wsEvExpectClose(wsStatusGoingAway)(t, frames)
			_ = c.Close()
			<-done
			wsEvWaitCodes(t, log, wsStatusGoingAway)
		})
	}
}

func TestWSEventsReadTimeoutCloses(t *testing.T) {
	for _, tr := range perfTransports {
		t.Run(tr.name, func(t *testing.T) {
			log := &wsEvCloseLog{}
			ts := wsEvStartServer(t, tr.tls, func(cfg *Config) { cfg.WSReadTimeout = wsEvShortTimeout }, log, nil)
			c, br, _ := wsEvDial(t, ts, "/events/default")
			start := turbo.Now()
			frames := wsEvReadAll(br)
			wsEvExpectBareClose(t, frames)
			if el := turbo.Since(start); el < wsEvShortTimeout-epollDeadlineSlack {
				t.Fatalf("closed after %v, before the %v read timeout", el, wsEvShortTimeout)
			}
			_ = c.Close()
			wsEvWaitCodes(t, log, wsStatusAbnormal)
		})
	}
}

const epollDeadlineSlack = 5 * time.Millisecond

func TestWSEventsFrameTrickleDoesNotExtendReadTimeout(t *testing.T) {
	log := &wsEvCloseLog{}
	ts := wsEvStartServer(t, false, func(cfg *Config) { cfg.WSReadTimeout = wsEvShortTimeout }, log, nil)
	c, br, _ := wsEvDial(t, ts, "/events/default")
	frame := wsClientFrame(0x80|wsOpText, []byte(strings.Repeat("t", 40)))
	closed := make(chan []wsServerFrame, 1)
	go func() { closed <- wsEvReadAll(br) }()
	start := turbo.Now()
	for i := 0; i < len(frame)-1; i++ {
		if _, err := c.Write(frame[i : i+1]); err != nil {
			frames := <-closed
			if el := turbo.Since(start); el > wsEvShortTimeout+time.Second+wsEvSplitPause*4 {
				t.Fatalf("trickled frame kept the connection for %v (%s)", el, wsEvDescribe(frames))
			}
			return
		}
		select {
		case frames := <-closed:
			if len(frames) != 1 || frames[0].opcode() != wsOpClose {
				t.Fatalf("frames %s", wsEvDescribe(frames))
			}
			if el := turbo.Since(start); el > wsEvShortTimeout+time.Second+wsEvSplitPause*4 {
				t.Fatalf("trickled frame kept the connection for %v", el)
			}
			return
		case <-time.After(wsEvSplitPause * 3):
		}
	}
	t.Fatal("connection survived a frame trickled over many read timeouts")
}

func TestWSEventsOffLoopWritesAndClose(t *testing.T) {
	for _, tr := range perfTransports {
		t.Run(tr.name, func(t *testing.T) {
			log := &wsEvCloseLog{}
			ts := wsEvStartServer(t, tr.tls, nil, log, func(r *Router) {
				r.GET("/push", func(req *Request, resp *Response) {
					ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, WSEventHandler{
						OnMessage: func(ws *WSConn, op byte, msg []byte) {
							go func() {
								for i := 0; i < wsEvOffLoopCount; i++ {
									if err := ws.WriteText(fmt.Sprintf("m%d", i)); err != nil {
										return
									}
								}
								_ = ws.Close()
								if err := ws.WriteText("late"); err == nil {
									log.add(1)
								}
							}()
						},
						OnClose: func(ws *WSConn, code uint16) { log.add(code) },
					})
				})
			})
			c, br, _ := wsEvDial(t, ts, "/push")
			if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte("go"))); err != nil {
				t.Fatal(err)
			}
			frames := wsEvReadAll(br)
			if len(frames) != wsEvOffLoopCount+1 {
				t.Fatalf("got %d frames: %s", len(frames), wsEvDescribe(frames[:min(len(frames), 5)]))
			}
			for i := 0; i < wsEvOffLoopCount; i++ {
				if string(frames[i].payload) != fmt.Sprintf("m%d", i) {
					t.Fatalf("frame %d = %q", i, frames[i].payload)
				}
			}
			wsEvExpectBareClose(t, frames)
			_ = c.Close()
			wsEvWaitCodes(t, log, wsStatusNoStatus)
		})
	}
}

func TestWSEventsLargeBurstBackpressure(t *testing.T) {
	for _, tr := range perfTransports {
		t.Run(tr.name, func(t *testing.T) {
			log := &wsEvCloseLog{}
			chunk := bytes.Repeat([]byte{'q'}, wsEvBulkChunk)
			ts := wsEvStartServer(t, tr.tls, nil, log, func(r *Router) {
				r.GET("/bulk", func(req *Request, resp *Response) {
					ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, WSEventHandler{
						OnMessage: func(ws *WSConn, op byte, msg []byte) {
							for i := 0; i < wsEvBulkChunks; i++ {
								_ = ws.WriteBinary(chunk)
							}
							_ = ws.WriteMessage(op, msg)
						},
						OnClose: func(ws *WSConn, code uint16) { log.add(code) },
					})
				})
			})
			c, br, _ := wsEvDial(t, ts, "/bulk")
			var batch []byte
			for i := 0; i < 4; i++ {
				batch = append(batch, wsClientFrame(0x80|wsOpText, []byte(fmt.Sprintf("k%d", i)))...)
			}
			if _, err := c.Write(batch); err != nil {
				t.Fatal(err)
			}
			turbo.Sleep(wsEvSplitPause * 5)
			_ = c.SetDeadline(wallDeadline(wsEvCloseWait * 3))
			for i := 0; i < 4; i++ {
				for j := 0; j < wsEvBulkChunks; j++ {
					f, err := wsReadServerFrame(br)
					if err != nil || len(f.payload) != wsEvBulkChunk {
						t.Fatalf("msg %d chunk %d: len %d err %v", i, j, len(f.payload), err)
					}
				}
				f, err := wsReadServerFrame(br)
				if err != nil || string(f.payload) != fmt.Sprintf("k%d", i) {
					t.Fatalf("echo %d: %q err %v", i, f.payload, err)
				}
			}
			if _, err := c.Write(wsEvCloseFrame(1000, "")); err != nil {
				t.Fatal(err)
			}
			wsEvWaitCodes(t, log, 1000)
		})
	}
}

func TestWSEventsStalledReaderHitsWriteTimeout(t *testing.T) {
	log := &wsEvCloseLog{}
	chunk := bytes.Repeat([]byte{'s'}, wsEvBulkChunk)
	var wrote atomic.Int64
	ts := wsEvStartServer(t, false, func(cfg *Config) { cfg.WSWriteTimeout = wsEvShortTimeout }, log, func(r *Router) {
		r.GET("/flood", func(req *Request, resp *Response) {
			ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, WSEventHandler{
				OnMessage: func(ws *WSConn, op byte, msg []byte) {
					for i := 0; i < wsEvFloodChunks; i++ {
						if ws.WriteBinary(chunk) == nil {
							wrote.Add(1)
						}
					}
				},
				OnClose: func(ws *WSConn, code uint16) { log.add(code) },
			})
		})
	})
	c := wsEvDialSmallWindow(t, ts.addr)
	if _, err := io.WriteString(c, wsEvUpgradeRequest(ts.domain, "/flood")); err != nil {
		t.Fatal(err)
	}
	if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade %v %v", resp, err)
	}
	if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	wsEvWaitCodes(t, log, wsStatusAbnormal)
	if wrote.Load() == 0 {
		t.Fatal("handler never wrote")
	}
}

func wsEvDialSmallWindow(t *testing.T, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: harnessIOTimeout, Control: func(network, address string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096) }); err != nil {
			return err
		}
		return serr
	}}
	c, err := d.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(wallDeadline(wsEvCloseWait * 2))
	return c
}

func TestWSEventsConnReturnsToPool(t *testing.T) {
	log := &wsEvCloseLog{}
	ts := wsEvStartServer(t, false, nil, log, nil)
	c, br, _ := wsEvDial(t, ts, "/events/default")
	if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	if _, err := wsReadServerFrame(br); err != nil {
		t.Fatal(err)
	}
	freeWhileOpen := appFixPooledFreeConns(t, ts.srv)
	_ = c.Close()
	waitFor(t, harnessIOTimeout, func() bool {
		return ts.srv.activeConns.Load() == 0 && appFixPooledFreeConns(t, ts.srv) == freeWhileOpen+1
	})
	wsEvWaitCodes(t, log, wsStatusAbnormal)
}

func TestWSEventsInlineHandlersFallback(t *testing.T) {
	for _, tr := range perfTransports {
		t.Run(tr.name, func(t *testing.T) {
			log := &wsEvCloseLog{}
			ts := wsEvStartServer(t, tr.tls, func(cfg *Config) { cfg.InlineHandlers = true }, log, nil)
			c, br, _ := wsEvDial(t, ts, "/events/default")
			if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte("inline"))); err != nil {
				t.Fatal(err)
			}
			if f, err := wsReadServerFrame(br); err != nil || string(f.payload) != "inline" {
				t.Fatalf("echo %+v err %v", f, err)
			}
			if _, err := c.Write(wsEvCloseFrame(1000, "")); err != nil {
				t.Fatal(err)
			}
			wsEvExpectClose(1000)(t, wsEvReadAll(br))
			wsEvWaitCodes(t, log, 1000)
		})
	}
}

func TestWSEventsPanicInHandlerClosesWith1011(t *testing.T) {
	log := &wsEvCloseLog{}
	ts := wsEvStartServer(t, false, nil, log, func(r *Router) {
		r.GET("/panic", func(req *Request, resp *Response) {
			ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, WSEventHandler{
				OnMessage: func(ws *WSConn, op byte, msg []byte) { panic("boom") },
				OnClose:   func(ws *WSConn, code uint16) { log.add(code) },
			})
		})
	})
	c, br, _ := wsEvDial(t, ts, "/panic")
	if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	wsEvExpectClose(wsStatusInternalError)(t, wsEvReadAll(br))
	_ = c.Close()
	wsEvWaitCodes(t, log, wsStatusInternalError)
}

func TestWSEventsBlockingAPIsRejected(t *testing.T) {
	log := &wsEvCloseLog{}
	results := make(chan string, 1)
	ts := wsEvStartServer(t, false, nil, log, func(r *Router) {
		r.GET("/apis", func(req *Request, resp *Response) {
			ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, WSEventHandler{
				OnMessage: func(ws *WSConn, op byte, msg []byte) {
					_, _, readErr := ws.ReadMessage()
					results <- fmt.Sprint(readErr == errWSEventDriven, ws.NetConn() == nil, ws.SetDeadline(time.Time{}) == errWSEventDriven)
				},
			})
		})
	})
	c, _, _ := wsEvDial(t, ts, "/apis")
	if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-results:
		if got != "true true true" {
			t.Fatalf("got %s", got)
		}
	case <-time.After(wsEvCloseWait):
		t.Fatal("handler not called")
	}
}

func ctStartWith(t *testing.T, cfg Config, register func(*Server)) (*Server, string) {
	addr := freeLoopbackAddr(t)
	cfg.Addr = addr
	cfg.PlainHTTP = true
	cfg.WebSocketOriginMode = WSOriginOff
	s := New(cfg)
	s.Router.GET("/x", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	register(s)
	go func() { _ = s.ListenAndServeEpollH2(addr) }()
	t.Cleanup(func() { stopServer(s) })
	if !ctWaitReady(addr) {
		t.Fatalf("server on %s did not come up", addr)
	}
	if s.perIPConnLimiter.Load() != nil {
		ctWaitCount(t, s, ctIP, 0, 5*time.Second, "baseline")
	}
	return s, addr
}

func wsEvRegisterEcho(s *Server) {
	s.Router.GET("/ws", func(req *Request, resp *Response) {
		ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, WSEventHandler{
			OnMessage: func(ws *WSConn, op byte, msg []byte) { _ = ws.WriteMessage(op, msg) },
		})
	})
}

func TestWSEventsHoldsAndReleasesConnSlot(t *testing.T) {
	s, addr := ctStartWith(t, Config{Listeners: 1, MaxConnsPerIP: 1000, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}, wsEvRegisterEcho)
	for i := 0; i < 3; i++ {
		conn := ctWSDial(t, addr)
		ctWaitCount(t, s, ctIP, 1, 3*time.Second, "websocket must hold exactly one slot while alive")
		_ = conn.Close()
		ctWaitCount(t, s, ctIP, 0, 5*time.Second, "websocket must release its slot on close")
	}
}

func TestWSEventsProxyModeInFlightLimit(t *testing.T) {
	_, addr := ctStartWith(t, Config{Listeners: 2, ProxyMode: true, MaxConnsPerIP: 3, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}, wsEvRegisterEcho)
	var held []net.Conn
	for i := 0; i < 3; i++ {
		c, status := ctWSDialStatus(t, addr, "203.0.113.71")
		if !strings.Contains(status, "101") {
			t.Fatalf("websocket %d within the cap must upgrade, got %q", i, status)
		}
		held = append(held, c)
	}
	over, status := ctWSDialStatus(t, addr, "203.0.113.71")
	if !strings.Contains(status, "429") {
		t.Fatalf("a 4th concurrent websocket from the same real IP must be refused with 429, got %q", status)
	}
	_ = over.Close()
	other, otherStatus := ctWSDialStatus(t, addr, "203.0.113.72")
	if !strings.Contains(otherStatus, "101") {
		t.Fatalf("a different real IP keeps its own budget, got %q", otherStatus)
	}
	_ = other.Close()
	_ = held[0].Close()
	reclaimed := false
	deadline := turbo.Deadline(wsEvCloseWait)
	for turbo.Until(deadline) > 0 && !reclaimed {
		turbo.Sleep(harnessPollInterval)
		c, st := ctWSDialStatus(t, addr, "203.0.113.71")
		if strings.Contains(st, "101") {
			reclaimed = true
			held = append(held, c)
		} else {
			_ = c.Close()
		}
	}
	if !reclaimed {
		t.Fatal("closing an event websocket must return its slot to the client's budget")
	}
	for _, c := range held[1:] {
		_ = c.Close()
	}
}

func perfWSStartEventServer(tb testing.TB, useTLS bool) *testServer {
	tb.Helper()
	return newTestServer(tb, testServerOptions{
		TLS:    useTLS,
		Config: func(cfg *Config) { cfg.PlainHTTP = !useTLS },
		Routes: func(r *Router) {
			r.GET("/ws", func(req *Request, resp *Response) {
				ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, WSEventHandler{
					OnMessage: func(ws *WSConn, op byte, msg []byte) { _ = ws.WriteMessage(op, msg) },
				})
			})
		},
	})
}

func BenchmarkPerfWSEchoEvents(b *testing.B) {
	for _, tr := range perfTransports {
		for _, sz := range perfWSSizes {
			b.Run(tr.name+"/"+sz.name, func(b *testing.B) {
				if raceEnabled {
					b.Skip("the race detector distorts per-message cost")
				}
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				ts := perfWSStartEventServer(b, tr.tls)
				c := perfWSDial(b, ts, sz.size)
				for range perfWSWarmup {
					c.roundTrip(b)
				}
				b.SetBytes(int64(sz.size))
				b.ReportAllocs()
				for b.Loop() {
					c.roundTrip(b)
				}
			})
		}
	}
}

func TestPerfWSEchoEventsAllocLock(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates")
	}
	for _, tr := range perfTransports {
		for _, sz := range perfWSSizes {
			t.Run(tr.name+"/"+sz.name, func(t *testing.T) {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				ts := perfWSStartEventServer(t, tr.tls)
				c := perfWSDial(t, ts, sz.size)
				for range perfWSWarmup {
					c.roundTrip(t)
				}
				if allocs := testing.AllocsPerRun(perfAllocLockRuns, func() { c.roundTrip(t) }); allocs > 0.05 {
					t.Fatalf("event echo allocates %.3f/msg, want 0", allocs)
				}
			})
		}
	}
}

func TestPerfWSReadMessageIntoAllocLock(t *testing.T) {
	for _, sz := range perfWSSizes {
		t.Run(sz.name, func(t *testing.T) {
			frame := wsClientFrame(0x80|wsOpText, perfWSText(sz.size))
			conn := &perfReplayConn{stream: bytes.Repeat(frame, perfAllocLockRuns+2)}
			ws := perfNewWS(conn, 0)
			buf := make([]byte, 0, sz.size)
			if _, msg, err := ws.ReadMessageInto(buf); err != nil || len(msg) != sz.size {
				t.Fatalf("warmup len %d err %v", len(msg), err)
			}
			allocs := testing.AllocsPerRun(perfAllocLockRuns, func() {
				if _, _, err := ws.ReadMessageInto(buf); err != nil {
					t.Fatal(err)
				}
			})
			if allocs > 0 {
				t.Fatalf("ReadMessageInto allocates %.2f/msg", allocs)
			}
		})
	}
}

func TestWSNetConnDrainsBufferedBytes(t *testing.T) {
	first := wsClientFrame(0x80|wsOpText, []byte("one"))
	stream := append(append([]byte(nil), first...), "RAW"...)
	conn := &perfReplayConn{stream: stream}
	ws := perfNewWS(conn, 0)
	if _, msg, err := ws.ReadMessage(); err != nil || string(msg) != "one" {
		t.Fatalf("msg %q err %v", msg, err)
	}
	raw := make([]byte, 3)
	if _, err := io.ReadFull(ws.NetConn(), raw); err != nil || string(raw) != "RAW" {
		t.Fatalf("raw %q err %v", raw, err)
	}
}

func TestWSReadMessageSyscallsPerFrame(t *testing.T) {
	for _, sz := range perfWSSizes {
		t.Run(sz.name, func(t *testing.T) {
			frame := wsClientFrame(0x80|wsOpText, perfWSText(sz.size))
			const msgs = 50
			conn := &perfReplayConn{stream: bytes.Repeat(frame, msgs)}
			ws := perfNewWS(conn, 0)
			for i := 0; i < msgs; i++ {
				if _, _, err := ws.ReadMessage(); err != nil {
					t.Fatal(err)
				}
			}
			if per := float64(conn.reads) / msgs; per > 2.05 {
				t.Fatalf("%.2f reads per message", per)
			}
		})
	}
}

func TestWSEventsOverH2ExtendedConnect(t *testing.T) {
	log := &wsEvCloseLog{}
	ts := wsEvStartServer(t, false, nil, log, nil)
	rc, _ := h2DialCaptureSettings(t, ts.addr)
	ws, hdrs := openH2WebSocket(t, rc, 1, "/events/default")
	if hdrs[":status"] != "200" {
		t.Fatalf("response headers %v", hdrs)
	}
	ws.send(wsClientFrame(0x80|wsOpText, []byte("over-h2")))
	if f, err := ws.next(); err != nil || string(f.payload) != "over-h2" {
		t.Fatalf("echo %+v err %v", f, err)
	}
	ws.send(wsEvCloseFrame(1000, ""))
	if f, err := ws.next(); err != nil || wsCloseCode(f) != 1000 {
		t.Fatalf("close echo %+v err %v", f, err)
	}
	wsEvWaitCodes(t, log, 1000)
}
