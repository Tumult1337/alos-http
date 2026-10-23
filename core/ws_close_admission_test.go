//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const wsCloseAdmissionSettle = 300 * time.Millisecond

type wsBlockingClose struct {
	entered     chan struct{}
	release     chan struct{}
	upgrading   chan struct{}
	upgradeGate chan struct{}
	running     atomic.Int32
	peak        atomic.Int32
	once        sync.Once
}

func newWSBlockingClose() *wsBlockingClose {
	return &wsBlockingClose{entered: make(chan struct{}, 64), release: make(chan struct{}), upgrading: make(chan struct{}, 1), upgradeGate: make(chan struct{})}
}

func (b *wsBlockingClose) handler() WSEventHandler {
	return WSEventHandler{
		OnMessage: func(ws *WSConn, op byte, msg []byte) {},
		OnClose: func(ws *WSConn, code uint16) {
			n := b.running.Add(1)
			for {
				peak := b.peak.Load()
				if n <= peak || b.peak.CompareAndSwap(peak, n) {
					break
				}
			}
			b.entered <- struct{}{}
			<-b.release
			b.running.Add(-1)
		},
	}
}

func (b *wsBlockingClose) messageHandler() WSEventHandler {
	return WSEventHandler{
		OnMessage: func(ws *WSConn, op byte, msg []byte) {
			_ = ws.Close()
			b.entered <- struct{}{}
			<-b.release
		},
	}
}

func (b *wsBlockingClose) unblock() { b.once.Do(func() { close(b.release) }) }

func (b *wsBlockingClose) awaitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-b.entered:
	case <-time.After(wsEvCloseWait):
		t.Fatal("OnClose was not entered")
	}
}

func wsCloseAdmissionServer(t *testing.T, blocker *wsBlockingClose, cfgFn func(*Config)) *testServer {
	t.Helper()
	ts := newTestServer(t, testServerOptions{
		Config: func(cfg *Config) {
			cfg.PlainHTTP = true
			cfg.WebSocketOriginMode = WSOriginOff
			cfgFn(cfg)
		},
		Routes: func(r *Router) {
			r.GET("/ws", func(req *Request, resp *Response) {
				ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, blocker.handler())
			})
			r.GET("/ws-block-message", func(req *Request, resp *Response) {
				ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, WSEventHandler{OnMessage: func(ws *WSConn, op byte, msg []byte) {
					blocker.entered <- struct{}{}
					<-blocker.release
				}})
			})
			r.GET("/ws-slow-upgrade", func(req *Request, resp *Response) {
				ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, blocker.handler())
				blocker.upgrading <- struct{}{}
				<-blocker.upgradeGate
			})
			r.GET("/ping", func(req *Request, resp *Response) { resp.String("pong") })
			r.GET("/ws-message", func(req *Request, resp *Response) {
				ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, blocker.messageHandler())
			})
		},
	})
	t.Cleanup(blocker.unblock)
	awaitIdleAfterReadinessProbe(t, ts, "/ping")
	return ts
}

func wsCloseAdmissionUpgrade(t *testing.T, ts *testServer, extra ...string) int {
	t.Helper()
	c := ts.dial(t)
	defer c.Close()
	_ = c.SetDeadline(wallDeadline(wsEvCloseWait))
	if _, err := c.Write([]byte(wsEvUpgradeRequest(ts.domain, "/ws", extra...))); err != nil {
		return 0
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0
	}
	return resp.StatusCode
}

func TestWSEventsBlockedOnCloseHoldsConnSlot(t *testing.T) {
	cases := []struct {
		name  string
		cfg   func(*Config)
		extra []string
		held  int
		deny  func(status int) bool
	}{
		{name: "max-conns", held: 2, cfg: func(cfg *Config) { cfg.MaxConns = 2 },
			deny: func(status int) bool { return status == 0 }},
		{name: "per-ip-conns", held: 1, cfg: func(cfg *Config) { cfg.MaxConnsPerIP = 1 },
			deny: func(status int) bool { return status == 0 || status == http.StatusTooManyRequests }},
		{name: "per-ip-trusted-proxy", held: 1, extra: []string{"X-Forwarded-For: 203.0.113.9"},
			cfg: func(cfg *Config) {
				cfg.MaxConnsPerIP = 1
				cfg.TrustedProxies = []string{"127.0.0.1"}
			},
			deny: func(status int) bool { return status == http.StatusTooManyRequests }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocker := newWSBlockingClose()
			ts := wsCloseAdmissionServer(t, blocker, tc.cfg)
			for held := range tc.held {
				if status := wsCloseAdmissionUpgrade(t, ts, tc.extra...); status != http.StatusSwitchingProtocols {
					t.Fatalf("upgrade below the limit: status %d", status)
				}
				blocker.awaitEntered(t)
				waitFor(t, wsEvCloseWait, func() bool { return ts.srv.activeConns.Load() == int64(held+1) })
			}
			for attempt := range 3 {
				status := wsCloseAdmissionUpgrade(t, ts, tc.extra...)
				if !tc.deny(status) {
					t.Fatalf("attempt %d with %d blocked OnClose callbacks: status %d, want refusal", attempt, tc.held, status)
				}
			}
			time.Sleep(wsCloseAdmissionSettle)
			if peak := blocker.peak.Load(); peak != int32(tc.held) {
				t.Fatalf("blocked OnClose peak %d, want %d", peak, tc.held)
			}
			blocker.unblock()
			waitFor(t, wsEvCloseWait, func() bool { return ts.srv.activeConns.Load() == 0 })
			if status := wsCloseAdmissionUpgrade(t, ts, tc.extra...); status != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade after OnClose returned: status %d", status)
			}
		})
	}
}

func TestWSEventsBlockedOnMessageAfterTeardownHoldsConnSlot(t *testing.T) {
	blocker := newWSBlockingClose()
	ts := wsCloseAdmissionServer(t, blocker, func(cfg *Config) { cfg.MaxConns = 1 })
	c, br, _ := wsEvDial(t, ts, "/ws-message")
	if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte("m"))); err != nil {
		t.Fatal(err)
	}
	blocker.awaitEntered(t)
	wsEvExpectBareClose(t, wsEvReadAll(br))
	_ = c.Close()
	time.Sleep(wsCloseAdmissionSettle)
	if got := ts.srv.activeConns.Load(); got != 1 {
		t.Fatalf("activeConns with a blocked OnMessage after teardown = %d, want 1", got)
	}
	for attempt := range 3 {
		if status := wsCloseAdmissionUpgrade(t, ts); status != 0 {
			t.Fatalf("attempt %d with a blocked OnMessage after teardown: status %d, want refusal", attempt, status)
		}
	}
	blocker.unblock()
	waitFor(t, wsEvCloseWait, func() bool { return ts.srv.activeConns.Load() == 0 })
	if status := wsCloseAdmissionUpgrade(t, ts); status != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade after OnMessage returned: status %d", status)
	}
}

func TestWSEventsBlockingPathOnCloseHoldsConnSlot(t *testing.T) {
	blocker := newWSBlockingClose()
	ts := wsCloseAdmissionServer(t, blocker, func(cfg *Config) { cfg.MaxConns = 2 })
	rc, _ := h2DialCaptureSettings(t, ts.addr)
	ws, hdrs := openH2WebSocket(t, rc, 1, "/ws")
	if hdrs[":status"] != "200" {
		t.Fatalf("tunnel status %q", hdrs[":status"])
	}
	ws.send(wsEvCloseFrame(1000, ""))
	blocker.awaitEntered(t)
	time.Sleep(wsCloseAdmissionSettle)
	if got := ts.srv.activeConns.Load(); got != 2 {
		t.Fatalf("activeConns with a blocked OnClose on a closed tunnel of an open H2 conn = %d, want 2", got)
	}
	if status := wsCloseAdmissionUpgrade(t, ts); status != 0 {
		t.Fatalf("upgrade with a blocked OnClose: status %d, want refusal", status)
	}
	blocker.unblock()
	waitFor(t, wsEvCloseWait, func() bool { return ts.srv.activeConns.Load() == 1 })
}

func awaitIdleAfterReadinessProbe(t *testing.T, ts *testServer, path string) {
	t.Helper()
	waitFor(t, wsEvCloseWait, func() bool {
		c, err := net.DialTimeout("tcp4", ts.addr, harnessIOTimeout)
		if err != nil {
			return false
		}
		defer c.Close()
		_ = c.SetDeadline(wallDeadline(harnessIOTimeout))
		if _, err := io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: "+ts.domain+"\r\nConnection: close\r\n\r\n"); err != nil {
			return false
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		return err == nil && resp.StatusCode == http.StatusOK
	})
	waitFor(t, wsEvCloseWait, func() bool { return ts.srv.activeConns.Load() == 0 })
}

func TestWSEventsCloseDuringUpgradeHoldsPerIPConnSlot(t *testing.T) {
	blocker := newWSBlockingClose()
	ts := wsCloseAdmissionServer(t, blocker, func(cfg *Config) { cfg.MaxConnsPerIP = 1 })
	c := ts.dial(t)
	if _, err := c.Write([]byte(wsEvUpgradeRequest(ts.domain, "/ws-slow-upgrade"))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocker.upgrading:
	case <-time.After(wsEvCloseWait):
		t.Fatal("upgrade handler not entered")
	}
	_ = c.Close()
	time.Sleep(wsCloseAdmissionSettle)
	close(blocker.upgradeGate)
	blocker.awaitEntered(t)
	time.Sleep(wsCloseAdmissionSettle)
	if status := wsCloseAdmissionUpgrade(t, ts); status != 0 && status != http.StatusTooManyRequests {
		t.Fatalf("upgrade while OnClose of a conn closed mid-upgrade blocks: status %d, want refusal", status)
	}
	blocker.unblock()
	waitFor(t, wsEvCloseWait, func() bool { return ts.srv.activeConns.Load() == 0 })
}
