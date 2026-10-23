//go:build linux && amd64

package core

import (
	"io"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

func TestWebSocketH2TunnelHoldsPerIPSlot(t *testing.T) {
	s := startH2WSServer(t, func(cfg *Config) {
		cfg.TrustedProxies = []string{"127.0.0.1"}
		cfg.MaxConnsPerIP = 1
	})
	xff := [2]string{"x-forwarded-for", "203.0.113.7"}
	rc, _ := h2DialCaptureSettings(t, s.ts.addr)
	ws, hdrs := openH2WebSocket(t, rc, 1, "/ws", xff)
	if hdrs[":status"] != "200" {
		t.Fatalf("first tunnel status %q", hdrs[":status"])
	}
	_, hdrs = openH2WebSocket(t, rc, 3, "/ws", xff)
	if hdrs[":status"] != "429" {
		t.Fatalf("second tunnel from the same client while the first is open: status %q, want 429", hdrs[":status"])
	}
	_, hdrs = openH2WebSocket(t, rc, 5, "/ws", [2]string{"x-forwarded-for", "203.0.113.8"})
	if hdrs[":status"] != "200" {
		t.Fatalf("tunnel from another client: status %q, want 200", hdrs[":status"])
	}
	ws.send(wsClientFrame(0x80|wsOpClose, []byte{0x03, 0xe8}))
	for {
		if _, err := ws.next(); err != nil {
			break
		}
	}
	select {
	case err := <-s.ended:
		if err != io.EOF {
			t.Fatalf("handler ended with %v", err)
		}
	case <-turbo.After(harnessIOTimeout):
		t.Fatal("handler did not end")
	}
	h2TunnelAwaitSlotFree(t, s.ts.srv, "203.0.113.7")
	_, hdrs = openH2WebSocket(t, rc, 7, "/ws", xff)
	if hdrs[":status"] != "200" {
		t.Fatalf("tunnel after the first closed: status %q, want 200", hdrs[":status"])
	}
	if _, ok := s.ts.srv.perIPLimiter.hold("203.0.113.7", 1); ok {
		t.Fatal("open tunnel does not hold the per-IP slot")
	}
	rc.write(H2FrameRSTStream, 0, 7, []byte{0, 0, 0, 8})
	h2TunnelAwaitSlotFree(t, s.ts.srv, "203.0.113.7")
}

func h2TunnelAwaitSlotFree(t *testing.T, srv *Server, ip string) {
	t.Helper()
	waitFor(t, harnessIOTimeout, func() bool {
		slot, ok := srv.perIPLimiter.hold(ip, 1)
		if ok && slot != nil {
			slot.release()
		}
		return ok
	})
}

func TestWebSocketH2BlockedCallbackHoldsSlotsAfterReset(t *testing.T) {
	blocker := newWSBlockingClose()
	ts := wsCloseAdmissionServer(t, blocker, func(cfg *Config) {
		cfg.TrustedProxies = []string{"127.0.0.1"}
		cfg.MaxConnsPerIP = 1
	})
	ip := "203.0.113.11"
	rc, _ := h2DialCaptureSettings(t, ts.addr)
	ws, hdrs := openH2WebSocket(t, rc, 1, "/ws-block-message", [2]string{"x-forwarded-for", ip})
	if hdrs[":status"] != "200" {
		t.Fatalf("tunnel status %q", hdrs[":status"])
	}
	ws.send(wsClientFrame(0x80|wsOpText, []byte("m")))
	blocker.awaitEntered(t)
	rc.write(H2FrameRSTStream, 0, 1, []byte{0, 0, 0, 8})
	time.Sleep(wsCloseAdmissionSettle)
	if _, ok := ts.srv.perIPLimiter.hold(ip, 1); ok {
		t.Fatal("a reset tunnel released its per-IP slot while OnMessage still runs")
	}
	if got := ts.srv.activeConns.Load(); got != 2 {
		t.Fatalf("activeConns with a blocked callback on a reset tunnel = %d, want 2", got)
	}
	blocker.unblock()
	h2TunnelAwaitSlotFree(t, ts.srv, ip)
	waitFor(t, wsEvCloseWait, func() bool { return ts.srv.activeConns.Load() == 1 })
}
