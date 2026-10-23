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
	h2TunnelReadTimeout = 300 * time.Millisecond
	h2TunnelIdle        = 3*time.Duration(epollSweepIntervalMs)*time.Millisecond + 500*time.Millisecond
)

func TestH2IdleWebSocketTunnelOutlivesReadTimeout(t *testing.T) {
	s := startH2WSServer(t, func(cfg *Config) {
		cfg.ReadTimeout = h2TunnelReadTimeout
		cfg.WSReadTimeout = 20 * time.Second
	})
	rc, _ := h2DialCaptureSettings(t, s.ts.addr)
	_ = rc.conn.SetDeadline(time.Now().Add(h2TunnelIdle + 5*time.Second))
	ws, hdrs := openH2WebSocket(t, rc, 1, "/ws", [2]string{"sec-websocket-protocol", "chat"})
	if hdrs[":status"] != "200" {
		t.Fatalf("headers %v", hdrs)
	}
	ws.send(wsClientFrame(0x80|wsOpText, []byte("a")))
	if f, err := ws.next(); err != nil || string(f.payload) != "chat>a" {
		t.Fatalf("first echo %+v err %v", f, err)
	}
	time.Sleep(h2TunnelIdle)
	ws.send(wsClientFrame(0x80|wsOpText, []byte("b")))
	if f, err := ws.next(); err != nil || string(f.payload) != "chat>b" {
		t.Fatalf("idle tunnel did not survive %v with ReadTimeout %v: %+v err %v", h2TunnelIdle, h2TunnelReadTimeout, f, err)
	}
}

func TestH2PeerEOFAbortsStreamedBodyReader(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
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
	if err := unix.Shutdown(p.peer, unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	p.w.readable(p.c, false)
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("handler read returned no error after the peer closed its side")
		}
	case <-time.After(h2FixCeiling):
		t.Fatal("handler stayed blocked on the body after the peer closed its side")
	}
}

func TestH2PeerEOFDropsWindowStalledResponse(t *testing.T) {
	p := newH2Progress(t)
	p.w.readTO = int64(time.Hour)
	p.w.writeTO = int64(time.Hour)
	big := make([]byte, 1<<20)
	p.w.server.Router.GET("/big", func(_ *Request, r *Response) { r.Status(200).Bytes(big) })
	p.w.server.Router.Build()
	p.w.server.computeFastDispatch()
	settings := h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0})
	p.open(settings, appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/big")))
	p.settleHandlers()
	if len(p.c.h2.sending) != 1 {
		t.Fatalf("response is not parked on the peer window: sending=%d", len(p.c.h2.sending))
	}
	if err := unix.Shutdown(p.peer, unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	p.w.readable(p.c, false)
	deadline := turbo.Deadline(h2FixCeiling)
	for p.c.fd >= 0 && turbo.Until(deadline) > 0 {
		p.w.flushPending()
		time.Sleep(time.Millisecond)
	}
	if p.c.fd >= 0 {
		t.Fatal("a response that waits for a WINDOW_UPDATE kept the connection open after peer EOF")
	}
}
