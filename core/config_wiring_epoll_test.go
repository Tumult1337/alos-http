//go:build linux && amd64

package core

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func firstBytesAfterH2Preface(t *testing.T, disableHTTP2 bool) []byte {
	t.Helper()
	addr := reserveLocalAddr(t)
	s := New(Config{Addr: addr, PlainHTTP: true, Listeners: 1, MaxConnsPerIP: -1, HTTPAddr: "-", DisableHTTP2: disableHTTP2})
	s.Router.GET("/ping", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	go func() { _ = s.ListenAndServeEpollH2(addr) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	if !waitServerReady(addr) {
		t.Fatal("server not ready")
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(H2ClientPreface[:]); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 9)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading the reply to the HTTP/2 preface: %v", err)
	}
	return got
}

func TestConfigDisableHTTP2PlainEpoll(t *testing.T) {
	if enabled := firstBytesAfterH2Preface(t, false); enabled[3] != H2FrameSettings {
		t.Fatalf("control server with HTTP/2 enabled did not answer the preface with SETTINGS: % x", enabled)
	}
	if disabled := firstBytesAfterH2Preface(t, true); string(disabled[:5]) != "HTTP/" {
		t.Fatalf("server with DisableHTTP2 answered the preface with %q, want an HTTP/1.1 response", disabled)
	}
}
