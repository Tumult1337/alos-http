//go:build linux && amd64

package core

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

const h2FuzzReadCeiling = 2 * time.Second

var (
	h2FuzzOnce sync.Once
	h2FuzzAddr string
	h2FuzzErr  error
)

func startH2FuzzServer(tb testing.TB) string {
	tb.Helper()
	h2FuzzOnce.Do(func() {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			h2FuzzErr = err
			return
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		srv := New(Config{Addr: addr, PlainHTTP: true, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1})
		srv.Router.GET("/", func(req *Request, resp *Response) { resp.String("root") })
		srv.Router.POST("/echo", func(req *Request, resp *Response) { resp.Bytes(req.Body) })
		srv.Router.GET("/stream", func(req *Request, resp *Response) {
			sse := resp.SSE()
			_ = sse.SendData("one")
			_ = sse.SendData("two")
			_ = sse.Close()
		})
		go func() { _ = srv.ListenAndServe() }()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if c, err := net.DialTimeout("tcp", addr, 150*time.Millisecond); err == nil {
				_ = c.Close()
				h2FuzzAddr = addr
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		h2FuzzErr = errors.New("h2c fuzz server never came up")
		_ = srv.Shutdown(context.Background())
	})
	if h2FuzzErr != nil {
		tb.Fatal(h2FuzzErr)
	}
	return h2FuzzAddr
}

func h2FuzzFrame(typ, flags byte, stream uint32, payload []byte) []byte {
	f := make([]byte, 9, 9+len(payload))
	f[0], f[1], f[2] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
	f[3], f[4] = typ, flags
	binary.BigEndian.PutUint32(f[5:], stream)
	return append(f, payload...)
}

func h2FuzzSeeds() [][]byte {
	get := []byte{0x82, 0x86, 0x84, 0x41, 0x06, 'a', '.', 't', 'e', 's', 't'}
	post := []byte{0x83, 0x86, 0x44, 0x05, '/', 'e', 'c', 'h', 'o', 0x41, 0x06, 'a', '.', 't', 'e', 's', 't'}
	stream := []byte{0x82, 0x86, 0x44, 0x07, '/', 's', 't', 'r', 'e', 'a', 'm', 0x41, 0x06, 'a', '.', 't', 'e', 's', 't'}
	settings := h2FuzzFrame(H2FrameSettings, 0, 0, []byte{0, 4, 0, 0, 0xff, 0xff})
	cat := func(frames ...[]byte) []byte {
		var out []byte
		for _, f := range frames {
			out = append(out, f...)
		}
		return out
	}
	return [][]byte{
		cat(settings, h2FuzzFrame(H2FrameHeaders, 0x05, 1, get)),
		cat(settings, h2FuzzFrame(H2FrameHeaders, 0x04, 1, post), h2FuzzFrame(H2FrameData, 0x01, 1, []byte("hello"))),
		cat(settings, h2FuzzFrame(H2FrameHeaders, 0x01, 1, get[:4]), h2FuzzFrame(H2FrameContinuation, 0x04, 1, get[4:])),
		cat(settings, h2FuzzFrame(H2FrameHeaders, 0x05, 1, stream), h2FuzzFrame(H2FrameWindowUpdate, 0, 0, []byte{0, 0, 0, 1})),
		cat(settings, h2FuzzFrame(H2FramePing, 0, 0, make([]byte, 8)), h2FuzzFrame(H2FrameRSTStream, 0, 1, []byte{0, 0, 0, 8})),
		cat(settings, h2FuzzFrame(H2FrameGoAway, 0, 0, make([]byte, 8))),
		cat(settings, h2FuzzFrame(H2FrameHeaders, 0x05, 2, get)),
		cat(h2FuzzFrame(H2FrameData, 0, 1, []byte("x"))),
		h2FuzzFrame(0xff, 0xff, 0x7fffffff, make([]byte, 20)),
	}
}

func checkH2ServerFrames(t *testing.T, out []byte, complete bool) {
	t.Helper()
	for len(out) >= 9 {
		n := int(out[0])<<16 | int(out[1])<<8 | int(out[2])
		typ := out[3]
		if 9+n > len(out) {
			if complete {
				t.Fatalf("server wrote a truncated frame (type %d, length %d, %d bytes left)", typ, n, len(out)-9)
			}
			return
		}
		payload := out[9 : 9+n]
		stream := binary.BigEndian.Uint32(out[5:9]) & 0x7fffffff
		switch typ {
		case H2FrameGoAway:
			if n < 8 || stream != 0 {
				t.Fatalf("malformed GOAWAY: length %d stream %d", n, stream)
			}
		case H2FrameRSTStream:
			if n != 4 || stream == 0 {
				t.Fatalf("malformed RST_STREAM: length %d stream %d", n, stream)
			}
		case H2FrameSettings:
			if n%6 != 0 || stream != 0 {
				t.Fatalf("malformed SETTINGS: length %d stream %d", n, stream)
			}
		case H2FramePing:
			if n != 8 || stream != 0 {
				t.Fatalf("malformed PING: length %d stream %d", n, stream)
			}
		case H2FrameWindowUpdate:
			if n != 4 || binary.BigEndian.Uint32(payload)&0x7fffffff == 0 {
				t.Fatalf("malformed WINDOW_UPDATE: %x", payload)
			}
		case H2FrameHeaders, H2FrameData, H2FrameContinuation:
			if stream == 0 {
				t.Fatalf("frame type %d on stream 0", typ)
			}
		}
		out = out[9+n:]
	}
	if complete && len(out) != 0 {
		t.Fatalf("server wrote %d trailing bytes that are not a frame", len(out))
	}
}

func FuzzEpollH2Frames(f *testing.F) {
	for _, seed := range h2FuzzSeeds() {
		f.Add(seed)
	}
	addr := startH2FuzzServer(f)
	f.Fuzz(func(t *testing.T, frames []byte) {
		conn, err := net.DialTimeout("tcp", addr, h2FuzzReadCeiling)
		if err != nil {
			t.Skipf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(h2FuzzReadCeiling))
		if _, err := conn.Write(append(H2ClientPreface[:], frames...)); err != nil {
			return
		}
		_ = conn.(*net.TCPConn).CloseWrite()
		out, err := io.ReadAll(conn)
		checkH2ServerFrames(t, out, err == nil)
	})
}

func TestEpollH2FuzzHarnessServes(t *testing.T) {
	addr := startH2FuzzServer(t)
	conn, err := net.DialTimeout("tcp", addr, h2FuzzReadCeiling)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(h2FuzzReadCeiling))
	if _, err := conn.Write(append(H2ClientPreface[:], h2FuzzSeeds()[0]...)); err != nil {
		t.Fatal(err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	checkH2ServerFrames(t, out, true)
	sawHeaders := false
	for len(out) >= 9 {
		n := int(out[0])<<16 | int(out[1])<<8 | int(out[2])
		if out[3] == H2FrameHeaders && binary.BigEndian.Uint32(out[5:9]) == 1 {
			sawHeaders = true
		}
		out = out[9+n:]
	}
	if !sawHeaders {
		t.Fatal("the GET seed got no response headers on stream 1")
	}
}
