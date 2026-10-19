//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	h2FixCeiling          = 2 * time.Second
	h2FixShutdownGrace    = 150 * time.Millisecond
	h2FixAuthority        = "h2fix.test"
	h2FixPaddedFloodCount = h2MaxCtrlPerWindow + 500
)

func startH2FixServer(t *testing.T, tune func(*Config), routes func(*Server)) string {
	t.Helper()
	addr := reserveLocalAddr(t)
	cfg := Config{
		Addr:          addr,
		PlainHTTP:     true,
		HTTPAddr:      "-",
		MaxConnsPerIP: -1,
	}
	if tune != nil {
		tune(&cfg)
	}
	srv := New(cfg)
	if routes != nil {
		routes(srv)
	}
	serve := srv.ListenAndServe
	if len(cfg.Certs) > 0 {
		serve = srv.ListenAndServeTLS
	}
	go func() { _ = serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), h2FixShutdownGrace)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	waitForPort(t, addr)
	return addr
}

func h2FixRequestBlock(method, path string) []byte {
	return hpackBlock(
		[2]string{":method", method},
		[2]string{":scheme", "http"},
		[2]string{":path", path},
		[2]string{":authority", h2FixAuthority},
	)
}

func h2FixSettings(pairs ...[2]uint32) []byte {
	out := make([]byte, 0, 6*len(pairs))
	for _, p := range pairs {
		out = binary.BigEndian.AppendUint16(out, uint16(p[0]))
		out = binary.BigEndian.AppendUint32(out, p[1])
	}
	return out
}

func h2FixWindowIncrement(n uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, n)
}

func (rc *h2RawConn) writeRaw(b []byte) {
	rc.t.Helper()
	if _, err := rc.conn.Write(b); err != nil {
		rc.t.Fatalf("write: %v", err)
	}
}

func (rc *h2RawConn) awaitGoAway() (uint32, error) {
	for {
		f, err := rc.tryRead()
		if err != nil {
			return 0, err
		}
		if f.typ == H2FrameGoAway {
			return binary.BigEndian.Uint32(f.payload[4:8]), nil
		}
	}
}

func h2FixConnClosed(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

func TestH2FixPaddedEmptyDataFloodIsRateLimited(t *testing.T) {
	addr := startH2FixServer(t, nil, nil)
	rc := h2RawDial(t, addr, nil)
	rc.write(H2FrameHeaders, H2FlagEndHeaders, 1, h2FixRequestBlock("POST", "/sink"))
	var flood []byte
	for range h2FixPaddedFloodCount {
		flood = appendH2Frame(flood, H2FrameData, H2FlagPadded, 1, []byte{0})
	}
	rc.writeRaw(flood)
	_ = rc.conn.SetReadDeadline(wallDeadline(h2FixCeiling))
	code, err := rc.awaitGoAway()
	if err != nil {
		t.Fatalf("%d padded DATA frames with no body bytes drew no GOAWAY: %v", h2FixPaddedFloodCount, err)
	}
	if code != H2ErrEnhanceYourCalm {
		t.Fatalf("GOAWAY code = %d, want ENHANCE_YOUR_CALM", code)
	}
}

const h2FixBenchBatch = 8

func startH2FixBenchServer(b *testing.B) string {
	b.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	srv := New(Config{Addr: addr, PlainHTTP: true, HTTPAddr: "-", MaxConnsPerIP: -1, Listeners: 1})
	mid := bytes.Repeat([]byte{'m'}, 32<<10)
	srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	srv.Router.GET("/mid", func(req *Request, resp *Response) { resp.Status(200).Bytes(mid) })
	go func() { _ = srv.ListenAndServe() }()
	b.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), h2FixShutdownGrace)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	deadline := turbo.Deadline(h2FixCeiling)
	for turbo.Until(deadline) > 0 {
		if c, err := net.DialTimeout("tcp", addr, h2FixShutdownGrace); err == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	b.Fatal("bench server never came up")
	return ""
}

func h2FixBenchReadFrame(r *bufio.Reader, hdr []byte) (byte, byte, error) {
	if _, err := io.ReadFull(r, hdr[:9]); err != nil {
		return 0, 0, err
	}
	n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	if _, err := r.Discard(n); err != nil {
		return 0, 0, err
	}
	return hdr[3], hdr[4], nil
}

func benchH2FixRoundTrip(b *testing.B, path string, bodyBytes int) {
	addr := startH2FixBenchServer(b)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	r := bufio.NewReaderSize(conn, 256<<10)
	var hdr [9]byte
	hello := append([]byte(nil), H2ClientPreface[:]...)
	hello = appendH2Frame(hello, H2FrameSettings, 0, 0, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), h2FixMaxWindow}))
	hello = appendH2Frame(hello, H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(h2FixMaxWindow-H2DefaultWindowSize))
	if _, err := conn.Write(hello); err != nil {
		b.Fatal(err)
	}
	for {
		typ, flags, err := h2FixBenchReadFrame(r, hdr[:])
		if err != nil {
			b.Fatal(err)
		}
		if typ == H2FrameSettings && flags&H2FlagAck == 0 {
			break
		}
	}
	block := h2FixRequestBlock("GET", path)
	out := appendH2Frame(nil, H2FrameSettings, H2FlagAck, 0, nil)
	nextID := uint32(1)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for range h2FixBenchBatch {
			out = appendH2Frame(out, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, nextID, block)
			nextID += 2
		}
		if _, err := conn.Write(out); err != nil {
			b.Fatal(err)
		}
		out = out[:0]
		if bodyBytes > 0 {
			out = appendH2Frame(out, H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(uint32(h2FixBenchBatch*bodyBytes)))
		}
		for ended := 0; ended < h2FixBenchBatch; {
			typ, flags, err := h2FixBenchReadFrame(r, hdr[:])
			if err != nil {
				b.Fatal(err)
			}
			if (typ == H2FrameData || typ == H2FrameHeaders) && flags&H2FlagEndStream != 0 {
				ended++
			}
		}
	}
}

func BenchmarkH2FixRoundTripSmall(b *testing.B) { benchH2FixRoundTrip(b, "/ok", 0) }

func BenchmarkH2FixRoundTripBody(b *testing.B) { benchH2FixRoundTrip(b, "/mid", 32<<10) }
