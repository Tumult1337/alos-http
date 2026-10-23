//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/guno1928/turbo"
)

const rootGetBenchBatch = 8

func startRootGetBenchServer(b *testing.B) string {
	b.Helper()
	addr := freeLoopbackAddr(b)
	srv := New(Config{Addr: addr, PlainHTTP: true, HTTPAddr: "-", MaxConnsPerIP: -1, Listeners: 1})
	srv.Router.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("root") })
	srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("okok") })
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
	}
	b.Fatal("bench server never came up")
	return ""
}

func benchRootGetH1(b *testing.B, path string) {
	addr := startRootGetBenchServer(b)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	r := bufio.NewReaderSize(conn, 64<<10)
	one := []byte("GET " + path + " HTTP/1.1\r\nHost: bench.test\r\n\r\n")
	batch := bytes.Repeat(one, rootGetBenchBatch)
	marker := []byte("\r\n\r\n")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := conn.Write(batch); err != nil {
			b.Fatal(err)
		}
		for range rootGetBenchBatch {
			if err := readH1BenchResponse(r, marker); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func readH1BenchResponse(r *bufio.Reader, marker []byte) error {
	var head []byte
	for !bytes.HasSuffix(head, marker) {
		c, err := r.ReadByte()
		if err != nil {
			return err
		}
		head = append(head, c)
	}
	_, err := r.Discard(4)
	return err
}

func benchRootGetH2(b *testing.B, path string) {
	addr := startRootGetBenchServer(b)
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
		for range rootGetBenchBatch {
			out = appendH2Frame(out, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, nextID, block)
			nextID += 2
		}
		if _, err := conn.Write(out); err != nil {
			b.Fatal(err)
		}
		out = out[:0]
		for ended := 0; ended < rootGetBenchBatch; {
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

func BenchmarkRootGetH1(b *testing.B) { benchRootGetH1(b, "/") }

func BenchmarkRootGetH1Control(b *testing.B) { benchRootGetH1(b, "/ok") }

func BenchmarkRootGetH2(b *testing.B) { benchRootGetH2(b, "/") }

func BenchmarkRootGetH2Control(b *testing.B) { benchRootGetH2(b, "/ok") }
