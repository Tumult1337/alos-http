//go:build linux && amd64

package core

import (
	"testing"

	"golang.org/x/sys/unix"
)

var fpFixBenchH1Response = []byte("HTTP/1.1 200 OK\r\n" +
	"Content-Type: text/html; charset=utf-8\r\n" +
	"Content-Length: 64\r\n" +
	"Date: Mon, 30 Jul 2026 08:47:33 GMT\r\n" +
	"Server: origin\r\n" +
	"Cache-Control: public, max-age=3600\r\n" +
	"ETag: \"a1b2c3d4e5f6\"\r\n" +
	"Last-Modified: Sun, 29 Jul 2026 12:00:00 GMT\r\n" +
	"Accept-Ranges: bytes\r\n\r\n" +
	"0123456789012345678901234567890123456789012345678901234567890123")

var fpFixBenchChunkedResponse = []byte("HTTP/1.1 200 OK\r\n" +
	"Content-Type: text/plain\r\n" +
	"Transfer-Encoding: chunked\r\n\r\n" +
	"10\r\n0123456789abcdef\r\n" +
	"10\r\n0123456789abcdef\r\n" +
	"8;ext=1\r\n01234567\r\n" +
	"0\r\n\r\n")

func fpFixBenchBackendRead(b *testing.B, response []byte) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		b.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	l := newLoopForTest()
	l.cfg.fill(1)
	c := &backendConn{fd: fds[0], be: &l.beLoop, state: connReady, transport: &plainTransport{}}
	c.proto = &l.h1proto
	l.ensureFD(fds[0])
	l.conns[fds[0]] = c
	l.liveConns = 1
	ex := &Exchange{req: &fpRequest{Method: "GET"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ex.req.Method = "GET"
		c.cur = ex
		c.h1.reset()
		if _, err := unix.Write(fds[1], response); err != nil {
			b.Fatalf("write: %v", err)
		}
		l.readableUntil(c, false)
		if c.cur != nil || c.state != connReady {
			b.Fatalf("response did not complete: state %d", c.state)
		}
		l.removeIdle(c)
	}
}

func BenchmarkFPFixBackendReadH1(b *testing.B) { fpFixBenchBackendRead(b, fpFixBenchH1Response) }

func BenchmarkFPFixBackendReadChunked(b *testing.B) {
	fpFixBenchBackendRead(b, fpFixBenchChunkedResponse)
}

func BenchmarkFPFixH2ResponseHeaders(b *testing.B) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		b.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	l := newLoopForTest()
	l.cfg.fill(1)
	c := &backendConn{fd: fds[0], be: &l.beLoop, state: connReady, key: poolKey{h2: true}, transport: &plainTransport{h2: true}}
	c.proto = &l.h2proto
	c.h2init()
	l.h2conns[c.key] = c
	l.liveConns = 1
	var e hpackEncoder
	e.reset(nil)
	e.buf = append(e.buf, 0x88)
	e.field("content-type", "text/html; charset=utf-8")
	e.field("content-length", "1024")
	e.field("date", "Mon, 30 Jul 2026 08:47:33 GMT")
	e.field("server", "origin")
	e.field("cache-control", "public, max-age=3600")
	e.field("etag", "\"a1b2c3d4e5f6\"")
	block := e.buf
	h := &l.h2proto
	ex := &Exchange{req: &fpRequest{Method: "GET"}}
	st := &h2Stream{id: 1, ex: ex}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*st = h2Stream{id: 1, ex: ex, headers: st.headers[:0]}
		ex.h2st = st
		c.h2.streams[1] = st
		if err := h.handleFrame(c, h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, block); err != nil {
			b.Fatalf("headers: %v", err)
		}
	}
}

func BenchmarkFPFixH2WindowUpdate(b *testing.B) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		b.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	l := newLoopForTest()
	l.cfg.fill(1)
	c := &backendConn{fd: fds[0], be: &l.beLoop, state: connReady, key: poolKey{h2: true}, transport: &plainTransport{h2: true}}
	c.proto = &l.h2proto
	c.h2init()
	h := &l.h2proto
	inc := []byte{0, 0, 0, 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.h2.connSendWindow = h2DefaultWindow
		if err := h.handleFrame(c, h2FrameWindowUpdate, 0, 0, inc); err != nil {
			b.Fatalf("window update: %v", err)
		}
	}
}

func BenchmarkFPFixHuffmanDecode(b *testing.B) {
	enc := []byte{0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := fpHpackHuffmanDecode(enc); err != nil {
			b.Fatal(err)
		}
	}
}
