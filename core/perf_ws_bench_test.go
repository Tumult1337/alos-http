//go:build linux && amd64

package core

import (
	"bytes"
	"compress/flate"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	perfWSSmall        = 64
	perfWSLarge        = 16 << 10
	perfWSWarmup       = 200
	perfWSIOTimeout    = 10 * time.Second
	perfWSHeadLimit    = 4096
	perfAllocLockRuns  = 2000
	perfSocketLockRuns = 3000
)

type perfSize struct {
	name string
	size int
}

var perfWSSizes = []perfSize{{"64B", perfWSSmall}, {"16KB", perfWSLarge}}

type perfTransport struct {
	name string
	tls  bool
}

var perfTransports = []perfTransport{{"plain", false}, {"tls", true}}

type perfRawConn struct {
	fd int
}

var perfRawAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}

func perfDialRaw(tb testing.TB, addr string) *perfRawConn {
	tb.Helper()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		tb.Fatalf("parse %s: %v", addr, err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		tb.Fatalf("socket: %v", err)
	}
	c := &perfRawConn{fd: fd}
	tb.Cleanup(func() { _ = c.Close() })
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}); err != nil {
		tb.Fatalf("connect %s: %v", addr, err)
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	tv := unix.NsecToTimeval(int64(perfWSIOTimeout))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	return c
}

func (c *perfRawConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		r, _, e := unix.Syscall6(unix.SYS_RECVFROM, uintptr(c.fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), 0, 0, 0)
		if e == unix.EINTR {
			continue
		}
		if e != 0 {
			return 0, e
		}
		if r == 0 {
			return 0, io.EOF
		}
		return int(r), nil
	}
}

func (c *perfRawConn) Write(p []byte) (int, error) {
	sent := 0
	for sent < len(p) {
		r, _, e := unix.Syscall6(unix.SYS_SENDTO, uintptr(c.fd), uintptr(unsafe.Pointer(&p[sent])), uintptr(len(p)-sent), unix.MSG_NOSIGNAL, 0, 0)
		if e == unix.EINTR {
			continue
		}
		if e != 0 {
			return sent, e
		}
		sent += int(r)
	}
	return sent, nil
}

func (c *perfRawConn) Close() error {
	if c.fd < 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}

func (c *perfRawConn) LocalAddr() net.Addr              { return perfRawAddr }
func (c *perfRawConn) RemoteAddr() net.Addr             { return perfRawAddr }
func (c *perfRawConn) SetDeadline(time.Time) error      { return nil }
func (c *perfRawConn) SetReadDeadline(time.Time) error  { return nil }
func (c *perfRawConn) SetWriteDeadline(time.Time) error { return nil }

func perfDialClient(tb testing.TB, ts *testServer) net.Conn {
	tb.Helper()
	if !ts.tls {
		return perfDialRaw(tb, ts.addr)
	}
	return perfDialTLSClient(tb, ts.addr, ts.tlsConfig("http/1.1"))
}

func perfReadFull(conn net.Conn, buf []byte) error {
	for got := 0; got < len(buf); {
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil {
			return err
		}
	}
	return nil
}

func perfWSEcho(ws *WSConn) {
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

func perfWSStartServer(tb testing.TB, useTLS bool) *testServer {
	tb.Helper()
	return newTestServer(tb, testServerOptions{
		TLS:    useTLS,
		Config: func(cfg *Config) { cfg.PlainHTTP = !useTLS },
		Routes: func(r *Router) {
			r.GET("/ws", func(req *Request, resp *Response) { ServeWebSocket(req, resp, perfWSEcho) })
		},
	})
}

type perfWSClient struct {
	conn  net.Conn
	frame []byte
	echo  []byte
	buf   []byte
}

func perfWSDial(tb testing.TB, ts *testServer, size int) *perfWSClient {
	tb.Helper()
	conn := perfDialClient(tb, ts)
	if _, err := conn.Write([]byte(wsUpgradeRequest(ts.domain))); err != nil {
		tb.Fatalf("upgrade write: %v", err)
	}
	head := make([]byte, perfWSHeadLimit)
	got := 0
	for !bytes.Contains(head[:got], dpCRLFCRLF) {
		if got == len(head) {
			tb.Fatalf("upgrade response head exceeds %d bytes", perfWSHeadLimit)
		}
		n, err := conn.Read(head[got:])
		got += n
		if err != nil {
			tb.Fatalf("upgrade read: %v", err)
		}
	}
	if end := bytes.Index(head[:got], dpCRLFCRLF) + len(dpCRLFCRLF); end != got || !bytes.HasPrefix(head, []byte("HTTP/1.1 101 ")) {
		tb.Fatalf("unexpected upgrade response %q", head[:got])
	}
	payload := bytes.Repeat([]byte{'w'}, size)
	echo := append(wsAppendFrameHeader(nil, 0x80|wsOpText, size), payload...)
	c := &perfWSClient{conn: conn, frame: wsClientFrame(0x80|wsOpText, payload), echo: echo, buf: make([]byte, len(echo))}
	c.roundTrip(tb)
	if !bytes.Equal(c.buf, c.echo) {
		tb.Fatalf("echo mismatch: got %d bytes, first %q", len(c.buf), c.buf[:min(len(c.buf), 16)])
	}
	return c
}

func (c *perfWSClient) roundTrip(tb testing.TB) {
	if _, err := c.conn.Write(c.frame); err != nil {
		tb.Fatalf("frame write: %v", err)
	}
	if err := perfReadFull(c.conn, c.buf); err != nil {
		tb.Fatalf("echo read: %v", err)
	}
}

type perfProcSnapshot struct {
	syscr, syscw   int64
	procSwitches   int64
	clientSwitches int64
	ok             bool
}

func perfProcField(data []byte, key string) (int64, bool) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		name, value, found := bytes.Cut(line, []byte(":"))
		if !found || string(bytes.TrimSpace(name)) != key {
			continue
		}
		v, err := strconv.ParseInt(string(bytes.TrimSpace(value)), 10, 64)
		return v, err == nil
	}
	return 0, false
}

func perfThreadSwitches(statusPath string) (int64, bool) {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0, false
	}
	vol, ok1 := perfProcField(data, "voluntary_ctxt_switches")
	invol, ok2 := perfProcField(data, "nonvoluntary_ctxt_switches")
	return vol + invol, ok1 && ok2
}

func perfTakeProcSnapshot() perfProcSnapshot {
	var s perfProcSnapshot
	ioStats, err := os.ReadFile("/proc/self/io")
	if err != nil {
		return s
	}
	var ok1, ok2 bool
	s.syscr, ok1 = perfProcField(ioStats, "syscr")
	s.syscw, ok2 = perfProcField(ioStats, "syscw")
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return s
	}
	for _, t := range tasks {
		if n, ok := perfThreadSwitches("/proc/self/task/" + t.Name() + "/status"); ok {
			s.procSwitches += n
		}
	}
	var ok3 bool
	s.clientSwitches, ok3 = perfThreadSwitches("/proc/thread-self/status")
	s.ok = ok1 && ok2 && ok3
	return s
}

func perfReportServerSyscalls(b *testing.B, before, after perfProcSnapshot, unit string) {
	if !before.ok || !after.ok || b.N == 0 {
		return
	}
	n := float64(b.N)
	b.ReportMetric(float64(after.syscr-before.syscr)/n, "srv-read-syscalls/"+unit)
	b.ReportMetric(float64(after.syscw-before.syscw)/n, "srv-write-syscalls/"+unit)
	server := (after.procSwitches - before.procSwitches) - (after.clientSwitches - before.clientSwitches)
	b.ReportMetric(float64(server)/n, "srv-ctxsw/"+unit)
}

func BenchmarkPerfWSEcho(b *testing.B) {
	for _, tr := range perfTransports {
		for _, sz := range perfWSSizes {
			b.Run(tr.name+"/"+sz.name, func(b *testing.B) {
				if raceEnabled {
					b.Skip("the race detector distorts per-message cost")
				}
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				ts := perfWSStartServer(b, tr.tls)
				c := perfWSDial(b, ts, sz.size)
				for range perfWSWarmup {
					c.roundTrip(b)
				}
				b.SetBytes(int64(sz.size))
				b.ReportAllocs()
				before := perfTakeProcSnapshot()
				for b.Loop() {
					c.roundTrip(b)
				}
				after := perfTakeProcSnapshot()
				perfReportServerSyscalls(b, before, after, "msg")
			})
		}
	}
}

type perfReplayConn struct {
	stream []byte
	off    int
	reads  int
	writes int
}

func (c *perfReplayConn) Read(p []byte) (int, error) {
	c.reads++
	if c.off == len(c.stream) {
		c.off = 0
	}
	n := copy(p, c.stream[c.off:])
	c.off += n
	return n, nil
}

func (c *perfReplayConn) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}

func (c *perfReplayConn) Close() error                     { return nil }
func (c *perfReplayConn) LocalAddr() net.Addr              { return perfRawAddr }
func (c *perfReplayConn) RemoteAddr() net.Addr             { return perfRawAddr }
func (c *perfReplayConn) SetDeadline(time.Time) error      { return nil }
func (c *perfReplayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *perfReplayConn) SetWriteDeadline(time.Time) error { return nil }

func perfNewWS(conn net.Conn, compressionLevel int) *WSConn {
	return &WSConn{
		conn:             conn,
		readTimeout:      wsDefaultReadTimeout,
		writeTimeout:     wsDefaultWriteTimeout,
		MaxMessageSize:   wsDefaultMaxMessageSize,
		compressionLevel: compressionLevel,
	}
}

func perfWSText(size int) []byte {
	return bytes.Repeat([]byte(`{"type":"tick","seq":12345}`), size/27+1)[:size]
}

type perfReadCase struct {
	name       string
	size       int
	compressed bool
}

var perfReadCases = []perfReadCase{
	{"64B", perfWSSmall, false},
	{"16KB", perfWSLarge, false},
	{"16KB-deflate", perfWSLarge, true},
}

func perfReadCaseConn(tb testing.TB, rc perfReadCase) (*perfReplayConn, *WSConn) {
	payload := perfWSText(rc.size)
	first := byte(0x80 | wsOpText)
	level := 0
	if rc.compressed {
		payload = wsClientDeflate(tb, payload)
		first |= wsRSV1
		level = flate.BestSpeed
	}
	conn := &perfReplayConn{stream: wsClientFrame(first, payload)}
	return conn, perfNewWS(conn, level)
}

func BenchmarkPerfWSReadMessage(b *testing.B) {
	for _, rc := range perfReadCases {
		b.Run(rc.name, func(b *testing.B) {
			conn, ws := perfReadCaseConn(b, rc)
			b.SetBytes(int64(rc.size))
			b.ReportAllocs()
			for b.Loop() {
				if _, msg, err := ws.ReadMessage(); err != nil || len(msg) != rc.size {
					b.Fatalf("read: len %d err %v", len(msg), err)
				}
			}
			b.ReportMetric(float64(conn.reads)/float64(b.N), "reads/msg")
		})
	}
}

func BenchmarkPerfWSWriteMessage(b *testing.B) {
	for _, sz := range perfWSSizes {
		b.Run(sz.name, func(b *testing.B) {
			conn := &perfReplayConn{}
			ws := perfNewWS(conn, 0)
			msg := perfWSText(sz.size)
			b.SetBytes(int64(sz.size))
			b.ReportAllocs()
			for b.Loop() {
				if err := ws.WriteMessage(wsOpText, msg); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(conn.writes)/float64(b.N), "writes/msg")
		})
	}
}

func BenchmarkPerfWSMaskXOR(b *testing.B) {
	key := [4]byte{0x11, 0x22, 0x33, 0x44}
	for _, sz := range perfWSSizes {
		b.Run(sz.name, func(b *testing.B) {
			buf := perfWSText(sz.size)
			b.SetBytes(int64(sz.size))
			b.ReportAllocs()
			for b.Loop() {
				maskXOR(buf, key)
			}
		})
	}
}

func BenchmarkPerfWSFrameHeader(b *testing.B) {
	var dst [wsMaxFrameHeaderLen]byte
	lengths := [...]int{perfWSSmall, perfWSLarge, 1 << 20}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		_ = wsAppendFrameHeader(dst[:0], 0x80|wsOpText, lengths[i%len(lengths)])
		i++
	}
}

func TestPerfWSMaskXORAllocLock(t *testing.T) {
	key := [4]byte{0x11, 0x22, 0x33, 0x44}
	for _, sz := range perfWSSizes {
		buf := perfWSText(sz.size)
		if got := testing.AllocsPerRun(perfAllocLockRuns, func() { maskXOR(buf, key) }); got != 0 {
			t.Fatalf("maskXOR %s: %.0f allocs, want 0", sz.name, got)
		}
	}
}

func TestPerfWSFrameHeaderAllocLock(t *testing.T) {
	var dst [wsMaxFrameHeaderLen]byte
	for _, n := range []int{0, perfWSSmall, 126, perfWSLarge, 65536, 1 << 20} {
		if got := testing.AllocsPerRun(perfAllocLockRuns, func() { _ = wsAppendFrameHeader(dst[:0], 0x80|wsOpBinary, n) }); got != 0 {
			t.Fatalf("wsAppendFrameHeader(%d): %.0f allocs, want 0", n, got)
		}
	}
}

func TestPerfWSWriteMessageAllocLock(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation")
	}
	for _, sz := range perfWSSizes {
		ws := perfNewWS(&perfReplayConn{}, 0)
		msg := perfWSText(sz.size)
		if got := testing.AllocsPerRun(perfAllocLockRuns, func() { _ = ws.WriteMessage(wsOpText, msg) }); got != 0 {
			t.Fatalf("WriteMessage %s: %.0f allocs, want 0", sz.name, got)
		}
	}
}

func TestPerfWSEchoClientIsSyscallInvisible(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector distorts per-message cost")
	}
	a, b, err := perfSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	msg := []byte("ping")
	buf := make([]byte, len(msg))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	beforeR, beforeW, ok := perfThreadIO()
	if !ok {
		t.Skip("/proc/thread-self/io unavailable")
	}
	const rounds = 500
	for range rounds {
		if _, err := a.Write(msg); err != nil {
			t.Fatal(err)
		}
		if err := perfReadFull(b, buf); err != nil {
			t.Fatal(err)
		}
	}
	afterR, afterW, _ := perfThreadIO()
	if dr, dw := afterR-beforeR, afterW-beforeW; dr > perfProcReadSlack || dw > perfProcReadSlack {
		t.Fatalf("raw client thread moved syscr by %d and syscw by %d over %d rounds; server syscall metrics would be polluted", dr, dw, rounds)
	}
}

const perfProcReadSlack = 8

func perfThreadIO() (syscr, syscw int64, ok bool) {
	data, err := os.ReadFile("/proc/thread-self/io")
	if err != nil {
		return 0, 0, false
	}
	r, ok1 := perfProcField(data, "syscr")
	w, ok2 := perfProcField(data, "syscw")
	return r, w, ok1 && ok2
}

func perfSocketPair() (*perfRawConn, *perfRawConn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return &perfRawConn{fd: fds[0]}, &perfRawConn{fd: fds[1]}, nil
}

func perfTCPPair(tb testing.TB) (net.Conn, *perfRawConn) {
	tb.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	client := perfDialRaw(tb, ln.Addr().String())
	server := <-accepted
	if server == nil {
		tb.Fatal("accept failed")
	}
	tb.Cleanup(func() { _ = server.Close() })
	return server, client
}

func BenchmarkPerfWSSocketRead(b *testing.B) {
	frame := wsClientFrame(0x80|wsOpText, perfWSText(perfWSSmall))
	for _, split := range []bool{true, false} {
		name := "single-read"
		if split {
			name = "split-2-4-64"
		}
		b.Run(name, func(b *testing.B) {
			server, client := perfTCPPair(b)
			var hdr [2]byte
			var mask [4]byte
			payload := make([]byte, perfWSSmall)
			whole := make([]byte, len(frame))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := client.Write(frame); err != nil {
					b.Fatal(err)
				}
				var err error
				if split {
					if err = perfReadFull(server, hdr[:]); err == nil {
						if err = perfReadFull(server, mask[:]); err == nil {
							err = perfReadFull(server, payload)
						}
					}
				} else {
					err = perfReadFull(server, whole)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPerfWSConnDeadline(b *testing.B) {
	server, _ := perfTCPPair(b)
	b.Run("read-set", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = server.SetReadDeadline(wallDeadline(wsDefaultReadTimeout))
		}
	})
	b.Run("write-set-clear", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = server.SetWriteDeadline(wallDeadline(wsDefaultWriteTimeout))
			_ = server.SetWriteDeadline(time.Time{})
		}
	})
}
