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
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	tlsEpollFixShutdownCtx      = 450 * time.Millisecond
	tlsEpollFixGoAwayWait       = 150 * time.Millisecond
	tlsEpollFixExpiryCloseWait  = 300 * time.Millisecond
	tlsEpollFixH2cJunkLen       = 1 << 20
	tlsEpollFixHPACKMethodGET   = 0x82
	tlsEpollFixHPACKSchemeHTTP  = 0x86
	tlsEpollFixHPACKPathName    = 0x04
	tlsEpollFixHPACKAuthName    = 0x01
	tlsEpollFixH2Preface        = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	tlsEpollFixShutdownRaceRuns = 4
	tlsEpollFixServeReturnLimit = 10 * time.Second
)

type tlsEpollFixH2Frame struct {
	typ     byte
	flags   byte
	stream  uint32
	payload []byte
}

func tlsEpollFixH2Get(stream uint32, path string) []byte {
	block := []byte{tlsEpollFixHPACKMethodGET, tlsEpollFixHPACKSchemeHTTP, tlsEpollFixHPACKPathName, byte(len(path))}
	block = append(block, path...)
	block = append(block, tlsEpollFixHPACKAuthName, 1, 'x')
	return appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, stream, block)
}

func tlsEpollFixH2cConn(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr, harnessIOTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(wallDeadline(harnessIOTimeout))
	if _, err := io.WriteString(c, tlsEpollFixH2Preface+string(appendH2Frame(nil, H2FrameSettings, 0, 0, nil))); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	for f := tlsEpollFixReadH2Frame(t, br); f.typ != H2FrameSettings; f = tlsEpollFixReadH2Frame(t, br) {
	}
	return c, br
}

func tlsEpollFixReadH2Frame(t *testing.T, br *bufio.Reader) tlsEpollFixH2Frame {
	t.Helper()
	f, err := tlsEpollFixTryReadH2Frame(br)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return f
}

func tlsEpollFixTryReadH2Frame(br *bufio.Reader) (tlsEpollFixH2Frame, error) {
	var hdr [h2FrameHeaderSize]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return tlsEpollFixH2Frame{}, err
	}
	f := tlsEpollFixH2Frame{typ: hdr[3], flags: hdr[4], stream: binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff}
	f.payload = make([]byte, int(hdr[0])<<16|int(hdr[1])<<8|int(hdr[2]))
	_, err := io.ReadFull(br, f.payload)
	return f, err
}

func tlsEpollFixShutdownAsync(srv *Server, timeout time.Duration) <-chan error {
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		done <- srv.Shutdown(ctx)
	}()
	return done
}

func TestTLSEpollFixShutdownGoAwaysBusyH2(t *testing.T) {
	h := newBlockingHandler()
	ts := newTestServer(t, testServerOptions{Routes: h.route})
	c, br := tlsEpollFixH2cConn(t, ts.addr)
	if _, err := c.Write(tlsEpollFixH2Get(1, "/block")); err != nil {
		t.Fatal(err)
	}
	h.awaitEntered(t)
	shutdown := tlsEpollFixShutdownAsync(ts.srv, tlsEpollFixShutdownCtx)
	_ = c.SetReadDeadline(wallDeadline(tlsEpollFixGoAwayWait))
	for {
		f, err := tlsEpollFixTryReadH2Frame(br)
		if err != nil {
			t.Fatalf("no GOAWAY within %v of Shutdown on a conn with a busy stream: %v", tlsEpollFixGoAwayWait, err)
		}
		if f.typ == H2FrameGoAway {
			if last := binary.BigEndian.Uint32(f.payload) & 0x7fffffff; last != 1 || binary.BigEndian.Uint32(f.payload[4:]) != H2ErrNoError {
				t.Fatalf("shutdown GOAWAY last-stream %d code %d, want 1 NO_ERROR", last, binary.BigEndian.Uint32(f.payload[4:]))
			}
			break
		}
	}
	_ = c.SetDeadline(wallDeadline(harnessIOTimeout))
	if _, err := c.Write(tlsEpollFixH2Get(3, "/ok")); err != nil {
		t.Fatal(err)
	}
	for {
		f := tlsEpollFixReadH2Frame(t, br)
		if f.stream != 3 {
			continue
		}
		if f.typ != H2FrameRSTStream || binary.BigEndian.Uint32(f.payload) != H2ErrRefusedStream {
			t.Fatalf("stream 3 opened after the shutdown GOAWAY got frame type %d, want RST_STREAM(REFUSED_STREAM)", f.typ)
		}
		break
	}
	close(h.release)
	served := false
	for {
		f, err := tlsEpollFixTryReadH2Frame(br)
		if err != nil {
			if !served {
				t.Fatalf("stream 1 not answered before close: %v", err)
			}
			break
		}
		served = served || (f.stream == 1 && f.typ == H2FrameData && strings.Contains(string(f.payload), "late body"))
	}
	if err := <-shutdown; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestTLSEpollFixShutdownClosesBusyH1AfterResponse(t *testing.T) {
	h := newBlockingHandler()
	ts := newTestServer(t, testServerOptions{Routes: h.route})
	c := ts.dial(t)
	if _, err := io.WriteString(c, "GET /block HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	h.awaitEntered(t)
	shutdown := tlsEpollFixShutdownAsync(ts.srv, tlsEpollFixShutdownCtx)
	for !ts.srv.shuttingDown.Load() {
		turbo.Sleep(harnessPollInterval)
	}
	close(h.release)
	br := bufio.NewReader(c)
	resp, body := readH1Response(t, br, "GET")
	if resp.StatusCode != 200 || string(body) != "late body" {
		t.Fatalf("in-flight request answered %d %q", resp.StatusCode, body)
	}
	if !resp.Close {
		t.Fatalf("response written during Shutdown kept the connection alive (Connection: %q)", resp.Header.Get("Connection"))
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("conn after the last response: %v, want EOF", err)
	}
	if err := <-shutdown; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestTLSEpollFixShutdownExpiryClosesStalledConns(t *testing.T) {
	ts := newTestServer(t, testServerOptions{})
	c := ts.dial(t)
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost:"); err != nil {
		t.Fatal(err)
	}
	h2, br := tlsEpollFixH2cConn(t, ts.addr)
	partial := tlsEpollFixH2Get(1, "/")
	if _, err := h2.Write(partial[:len(partial)-1]); err != nil {
		t.Fatal(err)
	}
	turbo.Sleep(harnessPollInterval)
	if err := <-tlsEpollFixShutdownAsync(ts.srv, tlsEpollFixGoAwayWait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown with stalled conns returned %v, want deadline exceeded", err)
	}
	_ = c.SetReadDeadline(wallDeadline(tlsEpollFixExpiryCloseWait))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("stalled HTTP/1.1 conn still open %v after the Shutdown deadline: %v", tlsEpollFixExpiryCloseWait, err)
	}
	_ = h2.SetReadDeadline(wallDeadline(tlsEpollFixExpiryCloseWait))
	for {
		if _, err := tlsEpollFixTryReadH2Frame(br); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("stalled h2c conn still open %v after the Shutdown deadline: %v", tlsEpollFixExpiryCloseWait, err)
			}
			break
		}
	}
}

func TestTLSEpollFixH2cErrorCloseLingers(t *testing.T) {
	h := newBlockingHandler()
	ts := newTestServer(t, testServerOptions{
		Config: func(c *Config) { c.MaxReadSize = tlsEpollFixSmallReadCap; c.InlineHandlers = true },
		Routes: h.route,
	})
	c, br := tlsEpollFixH2cConn(t, ts.addr)
	blocker := ts.dial(t)
	if _, err := io.WriteString(blocker, "GET /block HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	h.awaitEntered(t)
	wire := append(tlsEpollFixH2Get(2, "/"), make([]byte, tlsEpollFixH2cJunkLen)...)
	go func() { _, _ = c.Write(wire) }()
	turbo.Sleep(tlsEpollFixGoAwayWait)
	close(h.release)
	gotGoAway := false
	for {
		f, err := tlsEpollFixTryReadH2Frame(br)
		if err != nil {
			if errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("h2c conn closed with RST after its GOAWAY (goaway read: %v): the close skipped the linger", gotGoAway)
			}
			if !errors.Is(err, io.EOF) {
				t.Fatalf("read after GOAWAY: %v", err)
			}
			break
		}
		gotGoAway = gotGoAway || (f.typ == H2FrameGoAway && binary.BigEndian.Uint32(f.payload[4:]) == H2ErrProtocol)
	}
	if !gotGoAway {
		t.Fatal("no PROTOCOL_ERROR GOAWAY before EOF")
	}
}

func TestTLSEpollFixShutdownDuringTLSStartupRaceFree(t *testing.T) {
	for i := 0; i < tlsEpollFixShutdownRaceRuns; i++ {
		srv := New(Config{Addr: freeLoopbackAddr(t), HTTPAddr: "-", MaxConnsPerIP: -1, Listeners: 1, Certs: []CertConfig{{Domain: harnessDomain, Source: CertSelfSigned}}})
		served := make(chan error, 1)
		go func() { served <- srv.ListenAndServeTLS() }()
		if err := <-tlsEpollFixShutdownAsync(srv, harnessIOTimeout); err != nil {
			t.Fatalf("run %d: Shutdown: %v", i, err)
		}
		select {
		case <-served:
		case <-turbo.After(tlsEpollFixServeReturnLimit):
			t.Fatalf("run %d: ListenAndServeTLS did not return after Shutdown", i)
		}
	}
}

func TestTLSEpollFixCloseNotifySurvivesFullSendBuffer(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	filler := make([]byte, epollDiscardBufSize)
	for {
		if _, err := unix.Write(fds[0], filler); err != nil {
			break
		}
	}
	p := newTLSEpollFixPeer(t)
	p.conn.fd = fds[0]
	p.conn.worker = &epollWorker{}
	p.conn.sendCloseNotify()
	p.conn.writeBuf = p.conn.writeBuf[p.conn.writeSent:]
	recs := p.serverRecords(t)
	if len(recs) != 1 || recs[0].innerType != tlsRecAlert || !bytes.Equal(recs[0].content, []byte{tlsAlertLevelWarning, byte(alertCloseNotify)}) {
		t.Fatalf("close_notify sent into a full socket left %d pending records %+v; the alert must stay queued for the flush", len(recs), recs)
	}
}
