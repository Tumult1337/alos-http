//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func startRootCountServer(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	addr := startH2FixServer(t, nil, func(srv *Server) {
		srv.Router.GET("/", func(req *Request, resp *Response) {
			n := calls.Add(1)
			resp.Status(200).String("call-" + strconv.FormatInt(n, 10))
		})
	})
	return addr, &calls
}

func TestRootGETH1RunsHandlerPerRequest(t *testing.T) {
	addr, calls := startRootCountServer(t)
	conn, err := net.DialTimeout("tcp", addr, h2FixCeiling)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(h2FixCeiling))
	br := bufio.NewReader(conn)
	before := calls.Load()
	for i := range 3 {
		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: root.test\r\n\r\n")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status %d = %d", i, resp.StatusCode)
		}
	}
	if got := calls.Load() - before; got != 3 {
		t.Fatalf("handler ran %d times for 3 GET / requests over H1, want 3", got)
	}
}

func TestRootGETH2RunsHandlerPerRequest(t *testing.T) {
	addr, calls := startRootCountServer(t)
	rc := h2RawDial(t, addr, nil)
	before := calls.Load()
	for i := range 3 {
		streamID := uint32(2*i + 1)
		h2FixGet(rc, streamID, "/")
		if _, ended, err := rc.readStreamBody(streamID); err != nil || !ended {
			t.Fatalf("stream %d: ended=%v err=%v", streamID, ended, err)
		}
	}
	if got := calls.Load() - before; got != 3 {
		t.Fatalf("handler ran %d times for 3 GET / requests over H2, want 3", got)
	}
}

func TestRootGETH2HonorsZeroStreamWindow(t *testing.T) {
	addr, _ := startRootCountServer(t)
	rc := h2RawDial(t, addr, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0}))
	h2FixGet(rc, 1, "/")
	sawHeaders := false
	for _, f := range rc.framesWithin(h2FixQuietWindow) {
		if f.streamID != 1 {
			continue
		}
		switch f.typ {
		case H2FrameHeaders:
			sawHeaders = true
		case H2FrameData:
			if len(f.payload) > 0 {
				t.Fatalf("server sent %d DATA bytes on stream 1 with a zero stream window", len(f.payload))
			}
		}
	}
	if !sawHeaders {
		t.Fatal("server sent no HEADERS for GET / with a zero stream window")
	}
	rc.write(H2FrameWindowUpdate, 0, 1, h2FixWindowIncrement(1<<16))
	_ = rc.conn.SetReadDeadline(time.Now().Add(h2FixCeiling))
	n, ended, err := rc.readStreamBody(1)
	if err != nil || !ended || n == 0 {
		t.Fatalf("after WINDOW_UPDATE: body=%d ended=%v err=%v", n, ended, err)
	}
}

func TestH2HalfClosedPeerIsClosedAfterAsyncResponse(t *testing.T) {
	addr := startH2FixServer(t, nil, func(srv *Server) {
		srv.Router.GET("/slow", func(req *Request, resp *Response) {
			time.Sleep(h2FixHandlerDelay)
			resp.Status(200).String("late")
		})
	})
	conn, err := net.DialTimeout("tcp", addr, h2FixCeiling)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(h2FixCeiling))
	hello := append([]byte(nil), H2ClientPreface[:]...)
	hello = appendH2Frame(hello, H2FrameSettings, 0, 0, nil)
	hello = appendH2Frame(hello, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/slow"))
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("server kept a half-closed connection open after its last response: read %d bytes, %v", len(out), err)
	}
	if !bytes.Contains(out, []byte("late")) {
		t.Fatalf("response body missing from %d bytes", len(out))
	}
}

func TestH2PeerEOFDuringHandlerStillGetsResponse(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	addr := startH2FixServer(t, nil, func(srv *Server) {
		srv.Router.GET("/held", func(req *Request, resp *Response) {
			close(entered)
			<-release
			resp.Status(200).String("held-body")
		})
	})
	conn, err := net.DialTimeout("tcp", addr, h2FixCeiling)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(h2FixCeiling))
	hello := append([]byte(nil), H2ClientPreface[:]...)
	hello = appendH2Frame(hello, H2FrameSettings, 0, 0, nil)
	hello = appendH2Frame(hello, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/held"))
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(h2FixCeiling):
		t.Fatal("handler did not start")
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(h2FixQuietWindow)
	close(release)
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after half-close: %d bytes, %v", len(out), err)
	}
	if !bytes.Contains(out, []byte("held-body")) {
		t.Fatalf("response of the in-flight stream was dropped at peer EOF: got %d bytes", len(out))
	}
}
