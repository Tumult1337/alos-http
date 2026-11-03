//go:build linux && amd64

package core

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

const (
	h2TLSStallTimeout = 300 * time.Millisecond
	h2TLSStallWait    = time.Duration(epollSweepIntervalMs)*time.Millisecond*2 + h2TLSStallTimeout
)

func h2TLSStallServer(t *testing.T, tune func(*Config)) *testServer {
	t.Helper()
	big := make([]byte, 1<<20)
	chunk := make([]byte, 100<<10)
	return newTestServer(t, testServerOptions{
		TLS:    true,
		Config: tune,
		Routes: func(r *Router) {
			r.GET("/ok", func(_ *Request, resp *Response) { resp.Status(200).String("ok") })
			r.GET("/big", func(_ *Request, resp *Response) { resp.Status(200).Bytes(big) })
			r.GET("/streamed", func(_ *Request, resp *Response) {
				sw := resp.EnsureStreamWriter()
				resp.SetStreamer(sw)
				_ = sw.WriteHeader(200, nil, "application/octet-stream")
				_ = sw.WriteChunk(chunk)
				_ = sw.Close()
			})
			r.POST("/up", func(req *Request, resp *Response) {
				if s := req.BodyStream(); s != nil {
					_, _ = io.ReadAll(s)
				}
				resp.Status(200).String("up")
			})
		},
	})
}

func h2TLSDial(t *testing.T, ts *testServer, settings []byte) *h2RawConn {
	t.Helper()
	conn, err := tls.Dial("tcp4", ts.addr, ts.tlsConfig("h2"))
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("ALPN = %q, want h2", conn.ConnectionState().NegotiatedProtocol)
	}
	return h2RawStart(t, conn, settings)
}

func h2TLSRequest(method, path string) []byte {
	return hpackBlock([2]string{":method", method}, [2]string{":scheme", "https"}, [2]string{":path", path}, [2]string{":authority", harnessDomain})
}

func h2TLSAwaitReset(t *testing.T, rc *h2RawConn, streamID uint32) {
	t.Helper()
	end := time.Now().Add(h2TLSStallWait + 3*time.Second)
	for time.Now().Before(end) {
		_ = rc.conn.SetReadDeadline(time.Now().Add(h2TLSStallTimeout / 2))
		f, err := rc.tryRead()
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			rc.write(H2FramePing, 0, 0, make([]byte, 8))
			continue
		}
		if err != nil {
			t.Fatalf("no RST_STREAM for stream %d over TLS: %v", streamID, err)
		}
		if f.typ == H2FrameGoAway {
			t.Fatalf("GOAWAY instead of RST_STREAM for stream %d", streamID)
		}
		if f.typ == H2FrameRSTStream && f.streamID == streamID {
			if code := binary.BigEndian.Uint32(f.payload); code != H2ErrCancel {
				t.Fatalf("stream %d reset with code %d, want CANCEL", streamID, code)
			}
			return
		}
	}
	t.Fatalf("no RST_STREAM for stream %d within %v", streamID, h2TLSStallWait+3*time.Second)
}

func h2TLSSiblingCompletes(t *testing.T, rc *h2RawConn, streamID uint32, credit bool) {
	t.Helper()
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, streamID, h2TLSRequest("GET", "/ok"))
	if credit {
		rc.write(H2FrameWindowUpdate, 0, streamID, h2FixWindowIncrement(1<<16))
		rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(1<<16))
	}
	_ = rc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, ended, err := rc.readStreamBody(streamID)
	if err != nil || !ended || n != 2 {
		t.Fatalf("sibling stream %d after the reset: body=%d ended=%v err=%v", streamID, n, ended, err)
	}
}

func TestH2StalledStreamResetOverTLS(t *testing.T) {
	zeroWindow := h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0})
	for _, tc := range []struct {
		name     string
		tune     func(*Config)
		settings []byte
		open     func(rc *h2RawConn)
		credit   bool
	}{
		{"buffered-body", func(c *Config) { c.ReadTimeout = h2TLSStallTimeout }, nil, func(rc *h2RawConn) {
			rc.write(H2FrameHeaders, H2FlagEndHeaders, 1, h2TLSRequest("POST", "/up"))
		}, false},
		{"streamed-body", func(c *Config) { c.ReadTimeout = h2TLSStallTimeout; c.StreamBodyAbove = 1 }, nil, func(rc *h2RawConn) {
			rc.write(H2FrameHeaders, H2FlagEndHeaders, 1, h2TLSRequest("POST", "/up"))
		}, false},
		{"parked-response", func(c *Config) { c.WriteTimeout = h2TLSStallTimeout }, zeroWindow, func(rc *h2RawConn) {
			rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2TLSRequest("GET", "/big"))
		}, true},
		{"streamed-response", func(c *Config) { c.WriteTimeout = h2TLSStallTimeout }, zeroWindow, func(rc *h2RawConn) {
			rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2TLSRequest("GET", "/streamed"))
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := h2TLSStallServer(t, tc.tune)
			rc := h2TLSDial(t, ts, tc.settings)
			tc.open(rc)
			h2TLSAwaitReset(t, rc, 1)
			h2TLSSiblingCompletes(t, rc, 3, tc.credit)
		})
	}
}

func TestH2PeerFINUnderTLSEndsStalledStreamCleanly(t *testing.T) {
	ts := h2TLSStallServer(t, func(c *Config) { c.WriteTimeout = time.Hour })
	raw, err := net.DialTimeout("tcp4", ts.addr, harnessIOTimeout)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, ts.tlsConfig("h2"))
	t.Cleanup(func() { _ = tc.Close() })
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	rc := h2RawStart(t, tc, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), 0}))
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2TLSRequest("GET", "/streamed"))
	time.Sleep(h2TLSStallTimeout)
	if err := raw.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		f, err := rc.tryRead()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("connection end after a TCP FIN under TLS: %v, want a clean EOF", err)
		}
		if f.typ == H2FrameRSTStream && f.streamID == 1 {
			if code := binary.BigEndian.Uint32(f.payload); code != H2ErrCancel {
				t.Fatalf("reset code %d, want CANCEL", code)
			}
		}
	}
}
