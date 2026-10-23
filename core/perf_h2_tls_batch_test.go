//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
)

const (
	perfH2MixedPairs      = 12
	perfH2MixedBigBody    = 300001
	perfH2MixedPatternMod = 251
	perfH2MixedReadBuffer = 4096
)

func perfH2MixedPattern() []byte {
	body := make([]byte, perfH2MixedBigBody)
	for i := range body {
		body[i] = byte(i % perfH2MixedPatternMod)
	}
	return body
}

func perfH2MixedRoutes(srv *Server) {
	pattern := perfH2MixedPattern()
	srv.Router.GET("/pattern", func(req *Request, resp *Response) { resp.Status(200).Bytes(pattern) })
	srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
}

func perfH2CheckMixedResponses(t *testing.T, rc *h2RawConn) {
	t.Helper()
	rc.write(H2FrameSettings, 0, 0, h2FixSettings([2]uint32{uint32(H2SettingInitialWindowSize), h2FixMaxWindow}))
	rc.write(H2FrameWindowUpdate, 0, 0, h2FixWindowIncrement(h2FixMaxWindow-H2DefaultWindowSize))
	want := make(map[uint32]int, 2*perfH2MixedPairs)
	for i := range perfH2MixedPairs {
		big, small := uint32(4*i+1), uint32(4*i+3)
		h2FixGet(rc, big, "/pattern")
		h2FixGet(rc, small, "/ok")
		want[big], want[small] = perfH2MixedBigBody, len("ok")
	}
	got := make(map[uint32][]byte, len(want))
	ended := 0
	for ended < len(want) {
		f, err := rc.tryRead()
		if err != nil {
			t.Fatalf("read after %d/%d streams ended: %v", ended, len(want), err)
		}
		if _, ok := want[f.streamID]; !ok {
			continue
		}
		switch f.typ {
		case H2FrameRSTStream, H2FrameGoAway:
			t.Fatalf("stream %d ended with frame type %d", f.streamID, f.typ)
		case H2FrameHeaders:
			if f.fieldErr != nil {
				t.Fatalf("stream %d headers: %v", f.streamID, f.fieldErr)
			}
		case H2FrameData:
			got[f.streamID] = append(got[f.streamID], f.payload...)
			if f.flags&H2FlagEndStream != 0 {
				ended++
			}
		}
	}
	pattern := perfH2MixedPattern()
	for id, n := range want {
		body := got[id]
		if len(body) != n {
			t.Fatalf("stream %d: %d body bytes, want %d", id, len(body), n)
		}
		if n == perfH2MixedBigBody && !bytes.Equal(body, pattern) {
			t.Fatalf("stream %d: large body corrupted", id)
		}
		if n != perfH2MixedBigBody && string(body) != "ok" {
			t.Fatalf("stream %d: body %q, want ok", id, body)
		}
	}
}

func TestH2TLSMixedLargeAndSmallResponsesStayIntact(t *testing.T) {
	addr := startH2FixServer(t, func(c *Config) {
		c.PlainHTTP = false
		c.Certs = []CertConfig{{Domain: h2FixAuthority, Source: CertSelfSigned}}
	}, perfH2MixedRoutes)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: h2FixCeiling}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: h2FixAuthority, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	rc, _ := h2HandshakeCaptureSettings(t, conn)
	perfH2CheckMixedResponses(t, rc)
}

func TestH2cMixedLargeAndSmallResponsesSurvivePartialWrites(t *testing.T) {
	addr := startH2FixServer(t, nil, perfH2MixedRoutes)
	rc := h2RawDial(t, addr, nil)
	if tcp, ok := rc.conn.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(perfH2MixedReadBuffer)
	}
	perfH2CheckMixedResponses(t, rc)
}
