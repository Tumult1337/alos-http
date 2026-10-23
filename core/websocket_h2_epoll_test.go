//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

func hpackLiteral(name, value string) []byte {
	out := []byte{0x00, byte(len(name))}
	out = append(out, name...)
	out = append(out, byte(len(value)))
	return append(out, value...)
}

func hpackBlock(fields ...[2]string) []byte {
	var block []byte
	for _, f := range fields {
		block = append(block, hpackLiteral(f[0], f[1])...)
	}
	return block
}

func h2DialCaptureSettings(t *testing.T, addr string) (*h2RawConn, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, harnessIOTimeout)
	if err != nil {
		t.Fatal(err)
	}
	return h2HandshakeCaptureSettings(t, conn)
}

func h2HandshakeCaptureSettings(t *testing.T, conn net.Conn) (*h2RawConn, []byte) {
	t.Helper()
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(wallDeadline(5 * time.Second))
	rc := &h2RawConn{t: t, conn: conn}
	if _, err := conn.Write(H2ClientPreface[:]); err != nil {
		t.Fatal(err)
	}
	rc.write(H2FrameSettings, 0, 0, nil)
	for {
		f := rc.read()
		if f.typ == H2FrameSettings && f.flags&H2FlagAck == 0 {
			rc.write(H2FrameSettings, H2FlagAck, 0, nil)
			return rc, f.payload
		}
	}
}

func h2SettingValue(payload []byte, id uint16) (uint32, bool) {
	for i := 0; i+6 <= len(payload); i += 6 {
		if binary.BigEndian.Uint16(payload[i:]) == id {
			return binary.BigEndian.Uint32(payload[i+2:]), true
		}
	}
	return 0, false
}

type h2WSStream struct {
	t     *testing.T
	rc    *h2RawConn
	id    uint32
	buf   []byte
	ended bool
}

func (s *h2WSStream) send(frame []byte) {
	for len(frame) > 0 {
		n := min(len(frame), H2DefaultMaxFrameSize)
		s.rc.write(H2FrameData, 0, s.id, frame[:n])
		frame = frame[n:]
	}
}

func (s *h2WSStream) next() (wsServerFrame, error) {
	for {
		if f, err := wsReadServerFrame(bytes.NewReader(s.buf)); err == nil {
			s.buf = s.buf[2+wsExtLen(s.buf)+len(f.payload):]
			return f, nil
		}
		if s.ended {
			return wsServerFrame{}, io.EOF
		}
		f, err := s.rc.tryRead()
		if err != nil {
			return wsServerFrame{}, err
		}
		if f.streamID != s.id {
			continue
		}
		switch f.typ {
		case H2FrameData:
			s.buf = append(s.buf, f.payload...)
			s.ended = f.flags&H2FlagEndStream != 0
		case H2FrameRSTStream:
			return wsServerFrame{}, errors.New("stream reset")
		}
	}
}

func wsExtLen(b []byte) int {
	switch b[1] & 0x7F {
	case 126:
		return 2
	case 127:
		return 8
	}
	return 0
}

func openH2WebSocket(t *testing.T, rc *h2RawConn, id uint32, path string, extra ...[2]string) (*h2WSStream, map[string]string) {
	t.Helper()
	fields := append([][2]string{
		{":method", "CONNECT"}, {":protocol", "websocket"}, {":scheme", "http"}, {":path", path}, {":authority", harnessDomain},
		{"sec-websocket-version", "13"},
	}, extra...)
	rc.write(H2FrameHeaders, H2FlagEndHeaders, id, hpackBlock(fields...))
	f, err := rc.awaitStreamOutcome(id)
	if err != nil {
		t.Fatal(err)
	}
	if f.typ != H2FrameHeaders {
		t.Fatalf("extended CONNECT answered with frame type %d", f.typ)
	}
	hdrs, err := f.fields, f.fieldErr
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, kv := range hdrs {
		got[kv[0]] = kv[1]
	}
	return &h2WSStream{t: t, rc: rc, id: id}, got
}

type h2WSServer struct {
	ts    *testServer
	ended chan error
}

func startH2WSServer(t *testing.T, tune func(*Config)) *h2WSServer {
	return startH2WSServerTLS(t, false, tune)
}

func startH2WSServerTLS(t *testing.T, useTLS bool, tune func(*Config)) *h2WSServer {
	t.Helper()
	s := &h2WSServer{ended: make(chan error, 8)}
	echo := func(ws *WSConn) error {
		for {
			op, msg, err := ws.ReadMessage()
			if err != nil {
				return err
			}
			if err := ws.WriteMessage(op, append([]byte(ws.Subprotocol()+">"), msg...)); err != nil {
				return err
			}
		}
	}
	s.ts = newTestServer(t, testServerOptions{
		TLS: useTLS,
		Config: func(cfg *Config) {
			cfg.PlainHTTP = !useTLS
			if tune != nil {
				tune(cfg)
			}
		},
		Routes: func(r *Router) {
			r.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
			r.GET("/ws", func(req *Request, resp *Response) {
				ServeWebSocketWith(req, resp, WSUpgradeOptions{Subprotocols: []string{"chat"}, Compression: true}, func(ws *WSConn) {
					s.ended <- echo(ws)
				})
			})
			r.GET("/detached", func(req *Request, resp *Response) {
				ws := UpgradeWebSocket(req, resp)
				if ws == nil {
					return
				}
				go func() {
					_, msg, err := ws.ReadMessage()
					if err == nil {
						_ = ws.WriteText("detached>" + string(msg))
					}
					_ = ws.Close()
					s.ended <- err
				}()
			})
		},
	})
	return s
}

func TestWebSocketH2SettingAdvertised(t *testing.T) {
	s := startH2WSServer(t, nil)
	_, settings := h2DialCaptureSettings(t, s.ts.addr)
	if v, ok := h2SettingValue(settings, H2SettingEnableConnectProtocol); !ok || v != 1 {
		t.Fatalf("SETTINGS_ENABLE_CONNECT_PROTOCOL = %d (present %v)", v, ok)
	}
}

func TestWebSocketH2Echo(t *testing.T) {
	s := startH2WSServer(t, func(cfg *Config) { cfg.MaxBodySize = 1 << 10 })
	rc, _ := h2DialCaptureSettings(t, s.ts.addr)
	ws, hdrs := openH2WebSocket(t, rc, 1, "/ws",
		[2]string{"sec-websocket-protocol", "chat"}, [2]string{"sec-websocket-extensions", "permessage-deflate"})
	if hdrs[":status"] != "200" || hdrs["sec-websocket-protocol"] != "chat" || hdrs["sec-websocket-extensions"] != wsDeflateAcceptance {
		t.Fatalf("response headers %v", hdrs)
	}
	if _, ok := hdrs["sec-websocket-accept"]; ok {
		t.Fatal("Sec-WebSocket-Accept sent over HTTP/2")
	}

	ws.send(wsClientFrame(0x80|wsOpText, []byte("hello")))
	if f, err := ws.next(); err != nil || string(f.payload) != "chat>hello" || f.compressed() {
		t.Fatalf("echo %+v err %v", f, err)
	}
	big := []byte(strings.Repeat("over h2 ", 300))
	for range 4 {
		ws.send(wsClientFrame(0x80|wsRSV1|wsOpBinary, wsClientDeflate(t, big)))
		f, err := ws.next()
		if err != nil || !f.compressed() || !bytes.Equal(wsClientInflate(t, f.payload), append([]byte("chat>"), big...)) {
			t.Fatalf("compressed echo err %v", err)
		}
	}

	ws.send(wsClientFrame(0x80|wsOpClose, []byte{0x03, 0xe8}))
	if f, err := ws.next(); err != nil || wsCloseCode(f) != 1000 {
		t.Fatalf("close echo %+v err %v", f, err)
	}
	if _, err := ws.next(); err != io.EOF {
		t.Fatalf("stream not ended after close: %v", err)
	}
	select {
	case err := <-s.ended:
		if err != io.EOF {
			t.Fatalf("handler ended with %v", err)
		}
	case <-turbo.After(harnessIOTimeout):
		t.Fatal("handler did not end")
	}

	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, hpackBlock([2]string{":method", "GET"}, [2]string{":scheme", "http"}, [2]string{":path", "/ok"}, [2]string{":authority", harnessDomain}))
	if f, err := rc.awaitStreamOutcome(3); err != nil || f.typ != H2FrameHeaders || f.status(t) != 200 {
		t.Fatalf("connection unusable after the WebSocket: %+v %v", f, err)
	}
}

func TestWebSocketH2DetachedHandler(t *testing.T) {
	s := startH2WSServer(t, nil)
	rc, _ := h2DialCaptureSettings(t, s.ts.addr)
	ws, hdrs := openH2WebSocket(t, rc, 1, "/detached")
	if hdrs[":status"] != "200" {
		t.Fatalf("headers %v", hdrs)
	}
	ws.send(wsClientFrame(0x80|wsOpText, []byte("ping")))
	if f, err := ws.next(); err != nil || string(f.payload) != "detached>ping" {
		t.Fatalf("echo %+v err %v", f, err)
	}
	if f, err := ws.next(); err != nil || f.opcode() != wsOpClose {
		t.Fatalf("close %+v err %v", f, err)
	}
	if _, err := ws.next(); err != io.EOF {
		t.Fatalf("stream not ended: %v", err)
	}
}

func TestWebSocketH2ClientReset(t *testing.T) {
	s := startH2WSServer(t, nil)
	rc, _ := h2DialCaptureSettings(t, s.ts.addr)
	ws, _ := openH2WebSocket(t, rc, 1, "/ws")
	ws.send(wsClientFrame(0x80|wsOpText, []byte("x")))
	if _, err := ws.next(); err != nil {
		t.Fatal(err)
	}
	rc.write(H2FrameRSTStream, 0, 1, binary.BigEndian.AppendUint32(nil, uint32(H2ErrCancel)))
	select {
	case err := <-s.ended:
		if err == nil {
			t.Fatal("handler read succeeded after RST_STREAM")
		}
	case <-turbo.After(3 * sseHeartbeatTestInterval):
		t.Fatal("handler still running after RST_STREAM")
	}
}

func TestWebSocketH2MalformedRequests(t *testing.T) {
	s := startH2WSServer(t, nil)
	rc, _ := h2DialCaptureSettings(t, s.ts.addr)
	cases := []struct {
		id     uint32
		fields [][2]string
	}{
		{1, [][2]string{{":method", "GET"}, {":protocol", "websocket"}, {":scheme", "http"}, {":path", "/ws"}, {":authority", harnessDomain}}},
		{3, [][2]string{{":method", "CONNECT"}, {":protocol", "websocket"}, {":scheme", "http"}, {":authority", harnessDomain}}},
		{5, [][2]string{{":method", "CONNECT"}, {":protocol", "websocket"}, {":path", "/ws"}, {":authority", harnessDomain}}},
		{7, [][2]string{{":method", "GET"}, {":scheme", "http"}, {":authority", harnessDomain}}},
	}
	for _, c := range cases {
		rc.write(H2FrameHeaders, H2FlagEndHeaders, c.id, hpackBlock(c.fields...))
		f, err := rc.awaitStreamOutcome(c.id)
		if err != nil || f.typ != H2FrameRSTStream || binary.BigEndian.Uint32(f.payload) != uint32(H2ErrProtocol) {
			t.Fatalf("stream %d: frame %+v err %v, want RST_STREAM(PROTOCOL_ERROR)", c.id, f, err)
		}
	}
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 9, hpackBlock([2]string{":method", "GET"}, [2]string{":scheme", "http"}, [2]string{":path", "/ok"}, [2]string{":authority", harnessDomain}))
	if f, err := rc.awaitStreamOutcome(9); err != nil || f.typ != H2FrameHeaders || f.status(t) != 200 {
		t.Fatalf("connection unusable after malformed requests: %+v %v", f, err)
	}
}

func TestWebSocketH2RejectsBadVersion(t *testing.T) {
	s := startH2WSServer(t, nil)
	rc, _ := h2DialCaptureSettings(t, s.ts.addr)
	rc.write(H2FrameHeaders, H2FlagEndHeaders, 1, hpackBlock(
		[2]string{":method", "CONNECT"}, [2]string{":protocol", "websocket"}, [2]string{":scheme", "http"},
		[2]string{":path", "/ws"}, [2]string{":authority", harnessDomain}, [2]string{"sec-websocket-version", "8"}))
	f, err := rc.awaitStreamOutcome(1)
	if err != nil || f.typ != H2FrameHeaders || f.status(t) != 426 {
		t.Fatalf("frame %+v err %v, want 426", f, err)
	}
}

func TestWebSocketH2EchoTLS(t *testing.T) {
	s := startH2WSServerTLS(t, true, nil)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: harnessIOTimeout}, "tcp4", s.ts.addr, s.ts.tlsConfig("h2"))
	if err != nil {
		t.Fatal(err)
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("ALPN %q", conn.ConnectionState().NegotiatedProtocol)
	}
	rc, settings := h2HandshakeCaptureSettings(t, conn)
	if v, _ := h2SettingValue(settings, H2SettingEnableConnectProtocol); v != 1 {
		t.Fatal("SETTINGS_ENABLE_CONNECT_PROTOCOL not advertised over TLS")
	}
	ws, hdrs := openH2WebSocket(t, rc, 1, "/ws", [2]string{"sec-websocket-protocol", "chat"})
	if hdrs[":status"] != "200" || hdrs["sec-websocket-protocol"] != "chat" {
		t.Fatalf("headers %v", hdrs)
	}
	msg := []byte(strings.Repeat("tls ", 5000))
	ws.send(wsClientFrame(0x80|wsOpBinary, msg))
	if f, err := ws.next(); err != nil || !bytes.Equal(f.payload, append([]byte("chat>"), msg...)) {
		t.Fatalf("echo err %v (%d bytes)", err, len(f.payload))
	}
}
