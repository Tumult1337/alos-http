//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"
)

const wsSampleKey = "dGhlIHNhbXBsZSBub25jZQ=="

func wsUpgradeRequest(domain string, extra ...string) string {
	var b strings.Builder
	b.WriteString("GET /ws HTTP/1.1\r\nHost: " + domain + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + wsSampleKey + "\r\n")
	for _, h := range extra {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

func startWSExtServer(t *testing.T, opts WSUpgradeOptions) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		Config: func(cfg *Config) { cfg.PlainHTTP = true },
		Routes: func(r *Router) {
			r.GET("/ws", func(req *Request, resp *Response) {
				ServeWebSocketWith(req, resp, opts, func(ws *WSConn) {
					for {
						op, msg, err := ws.ReadMessage()
						if err != nil {
							return
						}
						if err := ws.WriteMessage(op, append([]byte(ws.Subprotocol()+":"), msg...)); err != nil {
							return
						}
					}
				})
			})
		},
	})
}

func TestWebSocketExtensionsEpoll(t *testing.T) {
	ts := startWSExtServer(t, WSUpgradeOptions{Subprotocols: []string{"chat.v2", "chat.v1"}, Compression: true})
	c := ts.dial(t)
	br := bufio.NewReader(c)
	if _, err := c.Write([]byte(wsUpgradeRequest(ts.domain, "Sec-WebSocket-Protocol: chat.v1, chat.v2", "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits"))); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Protocol") != "chat.v2" ||
		resp.Header.Get("Sec-WebSocket-Extensions") != wsDeflateAcceptance ||
		resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}

	msg := []byte(strings.Repeat("deflate over a real socket ", 30))
	if _, err := c.Write(wsClientFrame(0x80|wsRSV1|wsOpText, wsClientDeflate(t, msg))); err != nil {
		t.Fatal(err)
	}
	frame, err := wsReadServerFrame(br)
	if err != nil {
		t.Fatal(err)
	}
	if !frame.compressed() || frame.opcode() != wsOpText {
		t.Fatalf("echo frame first byte %#x", frame.first)
	}
	if got := wsClientInflate(t, frame.payload); !bytes.Equal(got, append([]byte("chat.v2:"), msg...)) {
		t.Fatalf("echo %q", got)
	}

	if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte("hi"))); err != nil {
		t.Fatal(err)
	}
	if frame, err = wsReadServerFrame(br); err != nil || frame.compressed() || string(frame.payload) != "chat.v2:hi" {
		t.Fatalf("small echo %+v err %v", frame, err)
	}
}

func TestWebSocketNoOverlapEpoll(t *testing.T) {
	ts := startWSExtServer(t, WSUpgradeOptions{Subprotocols: []string{"chat.v2"}})
	c := ts.dial(t)
	br := bufio.NewReader(c)
	if _, err := c.Write([]byte(wsUpgradeRequest(ts.domain, "Sec-WebSocket-Protocol: mqtt", "Sec-WebSocket-Extensions: permessage-deflate"))); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, ok := resp.Header["Sec-Websocket-Protocol"]; ok {
		t.Fatalf("Sec-WebSocket-Protocol sent without overlap: %v", resp.Header)
	}
	if _, ok := resp.Header["Sec-Websocket-Extensions"]; ok {
		t.Fatalf("Sec-WebSocket-Extensions sent with compression off: %v", resp.Header)
	}
	if _, err := c.Write(wsClientFrame(0x80|wsRSV1|wsOpText, wsClientDeflate(t, []byte("not negotiated")))); err != nil {
		t.Fatal(err)
	}
	if frame, err := wsReadServerFrame(br); err != nil || frame.opcode() != wsOpClose {
		t.Fatalf("RSV1 without negotiation: frame %+v err %v, want a close", frame, err)
	}
}
