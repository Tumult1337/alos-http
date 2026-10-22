//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/guno1928/turbo"
)

func b4DirectPayload(size, seed int) []byte {
	p := make([]byte, size)
	for i := range p {
		p[i] = byte('a' + (i*7+seed)%26)
	}
	return p
}

func TestB4WSEventsDirectSendKeepsFramesIntact(t *testing.T) {
	log := &wsEvCloseLog{}
	sizes := []int{wsDirectSendMin - 1, wsDirectSendMin, 5000, 16 << 10, 16<<10 + 9, 64 << 10, 300 << 10, 64, wsDirectSendMin + 1}
	ts := wsEvStartServer(t, false, nil, log, func(r *Router) {
		r.GET("/twice", func(req *Request, resp *Response) {
			ServeWebSocketEvents(req, resp, WSUpgradeOptions{}, WSEventHandler{
				OnMessage: func(ws *WSConn, op byte, msg []byte) {
					_ = ws.WriteMessage(op, msg)
					_ = ws.WriteMessage(op, msg)
				},
				OnClose: func(ws *WSConn, code uint16) { log.add(code) },
			})
		})
	})
	c := wsEvDialSmallWindow(t, ts.addr)
	if _, err := io.WriteString(c, wsEvUpgradeRequest(ts.domain, "/twice")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade %v %v", resp, err)
	}
	var batch []byte
	for i, n := range sizes {
		batch = append(batch, wsClientFrame(0x80|wsOpText, b4DirectPayload(n, i))...)
	}
	go func() { _, _ = c.Write(batch) }()
	turbo.Sleep(wsEvSplitPause * 5)
	for i, n := range sizes {
		want := b4DirectPayload(n, i)
		for k := 0; k < 2; k++ {
			f, err := wsReadServerFrame(br)
			if err != nil {
				t.Fatalf("message %d copy %d: %v", i, k, err)
			}
			if f.first != 0x80|wsOpText || !bytes.Equal(f.payload, want) {
				t.Fatalf("message %d copy %d (%d bytes): first %#x len %d, payload mismatch", i, k, n, f.first, len(f.payload))
			}
		}
	}
	if _, err := c.Write(wsEvCloseFrame(1000, "")); err != nil {
		t.Fatal(err)
	}
	wsEvWaitCodes(t, log, 1000)
}
