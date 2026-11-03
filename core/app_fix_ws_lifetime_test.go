//go:build linux && amd64

package core

import (
	"bufio"
	"net"
	"net/http"
	"testing"
)

const appFixWSUserHeader = "X-User"

func startAppFixWSIdentityServer(t *testing.T, inline bool) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		Config: func(cfg *Config) {
			cfg.PlainHTTP = true
			cfg.InlineHandlers, cfg.DisableInlineHandlers = inline, !inline
		},
		Routes: func(r *Router) {
			r.GET("/ws", func(req *Request, resp *Response) {
				ServeWebSocket(req, resp, func(ws *WSConn) {
					for {
						_, msg, err := ws.ReadMessage()
						if err != nil {
							return
						}
						reply := string(msg) + " user=" + req.Header(appFixWSUserHeader) + " path=" + req.Path
						if err := ws.WriteMessage(wsOpText, []byte(reply)); err != nil {
							return
						}
					}
				})
			})
			r.GET("/me", func(req *Request, resp *Response) {
				resp.String("hello " + req.Header(appFixWSUserHeader))
			})
		},
	})
}

func appFixWSRoundTrip(t *testing.T, c net.Conn, br *bufio.Reader, msg string) string {
	t.Helper()
	if _, err := c.Write(wsClientFrame(0x80|wsOpText, []byte(msg))); err != nil {
		t.Fatalf("write ws frame: %v", err)
	}
	frame, err := wsReadServerFrame(br)
	if err != nil {
		t.Fatalf("read ws frame: %v", err)
	}
	return string(frame.payload)
}

func TestAppFixWebSocketKeepsItsOwnRequestAfterConnReuse(t *testing.T) {
	t.Run("async", func(t *testing.T) { appFixCheckWSIdentityAfterReuse(t, false) })
	t.Run("inline", func(t *testing.T) { appFixCheckWSIdentityAfterReuse(t, true) })
}

func appFixCheckWSIdentityAfterReuse(t *testing.T, inline bool) {
	ts := startAppFixWSIdentityServer(t, inline)
	wsConn := ts.dial(t)
	wsReader := bufio.NewReader(wsConn)
	if _, err := wsConn.Write([]byte(wsUpgradeRequest(ts.domain, appFixWSUserHeader+": attacker"))); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(wsReader, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: resp %v err %v", resp, err)
	}
	const want = " user=attacker path=/ws"
	if got := appFixWSRoundTrip(t, wsConn, wsReader, "m1"); got != "m1"+want {
		t.Fatalf("first reply %q", got)
	}
	for i := 0; i < 4; i++ {
		_, body := ts.rawH1(t, "GET /me HTTP/1.1\r\nHost: "+ts.domain+"\r\n"+appFixWSUserHeader+": VICTIM-ADMIN\r\nConnection: close\r\n\r\n")
		if string(body) != "hello VICTIM-ADMIN" {
			t.Fatalf("victim body %q", body)
		}
		if got := appFixWSRoundTrip(t, wsConn, wsReader, "m2"); got != "m2"+want {
			t.Fatalf("after a new client reused the server conn the websocket saw %q, want %q", got, "m2"+want)
		}
	}
}

func TestAppFixWebSocketConnReturnsToPoolAfterClose(t *testing.T) {
	t.Run("async", func(t *testing.T) { appFixCheckWSConnRecycledAfterClose(t, false) })
	t.Run("inline", func(t *testing.T) { appFixCheckWSConnRecycledAfterClose(t, true) })
}

func appFixCheckWSConnRecycledAfterClose(t *testing.T, inline bool) {
	ts := startAppFixWSIdentityServer(t, inline)
	wsConn := ts.dial(t)
	wsReader := bufio.NewReader(wsConn)
	if _, err := wsConn.Write([]byte(wsUpgradeRequest(ts.domain, appFixWSUserHeader+": a"))); err != nil {
		t.Fatal(err)
	}
	if resp, err := http.ReadResponse(wsReader, nil); err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: resp %v err %v", resp, err)
	}
	if got := appFixWSRoundTrip(t, wsConn, wsReader, "x"); got != "x user=a path=/ws" {
		t.Fatalf("reply %q", got)
	}
	freeWhileOpen := appFixPooledFreeConns(t, ts.srv)
	_ = wsConn.Close()
	waitFor(t, harnessIOTimeout, func() bool {
		return ts.srv.activeConns.Load() == 0 && appFixPooledFreeConns(t, ts.srv) == freeWhileOpen+1
	})
}

func appFixPooledFreeConns(t *testing.T, srv *Server) int {
	t.Helper()
	srv.wakersMu.Lock()
	var worker *epollWorker
	for waker := range srv.wakers {
		if w, ok := waker.(*epollWorker); ok {
			worker = w
		}
	}
	srv.wakersMu.Unlock()
	if worker == nil {
		t.Fatal("no epoll worker registered")
	}
	free := make(chan int, 1)
	worker.postTask(func(w *epollWorker) { free <- len(w.pool.free) })
	return <-free
}
