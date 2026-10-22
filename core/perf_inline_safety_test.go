//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	inlineSafetySlow     = 450 * time.Millisecond
	inlineSafetyFastMax  = 150 * time.Millisecond
	inlineSafetyFlipSlow = 150 * time.Millisecond
	inlineSafetyBodyGap  = 150 * time.Millisecond
	inlineSafetyPoll     = 15 * time.Millisecond
	inlineSafetyCeiling  = 3 * time.Second
	inlineSafetyProbes   = 20
	inlineSafetyBodyLen  = 300
)

type inlineSafetyApp struct {
	entered chan struct{}
	flip    chan struct{}
	flipped sync.Once
}

func newInlineSafetyApp() *inlineSafetyApp {
	return &inlineSafetyApp{entered: make(chan struct{}, 64), flip: make(chan struct{})}
}

func (a *inlineSafetyApp) routes(r *Router) {
	r.GET("/fast", func(req *Request, resp *Response) { resp.String("fast") })
	r.GET("/where", func(req *Request, resp *Response) { reportDispatchMode(resp, "w") })
	r.GET("/slow", func(req *Request, resp *Response) {
		select {
		case a.entered <- struct{}{}:
		default:
		}
		turbo.Sleep(inlineSafetySlow)
		resp.String("slow")
	})
	r.GET("/flip", func(req *Request, resp *Response) {
		select {
		case <-a.flip:
			resp.String("quick")
		default:
			a.flipped.Do(func() { close(a.flip) })
			turbo.Sleep(inlineSafetyFlipSlow)
			resp.String("slow")
		}
	})
	r.GET("/panic", func(req *Request, resp *Response) { panic("inline boom") })
	r.GET("/slowpanic", func(req *Request, resp *Response) {
		turbo.Sleep(inlineSafetyFlipSlow)
		panic("late boom")
	})
	r.GET("/goexit", func(req *Request, resp *Response) { runtime.Goexit() })
	r.GET("/stream", func(req *Request, resp *Response) {
		sw := resp.EnsureStreamWriter()
		if sw == nil {
			resp.Status(500).String("no stream")
			return
		}
		_ = sw.WriteHeader(200, nil, "text/plain")
		resp.SetStreamer(sw)
		_ = sw.WriteChunk([]byte("part1,"))
		_ = sw.WriteChunk([]byte("part2"))
		_ = sw.Close()
	})
	r.POST("/echo", func(req *Request, resp *Response) { resp.String(strconv.Itoa(len(req.Body))) })
}

func (a *inlineSafetyApp) awaitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-a.entered:
	case <-time.After(inlineSafetyCeiling):
		t.Fatal("slow handler never started")
	}
}

func inlineSafetyServer(t *testing.T, useTLS bool, app *inlineSafetyApp, cfg func(*Config)) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{TLS: useTLS, Routes: app.routes, Config: cfg})
}

func inlineSafetyModes(t *testing.T, fn func(t *testing.T, useTLS bool)) {
	for _, useTLS := range []bool{false, true} {
		name := "plain"
		if useTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) { fn(t, useTLS) })
	}
}

type inlineSafetyConn struct {
	conn net.Conn
	br   *bufio.Reader
}

func inlineSafetyDial(t *testing.T, ts *testServer) *inlineSafetyConn {
	t.Helper()
	c := ts.dial(t)
	_ = c.SetDeadline(wallDeadline(inlineSafetyCeiling))
	return &inlineSafetyConn{conn: c, br: bufio.NewReader(c)}
}

func (ic *inlineSafetyConn) get(t *testing.T, path string) (int, string) {
	t.Helper()
	status, body, err := ic.fetch(path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return status, body
}

func (ic *inlineSafetyConn) fetch(path string) (int, string, error) {
	if _, err := io.WriteString(ic.conn, "GET "+path+" HTTP/1.1\r\nHost: "+harnessDomain+"\r\n\r\n"); err != nil {
		return 0, "", err
	}
	resp, err := http.ReadResponse(ic.br, &http.Request{Method: "GET"})
	if err != nil {
		return 0, "", err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body), err
}

func (ic *inlineSafetyConn) fetchBody(path string) string {
	_, body, err := ic.fetch(path)
	if err != nil {
		return err.Error()
	}
	return body
}

func inlineSafetyAssertFast(t *testing.T, probe func() (int, string), want string) {
	t.Helper()
	for i := 0; i < inlineSafetyProbes; i++ {
		start := turbo.Now()
		status, body := probe()
		took := turbo.Since(start)
		if status != 200 || body != want {
			t.Fatalf("probe %d: %d %q, want 200 %q", i, status, body, want)
		}
		if took > inlineSafetyFastMax {
			t.Fatalf("probe %d took %v while a handler blocked its loop (limit %v)", i, took, inlineSafetyFastMax)
		}
	}
}

func inlineSafetyDemoted(r *Router, path string) bool {
	_, demoted := r.demotedInline(handlerIdentity(r.Lookup("GET", path, &Request{})))
	return demoted
}

func inlineSafetyAwait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := turbo.Deadline(inlineSafetyCeiling)
	for turbo.Until(deadline) > 0 {
		if cond() {
			return
		}
		turbo.Sleep(inlineSafetyPoll)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestInlineSafetySlowHandlerDoesNotStallLoopH1(t *testing.T) {
	inlineSafetyModes(t, func(t *testing.T, useTLS bool) {
		app := newInlineSafetyApp()
		ts := inlineSafetyServer(t, useTLS, app, nil)
		fast := inlineSafetyDial(t, ts)
		if status, body := fast.get(t, "/where"); status != 200 || body != "inline:w" {
			t.Fatalf("fast route before: %d %q, want inline dispatch", status, body)
		}
		handoffs := inlineHandoffs.Load()
		for round := 0; round < 2; round++ {
			slow := inlineSafetyDial(t, ts)
			done := make(chan string, 1)
			go func() { done <- slow.fetchBody("/slow") }()
			app.awaitEntered(t)
			inlineSafetyAssertFast(t, func() (int, string) { return fast.get(t, "/fast") }, "fast")
			if body := <-done; body != "slow" {
				t.Fatalf("round %d: slow body %q", round, body)
			}
			if !inlineSafetyDemoted(ts.srv.Router, "/slow") {
				t.Fatalf("round %d: /slow was not demoted to goroutine dispatch", round)
			}
		}
		if inlineHandoffs.Load() == handoffs {
			t.Fatal("the blocked loop was never handed off")
		}
		if status, body := fast.get(t, "/where"); status != 200 || body != "inline:w" {
			t.Fatalf("fast route after: %d %q, want inline dispatch", status, body)
		}
		if inlineSafetyDemoted(ts.srv.Router, "/fast") {
			t.Fatal("a fast route was demoted")
		}
	})
}

func TestInlineSafetyIdleWatchdogParksAndWakes(t *testing.T) {
	const idleWindow = 150 * time.Millisecond
	app := newInlineSafetyApp()
	ts := inlineSafetyServer(t, false, app, nil)
	fast := inlineSafetyDial(t, ts)
	if status, body := fast.get(t, "/where"); status != 200 || body != "inline:w" {
		t.Fatalf("warm-up: %d %q", status, body)
	}
	iw := &ts.srv.inlineWatch
	inlineSafetyAwait(t, "watchdog to park", iw.parked.Load)
	ticks, wakeups := iw.ticks.Load(), iw.wakeups.Load()
	turbo.Sleep(idleWindow)
	if got := iw.ticks.Load() - ticks; got != 0 || !iw.parked.Load() {
		t.Fatalf("idle watchdog woke %d times in %v (parked=%v), want 0", got, idleWindow, iw.parked.Load())
	}
	handoffs := inlineHandoffs.Load()
	slow := inlineSafetyDial(t, ts)
	done := make(chan string, 1)
	go func() { done <- slow.fetchBody("/slow") }()
	app.awaitEntered(t)
	inlineSafetyAssertFast(t, func() (int, string) { return fast.get(t, "/fast") }, "fast")
	if body := <-done; body != "slow" {
		t.Fatalf("slow body %q", body)
	}
	if iw.wakeups.Load() == wakeups {
		t.Fatal("a parked watchdog was not woken by the inline handler")
	}
	if inlineHandoffs.Load() == handoffs {
		t.Fatal("the blocked loop was not handed off after the watchdog woke")
	}
}

func inlineSafetyH2Client(t *testing.T, ts *testServer) *http.Client {
	t.Helper()
	if ts.tls {
		return ts.client(t, "h2")
	}
	tr := &http.Transport{Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: inlineSafetyCeiling}
}

func inlineSafetyH2Get(t *testing.T, cl *http.Client, url string) (int, string, int) {
	t.Helper()
	resp, err := cl.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body), resp.ProtoMajor
}

func TestInlineSafetySlowHandlerDoesNotStallLoopH2(t *testing.T) {
	inlineSafetyModes(t, func(t *testing.T, useTLS bool) {
		app := newInlineSafetyApp()
		ts := inlineSafetyServer(t, useTLS, app, func(c *Config) { c.PlainHTTP = !useTLS })
		cl := inlineSafetyH2Client(t, ts)
		if status, body, major := inlineSafetyH2Get(t, cl, ts.url("/where")); status != 200 || body != "inline:w" || major != 2 {
			t.Fatalf("fast h2 route before: %d %q proto %d, want inline dispatch over h2", status, body, major)
		}
		done := make(chan string, 1)
		go func() {
			resp, err := cl.Get(ts.url("/slow"))
			if err != nil {
				done <- err.Error()
				return
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			done <- string(body)
		}()
		app.awaitEntered(t)
		inlineSafetyAssertFast(t, func() (int, string) {
			status, body, _ := inlineSafetyH2Get(t, cl, ts.url("/fast"))
			return status, body
		}, "fast")
		if body := <-done; body != "slow" {
			t.Fatalf("slow h2 body %q", body)
		}
		if !inlineSafetyDemoted(ts.srv.Router, "/slow") {
			t.Fatal("/slow was not demoted over h2")
		}
	})
}

func TestInlineSafetyDisableInlineHandlersForcesGoroutines(t *testing.T) {
	inlineSafetyModes(t, func(t *testing.T, useTLS bool) {
		app := newInlineSafetyApp()
		ts := inlineSafetyServer(t, useTLS, app, func(c *Config) {
			c.PlainHTTP = !useTLS
			c.DisableInlineHandlers = true
		})
		if status, body := inlineSafetyDial(t, ts).get(t, "/where"); status != 200 || body != "async:w" {
			t.Fatalf("h1 with DisableInlineHandlers: %d %q, want goroutine dispatch", status, body)
		}
		if status, body, major := inlineSafetyH2Get(t, inlineSafetyH2Client(t, ts), ts.url("/where")); status != 200 || body != "async:w" || major != 2 {
			t.Fatalf("h2 with DisableInlineHandlers: %d %q proto %d, want goroutine dispatch", status, body, major)
		}
	})
}

func TestInlineSafetyPanicRecovered(t *testing.T) {
	inlineSafetyModes(t, func(t *testing.T, useTLS bool) {
		app := newInlineSafetyApp()
		ts := inlineSafetyServer(t, useTLS, app, nil)
		c := inlineSafetyDial(t, ts)
		for _, path := range []string{"/panic", "/slowpanic", "/panic"} {
			if status, _ := c.get(t, path); status != 500 {
				t.Fatalf("%s: status %d, want 500", path, status)
			}
			if status, body := c.get(t, "/fast"); status != 200 || body != "fast" {
				t.Fatalf("after %s: %d %q", path, status, body)
			}
		}
		if status, body := inlineSafetyDial(t, ts).get(t, "/where"); status != 200 || body != "inline:w" {
			t.Fatalf("loop after panics: %d %q", status, body)
		}
	})
}

func TestInlineSafetyGoexitKeepsLoopAlive(t *testing.T) {
	app := newInlineSafetyApp()
	ts := inlineSafetyServer(t, false, app, nil)
	handoffs := inlineHandoffs.Load()
	c := inlineSafetyDial(t, ts)
	if _, err := io.WriteString(c.conn, "GET /goexit HTTP/1.1\r\nHost: "+harnessDomain+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	inlineSafetyAwait(t, "goexit hand-off", func() bool { return inlineHandoffs.Load() != handoffs })
	inlineSafetyAssertFast(t, func() (int, string) { return inlineSafetyDial(t, ts).get(t, "/fast") }, "fast")
}

func TestInlineSafetySlowBodyDoesNotStallLoop(t *testing.T) {
	inlineSafetyModes(t, func(t *testing.T, useTLS bool) {
		app := newInlineSafetyApp()
		ts := inlineSafetyServer(t, useTLS, app, nil)
		slow := inlineSafetyDial(t, ts)
		head := fmt.Sprintf("POST /echo HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", harnessDomain, inlineSafetyBodyLen)
		half := strings.Repeat("a", inlineSafetyBodyLen/2)
		if _, err := io.WriteString(slow.conn, head+half); err != nil {
			t.Fatal(err)
		}
		fast := inlineSafetyDial(t, ts)
		gapEnd := turbo.Deadline(inlineSafetyBodyGap)
		for turbo.Until(gapEnd) > 0 {
			inlineSafetyAssertFast(t, func() (int, string) { return fast.get(t, "/fast") }, "fast")
		}
		if _, err := io.WriteString(slow.conn, half); err != nil {
			t.Fatal(err)
		}
		resp, body := readH1Response(t, slow.br, "POST")
		if resp.StatusCode != 200 || string(body) != strconv.Itoa(inlineSafetyBodyLen) {
			t.Fatalf("slow body echo: %d %q", resp.StatusCode, body)
		}
	})
}

func TestInlineSafetyStreamingLeavesLoop(t *testing.T) {
	inlineSafetyModes(t, func(t *testing.T, useTLS bool) {
		app := newInlineSafetyApp()
		ts := inlineSafetyServer(t, useTLS, app, nil)
		c := inlineSafetyDial(t, ts)
		for i := 0; i < 3; i++ {
			if status, body := c.get(t, "/stream"); status != 200 || body != "part1,part2" {
				t.Fatalf("stream %d: %d %q", i, status, body)
			}
		}
		st, demoted := ts.srv.Router.demotedInline(handlerIdentity(ts.srv.Router.Lookup("GET", "/stream", &Request{})))
		if !demoted || st != nil {
			t.Fatalf("streaming route: demoted=%v repromotable=%v, want a permanent demotion", demoted, st != nil)
		}
		if status, body := inlineSafetyDial(t, ts).get(t, "/where"); status != 200 || body != "inline:w" {
			t.Fatalf("fast route after streaming: %d %q", status, body)
		}
	})
}

func TestInlineSafetyRepromotesAfterFastRuns(t *testing.T) {
	app := newInlineSafetyApp()
	ts := inlineSafetyServer(t, false, app, nil)
	c := inlineSafetyDial(t, ts)
	if status, body := c.get(t, "/flip"); status != 200 || body != "slow" {
		t.Fatalf("first flip: %d %q", status, body)
	}
	if !inlineSafetyDemoted(ts.srv.Router, "/flip") {
		t.Fatal("/flip was not demoted after blocking its loop")
	}
	for i := 0; i < inlineRepromoteRuns && inlineSafetyDemoted(ts.srv.Router, "/flip"); i++ {
		if status, body := c.get(t, "/flip"); status != 200 || body != "quick" {
			t.Fatalf("flip %d: %d %q", i, status, body)
		}
	}
	if inlineSafetyDemoted(ts.srv.Router, "/flip") {
		t.Fatalf("/flip still demoted after %d fast runs", inlineRepromoteRuns)
	}
}

func TestInlineSafetyShutdownWhileInlineHandlerRuns(t *testing.T) {
	inlineSafetyModes(t, func(t *testing.T, useTLS bool) {
		app := newInlineSafetyApp()
		addr := freeLoopbackAddr(t)
		cfg := Config{Addr: addr, HTTPAddr: "-", MaxConnsPerIP: -1, Listeners: 1}
		if useTLS {
			cfg.Certs = []CertConfig{{Domain: harnessDomain, Source: CertSelfSigned}}
		}
		s := New(cfg)
		app.routes(s.Router)
		served := make(chan error, 1)
		go func() {
			if useTLS {
				served <- s.ListenAndServeTLS()
				return
			}
			served <- s.ListenAndServe()
		}()
		waitForProxy(t, addr)
		ts := &testServer{srv: s, addr: addr, domain: harnessDomain, tls: useTLS}
		slow := inlineSafetyDial(t, ts)
		done := make(chan string, 1)
		go func() { done <- slow.fetchBody("/slow") }()
		app.awaitEntered(t)
		ctx, cancel := context.WithTimeout(context.Background(), inlineSafetyCeiling)
		defer cancel()
		shut := make(chan error, 1)
		go func() { shut <- s.Shutdown(ctx) }()
		if body := <-done; body != "slow" {
			t.Fatalf("in-flight inline request during shutdown: %q", body)
		}
		if err := <-shut; err != nil {
			t.Fatalf("shutdown: %v", err)
		}
		select {
		case <-served:
		case <-time.After(inlineSafetyCeiling):
			t.Fatal("serve never returned after shutdown")
		}
		inlineSafetyAwait(t, "inline watchdog exit", func() bool {
			iw := &s.inlineWatch
			iw.mu.Lock()
			defer iw.mu.Unlock()
			return !iw.active && len(iw.workers) == 0
		})
	})
}

func inlineSafetyConnSlots(s *Server, ip string) int64 {
	l := s.perIPConnLimiter.Load()
	if l == nil {
		return -1
	}
	if c, ok := l.m.Load(ip); ok {
		return c.n.Load()
	}
	return 0
}

func TestInlineSafetyPerIPSlotsReleased(t *testing.T) {
	const (
		maxConns = 4
		maxReqs  = 2
		ip       = "127.0.0.1"
	)
	inlineSafetyModes(t, func(t *testing.T, useTLS bool) {
		app := newInlineSafetyApp()
		ts := inlineSafetyServer(t, useTLS, app, func(c *Config) {
			c.MaxConnsPerIP = maxConns
			c.MaxRequestsPerIP = maxReqs
		})
		slow := inlineSafetyDial(t, ts)
		done := make(chan string, 1)
		go func() { done <- slow.fetchBody("/slow") }()
		app.awaitEntered(t)
		other := inlineSafetyDial(t, ts)
		for _, path := range []string{"/stream", "/panic", "/fast"} {
			if status, _ := other.get(t, path); status != 200 && path != "/panic" {
				t.Fatalf("%s: status %d", path, status)
			}
		}
		if body := <-done; body != "slow" {
			t.Fatalf("slow body %q", body)
		}
		inlineSafetyAwait(t, "request slots released", func() bool { return pxCount(ts.srv, ip) == 0 })
		_ = slow.conn.Close()
		_ = other.conn.Close()
		inlineSafetyAwait(t, "connection slots released", func() bool { return inlineSafetyConnSlots(ts.srv, ip) == 0 })
		for i := 0; i < maxConns; i++ {
			if status, body := inlineSafetyDial(t, ts).get(t, "/fast"); status != 200 || body != "fast" {
				t.Fatalf("fresh conn %d: %d %q", i, status, body)
			}
		}
	})
}
