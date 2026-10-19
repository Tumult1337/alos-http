//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	cancelE2ECeiling      = 2 * time.Second
	cancelShutdownGrace   = 150 * time.Millisecond
	cancelH2Authority     = harnessDomain
	h2ErrCodeCancel       = 0x8
	cancelProbeBufferSize = 8
)

var errCancelProbeTimeout = errors.New("handler context was never cancelled")

type cancelProbe struct {
	entered chan struct{}
	causes  chan error
}

func newCancelProbe() *cancelProbe {
	return &cancelProbe{
		entered: make(chan struct{}, cancelProbeBufferSize),
		causes:  make(chan error, cancelProbeBufferSize),
	}
}

func (p *cancelProbe) block(req *Request, resp *Response) {
	ctx := req.Context()
	p.entered <- struct{}{}
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.Canceled) {
			p.causes <- ctx.Err()
		} else {
			p.causes <- req.CancelCause()
		}
	case <-turbo.After(cancelE2ECeiling):
		p.causes <- errCancelProbeTimeout
	}
	resp.Status(200).String("done")
}

func (p *cancelProbe) awaitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-p.entered:
	case <-turbo.After(cancelE2ECeiling):
		t.Fatal("handler never started")
	}
}

func (p *cancelProbe) expectCause(t *testing.T, want error) time.Duration {
	t.Helper()
	start := turbo.Now()
	select {
	case got := <-p.causes:
		if got != want {
			t.Fatalf("cancel cause = %v, want %v", got, want)
		}
	case <-turbo.After(cancelE2ECeiling + cancelShutdownGrace):
		t.Fatal("handler did not report a cause")
	}
	return turbo.Since(start)
}

func startCancelServer(t *testing.T, probe *cancelProbe, configure func(*Config)) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		Config: configure,
		Routes: func(r *Router) {
			r.GET("/block", probe.block)
			r.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
		},
	})
}

func TestCancelH1ClientClose(t *testing.T) {
	for _, tlsMode := range []bool{false, true} {
		name := "plain"
		if tlsMode {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			probe := newCancelProbe()
			ts := newTestServer(t, testServerOptions{
				TLS:    tlsMode,
				Routes: func(r *Router) { r.GET("/block", probe.block) },
			})
			c := ts.dial(t)
			if _, err := io.WriteString(c, "GET /block HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			probe.awaitEntered(t)
			_ = c.Close()
			elapsed := probe.expectCause(t, ErrClientGone)
			t.Logf("cancelled %v after close", elapsed)
		})
	}
}

func TestCancelH1ClientReset(t *testing.T) {
	probe := newCancelProbe()
	ts := startCancelServer(t, probe, nil)
	c := ts.dial(t)
	if _, err := io.WriteString(c, "GET /block HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	probe.awaitEntered(t)
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
	probe.expectCause(t, ErrClientGone)
}

func TestCancelH1ContextFinishesWithHandler(t *testing.T) {
	for _, inline := range []bool{false, true} {
		name := "async"
		if inline {
			name = "inline"
		}
		t.Run(name, func(t *testing.T) {
			captured := make(chan context.Context, 1)
			ts := newTestServer(t, testServerOptions{
				Config: func(cfg *Config) { cfg.InlineHandlers = inline },
				Routes: func(r *Router) {
					r.GET("/ctx", func(req *Request, resp *Response) {
						captured <- req.Context()
						resp.Status(200).String("ok")
					})
				},
			})
			resp, _ := ts.rawH1(t, "GET /ctx HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n")
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			ctx := <-captured
			select {
			case <-ctx.Done():
			case <-turbo.After(cancelE2ECeiling):
				t.Fatal("context still live after the handler returned")
			}
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("Err = %v", ctx.Err())
			}
		})
	}
}

func TestCancelH1KeepAliveGetsFreshContext(t *testing.T) {
	ts := newTestServer(t, testServerOptions{
		Routes: func(r *Router) {
			r.GET("/err", func(req *Request, resp *Response) {
				if err := req.Context().Err(); err != nil {
					resp.Status(200).String(err.Error())
					return
				}
				resp.Status(200).String("live")
			})
		},
	})
	c := ts.dial(t)
	br := bufio.NewReader(c)
	for i := 0; i < 3; i++ {
		if _, err := io.WriteString(c, "GET /err HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		_, body := readH1Response(t, br, "GET")
		if string(body) != "live" {
			t.Fatalf("request %d saw %q", i, body)
		}
	}
}

func cancelH2Headers(path string) []byte {
	block := []byte{0x82, 0x86, 0x04, byte(len(path))}
	block = append(block, path...)
	block = append(block, 0x01, byte(len(cancelH2Authority)))
	return append(block, cancelH2Authority...)
}

func dialCancelH2(t *testing.T, ts *testServer) *h2RawConn {
	t.Helper()
	rc := h2RawDial(t, ts.addr, nil)
	_ = rc.conn.SetDeadline(wallDeadline(cancelE2ECeiling + cancelShutdownGrace))
	return rc
}

func plainH2Config(cfg *Config) { cfg.PlainHTTP = true }

func TestCancelH2RSTStream(t *testing.T) {
	probe := newCancelProbe()
	ts := startCancelServer(t, probe, plainH2Config)
	rc := dialCancelH2(t, ts)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, cancelH2Headers("/block"))
	probe.awaitEntered(t)
	var code [4]byte
	code[3] = h2ErrCodeCancel
	rc.write(H2FrameRSTStream, 0, 1, code[:])
	probe.expectCause(t, ErrClientGone)

	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, cancelH2Headers("/ok"))
	f, err := rc.awaitStreamOutcome(3)
	if err != nil {
		t.Fatalf("stream 3 after RST: %v", err)
	}
	if f.typ != H2FrameHeaders {
		t.Fatalf("stream 3 got frame type %d, want HEADERS", f.typ)
	}
	if status := h2RawStatusFromHeaders(t, f.payload); status != 200 {
		t.Fatalf("stream 3 status %d", status)
	}
}

func TestCancelH2RSTOnlyCancelsThatStream(t *testing.T) {
	probe := newCancelProbe()
	ts := startCancelServer(t, probe, plainH2Config)
	rc := dialCancelH2(t, ts)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, cancelH2Headers("/block"))
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, cancelH2Headers("/block"))
	probe.awaitEntered(t)
	probe.awaitEntered(t)
	var code [4]byte
	code[3] = h2ErrCodeCancel
	rc.write(H2FrameRSTStream, 0, 3, code[:])
	probe.expectCause(t, ErrClientGone)
	select {
	case got := <-probe.causes:
		t.Fatalf("stream 1 was cancelled too (cause %v)", got)
	case <-turbo.After(cancelShutdownGrace):
	}
	_ = rc.conn.Close()
	probe.expectCause(t, ErrClientGone)
}

func TestCancelH2ConnCloseCancelsAllStreams(t *testing.T) {
	const streams = 4
	probe := newCancelProbe()
	ts := startCancelServer(t, probe, plainH2Config)
	rc := dialCancelH2(t, ts)
	for i := 0; i < streams; i++ {
		rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, uint32(2*i+1), cancelH2Headers("/block"))
	}
	for i := 0; i < streams; i++ {
		probe.awaitEntered(t)
	}
	_ = rc.conn.Close()
	for i := 0; i < streams; i++ {
		probe.expectCause(t, ErrClientGone)
	}
}

func TestCancelShutdownDeadline(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "h1"
		if h2 {
			name = "h2"
		}
		t.Run(name, func(t *testing.T) {
			probe := newCancelProbe()
			var configure func(*Config)
			if h2 {
				configure = plainH2Config
			}
			ts := startCancelServer(t, probe, configure)
			if h2 {
				rc := dialCancelH2(t, ts)
				rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, cancelH2Headers("/block"))
			} else {
				c := ts.dial(t)
				if _, err := io.WriteString(c, "GET /block HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
			}
			probe.awaitEntered(t)
			ctx, cancel := context.WithTimeout(context.Background(), cancelShutdownGrace)
			defer cancel()
			if err := ts.srv.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Shutdown = %v, want DeadlineExceeded", err)
			}
			probe.expectCause(t, ErrServerShutdown)
		})
	}
}

func TestCancelShutdownWithoutDeadlineWaitsForHandler(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	causes := make(chan error, 1)
	ts := newTestServer(t, testServerOptions{
		Routes: func(r *Router) {
			r.GET("/slow", func(req *Request, resp *Response) {
				ctx := req.Context()
				entered <- struct{}{}
				<-release
				causes <- ctx.Err()
				resp.Status(200).String("ok")
			})
		},
	})
	c := ts.dial(t)
	if _, err := io.WriteString(c, "GET /slow HTTP/1.1\r\nHost: "+ts.domain+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	<-entered
	done := make(chan error, 1)
	go func() { done <- ts.srv.Shutdown(context.Background()) }()
	turbo.Sleep(cancelShutdownGrace)
	close(release)
	if err := <-causes; err != nil {
		t.Fatalf("handler context cancelled during graceful drain: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown = %v", err)
		}
	case <-turbo.After(cancelE2ECeiling):
		t.Fatal("Shutdown did not finish after the handler returned")
	}
}
