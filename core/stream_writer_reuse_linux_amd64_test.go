//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	swReuseRounds   = 64
	swReuseInjected = "INJECTED-BY-STALE-WRITER"
)

type swReuseProbe struct {
	mu       sync.Mutex
	stale    StreamWriter
	reused   int
	staleErr []error
}

func (p *swReuseProbe) routes(srv *Server) {
	srv.Router.GET("/keep", func(req *Request, resp *Response) {
		sw := resp.EnsureStreamWriter()
		resp.SetStreamer(sw)
		_ = sw.WriteHeader(200, nil, "text/plain")
		_ = sw.WriteChunk([]byte("first"))
		p.mu.Lock()
		p.stale = sw
		p.mu.Unlock()
	})
	srv.Router.GET("/next", func(req *Request, resp *Response) {
		sw := resp.EnsureStreamWriter()
		resp.SetStreamer(sw)
		_ = sw.WriteHeader(200, nil, "text/plain")
		p.mu.Lock()
		stale := p.stale
		p.stale = nil
		if stale == sw {
			p.reused++
		}
		p.mu.Unlock()
		if stale != nil {
			err := stale.WriteChunk([]byte(swReuseInjected))
			p.mu.Lock()
			p.staleErr = append(p.staleErr, err)
			p.mu.Unlock()
		}
		_ = sw.WriteChunk([]byte("second"))
	})
}

func TestH1StaleStreamWriterCannotWriteIntoNextResponse(t *testing.T) {
	p := &swReuseProbe{}
	addr := startH2FixServer(t, nil, p.routes)
	conn, err := net.DialTimeout("tcp", addr, h2FixCeiling)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	for round := range swReuseRounds {
		_ = conn.SetDeadline(wallDeadline(h2FixCeiling))
		for _, path := range []string{"/keep", "/next"} {
			if _, err := io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: sw.test\r\n\r\n"); err != nil {
				t.Fatalf("round %d write %s: %v", round, path, err)
			}
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("round %d read %s: %v", round, path, err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if strings.Contains(string(body), swReuseInjected) {
				t.Fatalf("round %d: a writer kept from an earlier request wrote into %s: %q", round, path, body)
			}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, err := range p.staleErr {
		if err == nil {
			t.Fatalf("stale write %d returned no error", i)
		}
	}
	t.Logf("writer object reused in %d of %d rounds", p.reused, swReuseRounds)
}

func TestH2StaleStreamWriterCannotWriteIntoNextResponse(t *testing.T) {
	p := &swReuseProbe{}
	addr := startH2FixServer(t, nil, p.routes)
	rc := h2RawDial(t, addr, nil)
	streamID := uint32(1)
	for round := range swReuseRounds {
		for _, path := range []string{"/keep", "/next"} {
			_ = rc.conn.SetDeadline(time.Now().Add(h2FixCeiling))
			h2FixGet(rc, streamID, path)
			var body []byte
			for ended := false; !ended; {
				f := rc.read()
				if f.typ == H2FrameGoAway {
					t.Fatalf("round %d: GOAWAY", round)
				}
				if f.streamID != streamID {
					continue
				}
				if f.typ == H2FrameData {
					body = append(body, f.payload...)
				}
				ended = f.flags&H2FlagEndStream != 0 || f.typ == H2FrameRSTStream
			}
			if bytes.Contains(body, []byte(swReuseInjected)) {
				t.Fatalf("round %d: a writer kept from an earlier stream wrote into %s: %q", round, path, body)
			}
			streamID += 2
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, err := range p.staleErr {
		if err == nil {
			t.Fatalf("stale write %d returned no error", i)
		}
	}
	t.Logf("writer object reused in %d of %d rounds", p.reused, swReuseRounds)
}

func TestH1StreamWriterWritesAfterHandlerReturnStayIsolated(t *testing.T) {
	var spinners sync.WaitGroup
	var spinMu sync.Mutex
	var spinErrs []error
	addr := startH2FixServer(t, nil, func(srv *Server) {
		srv.Router.GET("/spin", func(req *Request, resp *Response) {
			sw := resp.EnsureStreamWriter()
			resp.SetStreamer(sw)
			_ = sw.WriteHeader(200, nil, "text/plain")
			spinners.Add(1)
			go func() {
				defer spinners.Done()
				for {
					if err := sw.WriteChunk([]byte(swReuseInjected)); err != nil {
						spinMu.Lock()
						spinErrs = append(spinErrs, err)
						spinMu.Unlock()
						return
					}
				}
			}()
		})
		srv.Router.GET("/next", func(req *Request, resp *Response) {
			sw := resp.EnsureStreamWriter()
			resp.SetStreamer(sw)
			_ = sw.WriteHeader(200, nil, "text/plain")
			_ = sw.WriteChunk([]byte("second"))
		})
	})
	conn, err := net.DialTimeout("tcp", addr, h2FixCeiling)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	for round := range swReuseRounds {
		_ = conn.SetDeadline(wallDeadline(h2FixCeiling))
		for _, path := range []string{"/spin", "/next", "/next"} {
			if _, err := io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: sw.test\r\n\r\n"); err != nil {
				t.Fatalf("round %d write %s: %v", round, path, err)
			}
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("round %d read %s: %v", round, path, err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if path == "/next" && string(body) != "second" {
				t.Fatalf("round %d: /next body = %q, want only its own bytes", round, body)
			}
		}
	}
	spinners.Wait()
	spinMu.Lock()
	defer spinMu.Unlock()
	if len(spinErrs) != swReuseRounds {
		t.Fatalf("%d of %d spinners stopped", len(spinErrs), swReuseRounds)
	}
	for i, err := range spinErrs {
		if !errors.Is(err, ErrStreamClosed) {
			t.Fatalf("spinner %d stopped with %v, want ErrStreamClosed", i, err)
		}
	}
}

func TestH2StreamWriterWithQueuedPumpIsNotRecycled(t *testing.T) {
	w, c, _ := h2DeadlineFixture(t)
	sw := newEpollH2StreamWriter().(*epollH2StreamWriter)
	sw.c, sw.w, sw.gen = c, w, c.generation
	sw.mu.Lock()
	queued := sw.claimPumpLocked()
	sw.finished = true
	sw.mu.Unlock()
	if !queued {
		t.Fatal("fixture could not claim a pump task")
	}
	w.postTask(sw.pumpFn)
	c.h2PumpFrames(nil, sw, 0)
	sw.release()
	if sw.c != c {
		t.Fatal("writer was recycled while a posted pump task still referenced it")
	}
	w.drainTasks()
	if sw.c != nil {
		t.Fatal("writer was not recycled after its last pump task ran")
	}
}

func TestH1StreamWriterWithQueuedPumpIsNotRecycled(t *testing.T) {
	w, c, _ := h1ReceivedFixture(t, Config{})
	sw := newEpollH1StreamWriter().(*epollH1StreamWriter)
	sw.c, sw.w, sw.gen = c, w, c.generation
	sw.mu.Lock()
	queued := sw.claimPumpLocked()
	sw.finished = true
	sw.mu.Unlock()
	if !queued {
		t.Fatal("fixture could not claim a pump task")
	}
	w.postTask(sw.pumpFn)
	c.h1PumpStream(sw)
	sw.release()
	if sw.c != c {
		t.Fatal("writer was recycled while a posted pump task still referenced it")
	}
	w.drainTasks()
	if sw.c != nil {
		t.Fatal("writer was not recycled after its last pump task ran")
	}
}
