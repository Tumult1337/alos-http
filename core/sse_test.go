//go:build linux && amd64

package core

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const sseHeartbeatTestInterval = 150 * time.Millisecond

type recordingStreamWriter struct {
	out     bytes.Buffer
	flushes int
	closed  bool
	failAll bool
}

func (w *recordingStreamWriter) WriteHeader(int, [][2]string, string) error { return nil }

func (w *recordingStreamWriter) WriteChunk(data []byte) error {
	if w.failAll || w.closed {
		return ErrStreamClosed
	}
	w.out.Write(data)
	return nil
}

func (w *recordingStreamWriter) Flush() error {
	w.flushes++
	return nil
}

func (w *recordingStreamWriter) Close() error {
	w.closed = true
	return nil
}

func (w *recordingStreamWriter) snapshot(sse *SSEWriter) string {
	sse.mu.Lock()
	defer sse.mu.Unlock()
	return w.out.String()
}

func newRecordingSSE() (*SSEWriter, *recordingStreamWriter) {
	rec := &recordingStreamWriter{}
	return &SSEWriter{sw: rec}, rec
}

func TestSSEWireFormat(t *testing.T) {
	cases := []struct {
		send func(*SSEWriter) error
		want string
	}{
		{func(w *SSEWriter) error { return w.Send("message", "hello") }, "event: message\ndata: hello\n\n"},
		{func(w *SSEWriter) error { return w.SendData("tick") }, "data: tick\n\n"},
		{func(w *SSEWriter) error { return w.SendData("line1\nline2") }, "data: line1\ndata: line2\n\n"},
		{func(w *SSEWriter) error { return w.SendData("a\n") }, "data: a\ndata: \n\n"},
		{func(w *SSEWriter) error { return w.SendData("") }, "data: \n\n"},
		{func(w *SSEWriter) error { return w.SendID("42", "update", `{"ok":true}`) }, "id: 42\nevent: update\ndata: {\"ok\":true}\n\n"},
		{func(w *SSEWriter) error { return w.SendID("", "reset", "x") }, "id: \nevent: reset\ndata: x\n\n"},
		{func(w *SSEWriter) error { return w.SendComment("keep-alive") }, ": keep-alive\n\n"},
		{func(w *SSEWriter) error { return w.SendComment("two\nlines") }, ": two\n: lines\n\n"},
	}
	for i, c := range cases {
		sse, rec := newRecordingSSE()
		if err := c.send(sse); err != nil {
			t.Fatal(err)
		}
		if got := rec.out.String(); got != c.want || rec.flushes != 1 {
			t.Errorf("case %d: %q (%d flushes), want %q", i, got, rec.flushes, c.want)
		}
	}
}

func TestSSELineBreakInjection(t *testing.T) {
	sse, rec := newRecordingSSE()
	_ = sse.SendData("a\rid: 99\r\nevent: admin\nb\r")
	_ = sse.SendID("7\r\nevent: x", "ev\rdata: y", "z")
	_ = sse.SendComment("c\r\nid: 1")
	want := "data: a\ndata: id: 99\ndata: event: admin\ndata: b\ndata: \n\n" +
		"id: 7event: x\nevent: evdata: y\ndata: z\n\n" +
		": c\n: id: 1\n\n"
	if got := rec.out.String(); got != want {
		t.Fatalf("%q\nwant %q", got, want)
	}
	for _, line := range strings.Split(rec.out.String(), "\n") {
		if strings.ContainsRune(line, '\r') {
			t.Fatalf("a CR survived in %q", line)
		}
	}
}

func TestSSEHeartbeat(t *testing.T) {
	sse, rec := newRecordingSSE()
	stop := sse.StartHeartbeat(sseHeartbeatTestInterval)
	deadline := turbo.Deadline(3 * sseHeartbeatTestInterval)
	for strings.Count(rec.snapshot(sse), ": ping\n\n") < 2 {
		if turbo.Until(deadline) <= 0 {
			t.Fatalf("fewer than 2 heartbeats within %v: %q", 3*sseHeartbeatTestInterval, rec.snapshot(sse))
		}
		time.Sleep(15 * time.Millisecond)
	}
	stop()
	stop()
	after := rec.snapshot(sse)
	time.Sleep(sseHeartbeatTestInterval + 50*time.Millisecond)
	if got := rec.snapshot(sse); got != after {
		t.Fatalf("heartbeat wrote after stop returned: %q", got[len(after):])
	}
	if noop := sse.StartHeartbeat(0); noop == nil {
		t.Fatal("non-positive interval returned a nil stop function")
	} else {
		noop()
	}
}

func TestSSEHeartbeatStopsOnWriteError(t *testing.T) {
	sse, rec := newRecordingSSE()
	rec.failAll = true
	stop := sse.StartHeartbeat(10 * time.Millisecond)
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-turbo.After(sseHeartbeatTestInterval):
		t.Fatal("stop blocked after the heartbeat goroutine hit a write error")
	}
}

func TestSSEConcurrentSendAndHeartbeat(t *testing.T) {
	sse, rec := newRecordingSSE()
	stop := sse.StartHeartbeat(time.Millisecond)
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 50 {
				_ = sse.SendID(string(rune('a'+g)), "e", strings.Repeat("x", i))
			}
		}()
	}
	wg.Wait()
	stop()
	_ = sse.Close()
	if err := sse.SendData("late"); !errors.Is(err, ErrStreamClosed) {
		t.Fatalf("send after close: %v", err)
	}
	for _, block := range strings.Split(strings.TrimSuffix(rec.out.String(), "\n\n"), "\n\n") {
		if !strings.HasPrefix(block, "id: ") && block != ": ping" {
			t.Fatalf("interleaved block %q", block)
		}
	}
}

func TestSSESendAllocs(t *testing.T) {
	sse, rec := newRecordingSSE()
	allocs := testing.AllocsPerRun(100, func() {
		rec.out.Reset()
		_ = sse.SendID("42", "update", "line one\nline two")
	})
	if allocs != 0 {
		t.Fatalf("%.1f allocations per event", allocs)
	}
}

func TestRequestLastEventID(t *testing.T) {
	req := newTestReq()
	if req.LastEventID() != "" {
		t.Fatal("LastEventID without the header")
	}
	req.Headers = append(req.Headers, [2]string{"Last-Event-ID", "evt-41"})
	if got := req.LastEventID(); got != "evt-41" {
		t.Fatalf("LastEventID %q", got)
	}
}
