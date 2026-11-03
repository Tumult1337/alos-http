//go:build linux && amd64

package core

import (
	"bytes"
	"strconv"
	"testing"
)

const perfH1WriteHeadroom = 4 << 10

type perfH1WriteRig struct {
	w       *epollWorker
	c       *epollConn
	body    []byte
	wantLen int
}

func newPerfH1WriteRig(size int) *perfH1WriteRig {
	w := &epollWorker{}
	r := &perfH1WriteRig{w: w, c: &epollConn{worker: w}, body: bytes.Repeat([]byte{'x'}, size)}
	r.c.resp.resetFastH1()
	r.c.resp.BytesNoCopy(r.body)
	r.c.writeBuf = make([]byte, 0, min(size, h1OutSocketHighMark)+perfH1WriteHeadroom)
	r.wantLen = len(r.head()) + size
	return r
}

func (r *perfH1WriteRig) head() []byte {
	return appendPlainResponseHeaders(&r.c.resp, r.c.writeBuf[:0])
}

func (r *perfH1WriteRig) drainProgressive(sink func([]byte)) {
	c, w := r.c, r.w
	c.writeBuf, c.writeSent = c.writeBuf[:0], 0
	c.h1StartProgressiveBody(w, true)
	for {
		sink(c.writeBuf)
		sink(c.bodyOut)
		if c.h1Body == nil {
			break
		}
		c.writeBuf, c.writeSent, c.bodyOut = c.writeBuf[:0], 0, nil
		c.h1PumpOut(w)
	}
	c.flushQueued, c.h1ResumeDue = false, false
	w.flushList = w.flushList[:0]
}

func (r *perfH1WriteRig) write() int {
	c := r.c
	if c.h1LargeBody() {
		emitted := 0
		r.drainProgressive(func(p []byte) { emitted += len(p) })
		return emitted
	}
	c.writeBuf = c.writeBuf[:0]
	c.h1WriteResponse(true)
	return len(c.writeBuf)
}

func (r *perfH1WriteRig) lifecycle() int {
	c := r.c
	c.writeBuf = acquireIOBuf()
	c.resp.resetFastH1()
	c.resp.Bytes(r.body)
	n := r.write()
	releaseIOBuf(c.writeBuf)
	c.writeBuf = nil
	c.resp.resetFastH1()
	return n
}

func (r *perfH1WriteRig) mustEmitAll(tb testing.TB, got int) {
	tb.Helper()
	if got != r.wantLen {
		tb.Fatalf("write path emitted %d bytes, want %d", got, r.wantLen)
	}
}

func benchPerfH1Head(b *testing.B, size int) {
	r := newPerfH1WriteRig(size)
	b.ReportAllocs()
	for b.Loop() {
		benchSink = r.head()
	}
}

func benchPerfH1Write(b *testing.B, size int, step func(*perfH1WriteRig) int) {
	r := newPerfH1WriteRig(size)
	b.SetBytes(int64(r.wantLen))
	b.ReportAllocs()
	got := 0
	for b.Loop() {
		got = step(r)
	}
	r.mustEmitAll(b, got)
}

func BenchmarkPerfH1HeadOnly64K(b *testing.B) { benchPerfH1Head(b, perfH1Body64K) }

func BenchmarkPerfH1HeadOnly1M(b *testing.B) { benchPerfH1Head(b, perfH1Body1M) }

func BenchmarkPerfH1WriteResponse64K(b *testing.B) {
	benchPerfH1Write(b, perfH1Body64K, (*perfH1WriteRig).write)
}

func BenchmarkPerfH1WriteProgressive1M(b *testing.B) {
	benchPerfH1Write(b, perfH1Body1M, (*perfH1WriteRig).write)
}

func BenchmarkPerfH1Lifecycle64K(b *testing.B) {
	benchPerfH1Write(b, perfH1Body64K, (*perfH1WriteRig).lifecycle)
}

func BenchmarkPerfH1Lifecycle1M(b *testing.B) {
	benchPerfH1Write(b, perfH1Body1M, (*perfH1WriteRig).lifecycle)
}

func TestPerfH1WritePathEmitsWholeResponse(t *testing.T) {
	for _, size := range []int{perfH1Body64K, perfH1Body1M} {
		r := newPerfH1WriteRig(size)
		head := append([]byte(nil), r.head()...)
		if !bytes.HasPrefix(head, statusLines[200]) || !bytes.Contains(head, []byte("Content-Length: "+strconv.Itoa(size)+"\r\n")) {
			t.Fatalf("size %d: unexpected head %q", size, head)
		}
		if r.c.h1LargeBody() != (size >= h1DirectBodyMin) {
			t.Fatalf("size %d: progressive=%v", size, r.c.h1LargeBody())
		}
		var out []byte
		if r.c.h1LargeBody() {
			r.drainProgressive(func(p []byte) { out = append(out, p...) })
		} else {
			r.write()
			out = append(out, r.c.writeBuf...)
		}
		if len(out) != r.wantLen || !bytes.Equal(out[:len(head)], head) || !bytes.Equal(out[len(head):], r.body) {
			t.Fatalf("size %d: emitted %d bytes, want head %d + body %d", size, len(out), len(head), len(r.body))
		}
	}
}

func TestPerfH1WritePathDoesNotAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	cases := []struct {
		name string
		size int
		step func(*perfH1WriteRig) int
	}{
		{"head64K", perfH1Body64K, func(r *perfH1WriteRig) int { benchSink = r.head(); return r.wantLen }},
		{"head1M", perfH1Body1M, func(r *perfH1WriteRig) int { benchSink = r.head(); return r.wantLen }},
		{"write64K", perfH1Body64K, (*perfH1WriteRig).write},
		{"progressive1M", perfH1Body1M, (*perfH1WriteRig).write},
		{"lifecycle64K", perfH1Body64K, (*perfH1WriteRig).lifecycle},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newPerfH1WriteRig(tc.size)
			for range perfH1LockWarmup {
				r.mustEmitAll(t, tc.step(r))
			}
			got := 0
			allocs := testing.AllocsPerRun(perfH1LockRuns, func() { got = tc.step(r) })
			r.mustEmitAll(t, got)
			if allocs > 0 {
				t.Fatalf("%s: %.2f allocs per response, want 0", tc.name, allocs)
			}
		})
	}
}
