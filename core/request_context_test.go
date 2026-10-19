//go:build linux && amd64

package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

const ctxTestWait = 150 * time.Millisecond

func requireClosed(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(ctxTestWait):
		t.Fatal("done channel not closed")
	}
}

func requireOpen(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal("done channel closed early")
	default:
	}
}

func TestRequestContextUnusedDoesNotAllocate(t *testing.T) {
	r := &Request{}
	r.Reset()
	allocs := testing.AllocsPerRun(1000, func() {
		r.resetFastH1()
		r.Reset()
	})
	if allocs != 0 {
		t.Fatalf("allocs = %v, want 0", allocs)
	}
	if r.cancelSrc != nil {
		t.Fatal("cancel state created without Context()")
	}
}

func TestRequestContextCancelAfterDone(t *testing.T) {
	r := &Request{}
	ctx := r.Context()
	done := ctx.Done()
	requireOpen(t, done)
	if ctx.Err() != nil {
		t.Fatalf("Err = %v before cancel", ctx.Err())
	}
	r.cancelRequest(ErrClientGone)
	requireClosed(t, done)
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("Err = %v, want context.Canceled", ctx.Err())
	}
	if r.CancelCause() != ErrClientGone {
		t.Fatalf("CancelCause = %v, want ErrClientGone", r.CancelCause())
	}
}

func TestRequestContextCancelBeforeContext(t *testing.T) {
	r := &Request{}
	r.cancelRequest(ErrServerShutdown)
	ctx := r.Context()
	requireClosed(t, ctx.Done())
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("Err = %v, want context.Canceled", ctx.Err())
	}
	if r.CancelCause() != ErrServerShutdown {
		t.Fatalf("CancelCause = %v, want ErrServerShutdown", r.CancelCause())
	}
}

func TestRequestContextFirstCauseWins(t *testing.T) {
	r := &Request{}
	r.cancelRequest(ErrClientGone)
	r.cancelRequest(ErrServerShutdown)
	if r.CancelCause() != ErrClientGone {
		t.Fatalf("CancelCause = %v, want ErrClientGone", r.CancelCause())
	}
}

func TestRequestContextNoCauseWhileRunning(t *testing.T) {
	r := &Request{}
	if r.CancelCause() != nil {
		t.Fatal("CancelCause non-nil before Context()")
	}
	_ = r.Context()
	if r.CancelCause() != nil {
		t.Fatal("CancelCause non-nil on live request")
	}
}

func TestRequestContextFinishedOnReset(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reset func(*Request)
	}{
		{"Reset", (*Request).Reset},
		{"resetFastH1", (*Request).resetFastH1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Request{}
			old := r.Context()
			tc.reset(r)
			requireClosed(t, old.Done())
			if !errors.Is(old.Err(), context.Canceled) {
				t.Fatalf("old Err = %v", old.Err())
			}
			fresh := r.Context()
			if fresh == old {
				t.Fatal("reset reused the finished context")
			}
			requireOpen(t, fresh.Done())
			if fresh.Err() != nil {
				t.Fatalf("fresh Err = %v", fresh.Err())
			}
		})
	}
}

func TestRequestContextSetContextOverrides(t *testing.T) {
	r := &Request{}
	custom, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.SetContext(custom)
	if r.Context() != custom {
		t.Fatal("SetContext not returned by Context()")
	}
	r.Reset()
	if r.Context() == custom {
		t.Fatal("Reset kept the custom context")
	}
}

func TestRequestContextPropagatesToDerived(t *testing.T) {
	r := &Request{}
	child, cancel := context.WithTimeout(r.Context(), time.Hour)
	defer cancel()
	r.cancelRequest(ErrClientGone)
	requireClosed(t, child.Done())
	if !errors.Is(child.Err(), context.Canceled) {
		t.Fatalf("child Err = %v", child.Err())
	}
}

func TestRequestContextCopySharesSlot(t *testing.T) {
	r := &Request{cancelSrc: &cancelSlot{}}
	ctx := r.Context()
	copied := *r
	copied.cancelRequest(ErrClientGone)
	requireClosed(t, ctx.Done())
	if r.CancelCause() != ErrClientGone {
		t.Fatalf("CancelCause = %v", r.CancelCause())
	}
}

func TestRequestContextSlotReuseIsolatesRequests(t *testing.T) {
	slot := &cancelSlot{}
	first := &Request{cancelSrc: slot}
	old := first.Context()
	first.finishContext()
	second := &Request{cancelSrc: slot}
	fresh := second.Context()
	if fresh == old {
		t.Fatal("slot reused the finished state")
	}
	requireOpen(t, fresh.Done())
	if second.CancelCause() != nil {
		t.Fatalf("second request inherited cause %v", second.CancelCause())
	}
}

func TestRequestContextValueAndDeadline(t *testing.T) {
	ctx := (&Request{}).Context()
	if ctx.Value("k") != nil {
		t.Fatal("Value non-nil")
	}
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("unexpected deadline")
	}
}

func TestRequestContextConcurrentCancel(t *testing.T) {
	const handlers = 16
	for round := 0; round < 200; round++ {
		r := &Request{cancelSrc: &cancelSlot{}}
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < handlers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				ctx := r.Context()
				<-ctx.Done()
				if !errors.Is(ctx.Err(), context.Canceled) {
					t.Errorf("Err = %v", ctx.Err())
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r.cancelRequest(ErrClientGone)
		}()
		close(start)
		wg.Wait()
		if r.CancelCause() != ErrClientGone {
			t.Fatalf("round %d: CancelCause = %v", round, r.CancelCause())
		}
	}
}

func TestRequestContextConcurrentFinish(t *testing.T) {
	for round := 0; round < 200; round++ {
		slot := &cancelSlot{}
		r := &Request{cancelSrc: slot}
		ctx := r.Context()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			slot.cancel(ErrClientGone)
		}()
		go func() {
			defer wg.Done()
			slot.finish()
		}()
		wg.Wait()
		requireClosed(t, ctx.Done())
	}
}

func BenchmarkRequestContextUnused(b *testing.B) {
	r := &Request{}
	b.ReportAllocs()
	for b.Loop() {
		r.resetFastH1()
	}
}

func BenchmarkRequestContextDone(b *testing.B) {
	r := &Request{}
	b.ReportAllocs()
	for b.Loop() {
		_ = r.Context().Done()
		r.resetFastH1()
	}
}
