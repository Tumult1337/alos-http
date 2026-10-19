//go:build linux && amd64

package core

import "testing"

func TestAppFixPanickingOnPanicHookIsContained(t *testing.T) {
	calls := 0
	s := New(Config{OnPanic: func(*Request, any, []byte) {
		calls++
		panic("hook is broken too")
	}})
	defer s.perIPConnLimiter.Load().Stop()
	escaped := func() (r any) {
		defer func() { r = recover() }()
		s.reportPanic(&Request{Method: "GET", Path: "/boom"}, "handler panic")
		return nil
	}()
	if escaped != nil {
		t.Fatalf("a panic inside Config.OnPanic escaped reportPanic (it is raised inside the recover handlers and kills the process): %v", escaped)
	}
	if calls != 1 {
		t.Fatalf("OnPanic called %d times, want 1", calls)
	}
}
