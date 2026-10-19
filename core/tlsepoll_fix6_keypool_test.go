//go:build linux && amd64

package core

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	tlsEpollFix6FillersStarted = 3
	tlsEpollFix6Poll           = 10 * time.Millisecond
)

func tlsEpollFix6Server(t *testing.T) *Server {
	return New(Config{Addr: freeLoopbackAddr(t), HTTPAddr: "-", MaxConnsPerIP: -1, Listeners: 1, Certs: []CertConfig{{Domain: harnessDomain, Source: CertSelfSigned}}})
}

func TestTLSEpollFix6ShutdownBeforeTLSStartupLeavesNoKeyPool(t *testing.T) {
	srv := tlsEpollFix6Server(t)
	if err := <-tlsEpollFixShutdownAsync(srv, harnessIOTimeout); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServeTLS() }()
	select {
	case <-served:
	case <-turbo.After(tlsEpollFixServeReturnLimit):
		t.Fatal("ListenAndServeTLS did not return after Shutdown")
	}
	if pool := srv.x25519Pool; pool != nil {
		pool.Close()
		t.Fatal("ListenAndServeTLS after Shutdown started an x25519 key pool that nothing closes")
	}
}

func TestTLSEpollFix6TimedOutShutdownStopsKeyPool(t *testing.T) {
	srv := tlsEpollFix6Server(t)
	srv.ensureTLSRuntime()
	pool := srv.x25519Pool
	srv.activeConns.Add(1)
	defer srv.activeConns.Add(-1)
	ctx, cancel := context.WithTimeout(context.Background(), tlsEpollFixGoAwayWait)
	defer cancel()
	if err := srv.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown with a connection still open = %v, want context.DeadlineExceeded", err)
	}
	select {
	case <-pool.stop:
	default:
		pool.Close()
		t.Fatal("Shutdown that hit its deadline left the x25519 key pool fill goroutines running")
	}
}

func TestTLSEpollFix6ShutdownConcurrentWithTLSRuntimeRaceFree(t *testing.T) {
	srv := tlsEpollFix6Server(t)
	baseline := runtime.NumGoroutine()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		srv.ensureTLSRuntime()
	}()
	go func() {
		defer wg.Done()
		deadline := turbo.Deadline(tlsEpollFixServeReturnLimit)
		for runtime.NumGoroutine() < baseline+tlsEpollFix6FillersStarted && turbo.Until(deadline) > 0 {
			time.Sleep(tlsEpollFix6Poll)
		}
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	}()
	wg.Wait()
	srv.x25519Pool.Close()
}

func TestTLSEpollFix6NilKeyPoolStillHandsOutKeys(t *testing.T) {
	var pool *x25519KeyPool
	kp, err := pool.Get()
	if err != nil {
		t.Fatalf("Get on a nil pool: %v", err)
	}
	defer kp.zero()
	if kp.pub == [32]byte{} {
		t.Fatal("Get on a nil pool returned an all-zero public key")
	}
}
