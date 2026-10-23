//go:build linux && amd64

package core

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPerfAtomicsBodyBudgetNeverOverAdmits(t *testing.T) {
	const (
		limit      = 1 << 20
		goroutines = 16
		rounds     = 20000
	)
	s := perfAtomicsServer()
	s.config.MaxInFlightBodyBytes = limit
	var held, peak atomic.Int64
	var refused atomic.Int64
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := range rounds {
				n := 1 + (seed*7919+i*104729)%(limit/4)
				if !s.tryReserveBodyBytes(n) {
					refused.Add(1)
					continue
				}
				now := held.Add(int64(n))
				for {
					p := peak.Load()
					if now <= p || peak.CompareAndSwap(p, now) {
						break
					}
				}
				held.Add(-int64(n))
				s.releaseBodyBytes(int64(n))
			}
		}(g)
	}
	wg.Wait()
	if p := peak.Load(); p > limit {
		t.Fatalf("admitted %d bytes at once, limit %d", p, limit)
	}
	if used := s.inFlightBodyBytes.Load(); used != 0 {
		t.Fatalf("budget leaked: %d bytes still reserved", used)
	}
	if refused.Load() == 0 {
		t.Fatal("budget never refused: the test did not reach the limit")
	}
}

func TestPerfAtomicsBodyBudgetRefusesOversizeWithoutCharging(t *testing.T) {
	s := perfAtomicsServer()
	s.config.MaxInFlightBodyBytes = 1 << 20
	if s.tryReserveBodyBytes(1<<20 + 1) {
		t.Fatal("reservation larger than the whole budget admitted")
	}
	if s.tryReserveBodyBytes(math.MaxInt) {
		t.Fatal("max-int reservation admitted")
	}
	if used := s.inFlightBodyBytes.Load(); used != 0 {
		t.Fatalf("refused reservations left %d bytes charged", used)
	}
	if !s.tryReserveBodyBytes(1 << 20) {
		t.Fatal("reservation equal to the budget refused")
	}
	if s.tryReserveBodyBytes(1) {
		t.Fatal("reservation beyond a full budget admitted")
	}
	s.releaseBodyBytes(1 << 20)
}

func TestPerfAtomicsBodyBudgetHugeLimitStaysExact(t *testing.T) {
	s := perfAtomicsServer()
	s.config.MaxInFlightBodyBytes = math.MaxInt64
	if !s.tryReserveBodyBytes(math.MaxInt64 - 10) {
		t.Fatal("reservation within a max-int64 budget refused")
	}
	if s.tryReserveBodyBytes(11) {
		t.Fatal("reservation that would overflow the budget admitted")
	}
	if !s.tryReserveBodyBytes(10) {
		t.Fatal("reservation filling the budget exactly refused")
	}
	s.releaseBodyBytes(10)
	s.releaseBodyBytes(math.MaxInt64 - 10)
	if used := s.inFlightBodyBytes.Load(); used != 0 {
		t.Fatalf("budget leaked: %d", used)
	}
}
