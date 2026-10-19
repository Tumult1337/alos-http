//go:build linux && amd64

package core

import (
	"sync"
	"testing"
	"time"
)

const outlierTestStart = int64(1000 * time.Hour)

func newOutlierTestDomain(n int, cfg OutlierConfig) (*domainState, *fakeClock) {
	backends := make([]*backend, n)
	for i := range backends {
		backends[i] = &backend{Addr: "10.0.0.1:80", Weight: 1}
		backends[i].Healthy.Store(true)
	}
	cfg.normalize()
	ds := newDomainState(DomainConfig{Outlier: cfg}, backends)
	clock := newFakeClock(outlierTestStart)
	ds.outlier.now = clock.now
	return ds, clock
}

func failTimes(d *outlierDetector, b *backend, n int) {
	for i := 0; i < n; i++ {
		d.recordFailure(b)
	}
}

func ejectedCount(ds *domainState, now int64) int {
	n := 0
	for _, b := range ds.backends {
		if b.ejected(now) {
			n++
		}
	}
	return n
}

func TestOutlierConfigDefaults(t *testing.T) {
	var oc OutlierConfig
	oc.normalize()
	want := OutlierConfig{ConsecutiveFailures: 5, BaseEject: 30 * time.Second, MaxEject: 5 * time.Minute, MaxEjectPercent: 50}
	if oc != want {
		t.Fatalf("defaults %+v, want %+v", oc, want)
	}
	oc = OutlierConfig{BaseEject: time.Hour, MaxEject: time.Minute, MaxEjectPercent: 250}
	oc.normalize()
	if oc.MaxEject != time.Hour || oc.MaxEjectPercent != 100 {
		t.Fatalf("MaxEject %v MaxEjectPercent %d, want MaxEject raised to BaseEject and percent capped at 100", oc.MaxEject, oc.MaxEjectPercent)
	}
	var dc DomainConfig
	dc.normalize()
	if dc.Outlier != want {
		t.Fatalf("DomainConfig.normalize left Outlier %+v", dc.Outlier)
	}
}

func TestProxyOutlier(t *testing.T) {
	t.Run("five consecutive failures eject for BaseEject", func(t *testing.T) {
		ds, clock := newOutlierTestDomain(2, OutlierConfig{})
		bad := ds.backends[0]
		failTimes(ds.outlier, bad, 4)
		if bad.ejected(clock.now()) {
			t.Fatal("ejected after 4 failures")
		}
		ds.outlier.recordFailure(bad)
		if !bad.ejected(clock.now()) || bad.available(clock.now()) {
			t.Fatal("not ejected after 5 failures")
		}
		clock.advance(30*time.Second - time.Nanosecond)
		if !bad.ejected(clock.now()) {
			t.Fatal("re-admitted before BaseEject")
		}
		clock.advance(time.Nanosecond)
		if bad.ejected(clock.now()) || !bad.available(clock.now()) {
			t.Fatal("not re-admitted after BaseEject")
		}
	})

	t.Run("a success resets the count", func(t *testing.T) {
		ds, clock := newOutlierTestDomain(2, OutlierConfig{})
		bad := ds.backends[0]
		failTimes(ds.outlier, bad, 4)
		ds.outlier.recordSuccess(bad)
		failTimes(ds.outlier, bad, 4)
		if bad.ejected(clock.now()) {
			t.Fatal("failures separated by a success ejected the backend")
		}
	})

	t.Run("5xx counts as a failure and other statuses as a success", func(t *testing.T) {
		ds, clock := newOutlierTestDomain(2, OutlierConfig{})
		bad := ds.backends[0]
		for _, status := range []int{502, 503, 500, 504} {
			ds.outlier.recordStatus(bad, status)
		}
		ds.outlier.recordStatus(bad, 404)
		for _, status := range []int{502, 503, 500, 504} {
			ds.outlier.recordStatus(bad, status)
		}
		if bad.ejected(clock.now()) {
			t.Fatal("a 404 did not reset the failure count")
		}
		ds.outlier.recordStatus(bad, 599)
		if !bad.ejected(clock.now()) {
			t.Fatal("five 5xx responses did not eject")
		}
	})

	t.Run("each ejection doubles up to MaxEject", func(t *testing.T) {
		ds, clock := newOutlierTestDomain(2, OutlierConfig{})
		bad := ds.backends[0]
		for _, want := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute} {
			failTimes(ds.outlier, bad, 5)
			got := time.Duration(bad.outlier.ejectedUntilNs.Load() - clock.now())
			if got != want {
				t.Fatalf("ejected for %v, want %v", got, want)
			}
			clock.advance(got)
		}
	})

	t.Run("doubling starts over after MaxEject in service", func(t *testing.T) {
		ds, clock := newOutlierTestDomain(2, OutlierConfig{})
		bad := ds.backends[0]
		failTimes(ds.outlier, bad, 5)
		clock.advance(30 * time.Second)
		failTimes(ds.outlier, bad, 5)
		clock.advance(time.Minute + 5*time.Minute)
		failTimes(ds.outlier, bad, 5)
		if got := time.Duration(bad.outlier.ejectedUntilNs.Load() - clock.now()); got != 30*time.Second {
			t.Fatalf("ejected for %v after a quiet MaxEject, want 30s", got)
		}
	})

	t.Run("failures while ejected do not extend the ejection", func(t *testing.T) {
		ds, clock := newOutlierTestDomain(2, OutlierConfig{})
		bad := ds.backends[0]
		failTimes(ds.outlier, bad, 5)
		until := bad.outlier.ejectedUntilNs.Load()
		failTimes(ds.outlier, bad, 20)
		if bad.outlier.ejectedUntilNs.Load() != until {
			t.Fatal("ejection extended by failures of requests already in flight")
		}
		clock.advance(30 * time.Second)
		if !bad.available(clock.now()) {
			t.Fatal("not re-admitted")
		}
	})

	t.Run("never more than MaxEjectPercent", func(t *testing.T) {
		for _, tc := range []struct {
			backends, percent, want int
		}{{1, 50, 0}, {2, 50, 1}, {3, 50, 1}, {4, 50, 2}, {4, 25, 1}, {4, 100, 4}, {10, 30, 3}} {
			ds, clock := newOutlierTestDomain(tc.backends, OutlierConfig{MaxEjectPercent: tc.percent})
			for _, b := range ds.backends {
				failTimes(ds.outlier, b, 5)
			}
			if got := ejectedCount(ds, clock.now()); got != tc.want {
				t.Errorf("%d backends at %d%%: %d ejected, want %d", tc.backends, tc.percent, got, tc.want)
			}
		}
	})

	t.Run("a backend held back by the cap is ejected once room frees up", func(t *testing.T) {
		ds, clock := newOutlierTestDomain(2, OutlierConfig{})
		first, second := ds.backends[0], ds.backends[1]
		failTimes(ds.outlier, first, 5)
		failTimes(ds.outlier, second, 5)
		if second.ejected(clock.now()) {
			t.Fatal("cap exceeded")
		}
		clock.advance(30 * time.Second)
		ds.outlier.recordFailure(second)
		if !second.ejected(clock.now()) {
			t.Fatal("held-back backend not ejected after the first returned")
		}
	})

	t.Run("disabled", func(t *testing.T) {
		ds, clock := newOutlierTestDomain(2, OutlierConfig{Disabled: true})
		failTimes(ds.outlier, ds.backends[0], 50)
		if ds.backends[0].ejected(clock.now()) {
			t.Fatal("ejected with Disabled set")
		}
	})

	t.Run("balancers skip an ejected backend", func(t *testing.T) {
		for _, lb := range []LoadBalancerType{LBRoundRobin, LBWeightedRR, LBLeastConn, LBIPHash, LBRandom} {
			ds, clock := newOutlierTestDomain(2, OutlierConfig{})
			failTimes(ds.outlier, ds.backends[0], 5)
			balancer := newBalancer(lb, ds.backends)
			for i := 0; i < 64; i++ {
				if got := balancer.pick(ds.backends, "198.51.100.7", clock.now()); got != 1 {
					t.Fatalf("balancer %d picked %d with backend 0 ejected", lb, got)
				}
			}
			clock.advance(30 * time.Second)
			seen := map[int]bool{}
			for i := 0; i < 64; i++ {
				seen[balancer.pick(ds.backends, "198.51.100.7", clock.now())] = true
			}
			if lb != LBIPHash && !seen[0] {
				t.Fatalf("balancer %d never picked the re-admitted backend", lb)
			}
		}
	})

	t.Run("retry fallback skips an ejected backend", func(t *testing.T) {
		ds, _ := newOutlierTestDomain(3, OutlierConfig{MaxEjectPercent: 100})
		failTimes(ds.outlier, ds.backends[0], 5)
		failTimes(ds.outlier, ds.backends[2], 5)
		tried := make([]bool, 3)
		tried[1] = true
		if got := pickRetryBackend(ds, "198.51.100.7", tried); got != -1 {
			t.Fatalf("picked %d, want none left", got)
		}
	})
}

func TestProxyOutlierParallel(t *testing.T) {
	const backends, goroutines, rounds = 8, 32, 400
	ds, clock := newOutlierTestDomain(backends, OutlierConfig{})
	stop := make(chan struct{})
	var watcher sync.WaitGroup
	watcher.Add(1)
	maxSeen := 0
	go func() {
		defer watcher.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			maxSeen = max(maxSeen, ejectedCount(ds, clock.now()))
		}
	}()
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				b := ds.backends[(g+i)%backends]
				if i%7 == 0 {
					ds.outlier.recordSuccess(b)
				} else {
					ds.outlier.recordFailure(b)
				}
				ds.balancer.pick(ds.backends, "", clock.now())
			}
		}(g)
	}
	wg.Wait()
	close(stop)
	watcher.Wait()
	if maxSeen > backends/2 {
		t.Fatalf("%d of %d backends ejected at once, cap is 50%%", maxSeen, backends)
	}
	if got := ejectedCount(ds, clock.now()); got != backends/2 {
		t.Fatalf("%d backends ejected at the end, want the cap of %d", got, backends/2)
	}
}
