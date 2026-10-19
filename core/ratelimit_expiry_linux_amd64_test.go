package core

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/guno1928/alosmap"
)

type rateExpiryFixture struct {
	now                  atomic.Int64
	counter              *rateLimitCounter
	window, block, grace int64
	max                  int64
	check                func() bool
	current              func() (*rateLimitCounter, bool)
	admitOld             func() (bool, time.Duration)
	retireOld            func(int64) bool
	cleanup              func(int64)
	replace              func() *rateLimitCounter
	blockMap             func(chan<- struct{}, <-chan struct{})
}

func newRateExpiryFixture(t *testing.T, engine bool, max int64, window, block time.Duration) *rateExpiryFixture {
	t.Helper()
	f := &rateExpiryFixture{window: int64(window), block: int64(block), max: max}
	f.now.Store(int64(5*time.Hour + 15*time.Minute))
	if engine {
		e := newRateLimitEngineWithClock(f.now.Load)
		t.Cleanup(e.Stop)
		e.SetRules([]RateLimitRule{{Path: "/expiry", MaxReqs: max, Window: window, BlockFor: block}})
		key := "192.0.2.1|/expiry"
		entry := e.entryFor(key)
		rule := e.matchRule("/expiry")
		f.counter = &entry.rateLimitCounter
		f.grace = int64(time.Minute)
		f.check = func() bool { ok, _, _ := e.Check("192.0.2.1", "/expiry"); return ok }
		f.current = func() (*rateLimitCounter, bool) {
			entry, ok := e.clients.Load(key)
			if !ok {
				return nil, false
			}
			return &entry.rateLimitCounter, true
		}
		f.admitOld = func() (bool, time.Duration) { return e.admitEntry(key, entry, rule) }
		f.retireOld = func(now int64) bool { return e.retireEntry(key, entry, now) }
		f.cleanup = e.cleanupStale
		f.blockMap = func(entered chan<- struct{}, release <-chan struct{}) {
			e.clients.Compute(key, func(old *rlEntry, _ bool) (*rlEntry, alosmap.ComputeOp) {
				close(entered)
				<-release
				return old, alosmap.CancelOp
			})
		}
		f.replace = func() *rateLimitCounter {
			replacement := &rlEntry{}
			e.clients.Store(key, replacement)
			return &replacement.rateLimitCounter
		}
	} else {
		stop := make(chan struct{})
		t.Cleanup(func() { close(stop) })
		middleware, state := newRateLimitMiddlewareWithClock(RateLimitMiddlewareConfig{MaxRequests: max, Window: window, KeyFunc: func(*Request) string { return "expiry" }, StopCh: stop}, f.now.Load)
		handler := middleware(func(_ *Request, resp *Response) { resp.Status(200) })
		entry := state.entryFor("expiry")
		f.counter = &entry.rateLimitCounter
		f.block = int64(rateLimitBlockFor)
		f.check = func() bool {
			req := &Request{RemoteAddr: "192.0.2.1:1234", Path: "/expiry"}
			resp := &Response{}
			handler(req, resp)
			return resp.StatusCode == 200
		}
		f.current = func() (*rateLimitCounter, bool) {
			entry, ok := state.entries.Load("expiry")
			if !ok {
				return nil, false
			}
			return &entry.rateLimitCounter, true
		}
		f.admitOld = func() (bool, time.Duration) { return state.admitEntry("expiry", entry, f.window, f.max, f.block) }
		f.retireOld = func(now int64) bool { return state.retireEntry("expiry", entry, now) }
		f.cleanup = state.cleanupStale
		f.blockMap = func(entered chan<- struct{}, release <-chan struct{}) {
			state.entries.Compute("expiry", func(old *rateLimitMWEntry, _ bool) (*rateLimitMWEntry, alosmap.ComputeOp) {
				close(entered)
				<-release
				return old, alosmap.CancelOp
			})
		}
		f.replace = func() *rateLimitCounter {
			replacement := &rateLimitMWEntry{}
			state.entries.Store("expiry", replacement)
			return &replacement.rateLimitCounter
		}
	}
	return f
}

func rateExpiryWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(h2FixCeiling):
		t.Fatal("controlled limiter stage did not complete")
	}
}

func TestRateLimitExpiryTransitionExcludesCompetingAdmission(t *testing.T) {
	for _, engine := range []bool{false, true} {
		for _, phase := range []string{"observed-block", "unblocked"} {
			t.Run(fmt.Sprintf("engine=%v/%s", engine, phase), func(t *testing.T) {
				f := newRateExpiryFixture(t, engine, 2, time.Hour, rateLimitBlockFor)
				for range 2 {
					if !f.check() {
						t.Fatal("quota fixture refused")
					}
				}
				if f.check() {
					t.Fatal("quota fixture did not block")
				}
				if current, ok := f.current(); !ok || current != f.counter || f.counter.state.Load()&rlCountMask != 3 {
					t.Fatal("public path did not own expected blocked counter")
				}
				f.now.Store(f.counter.blocked.Load())
				paused, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				var visits atomic.Int32
				pause := func() { visits.Add(1); close(paused); <-release }
				hooks := &rateLimitTransitionHooks{}
				if phase == "observed-block" {
					hooks.afterBlockedRead = pause
				} else {
					hooks.afterUnblock = pause
				}
				first := make(chan bool, 1)
				go func() {
					defer close(done)
					allowed, _, live := f.counter.admit(f.now.Load, f.window, f.max, f.block, hooks)
					first <- allowed && live
				}()
				t.Cleanup(func() { unblock(); rateExpiryWait(t, done) })
				rateExpiryWait(t, paused)
				wantBlock := f.now.Load()
				if phase == "unblocked" {
					wantBlock = 0
				}
				if f.counter.blocked.Load() != wantBlock || f.counter.state.Load()&rlCountMask != 3 {
					t.Fatal("controlled pause did not expose the intended partial-reset stage")
				}
				escaped := f.counter.mu.TryLock()
				if escaped {
					f.counter.mu.Unlock()
					t.Error("partial expiry was published without entry exclusion")
				}
				others := make(chan int, 1)
				compete := func() {
					allowed := 0
					for range 3 {
						if f.check() {
							allowed++
						}
					}
					others <- allowed
				}
				if escaped {
					compete()
				} else {
					go compete()
				}
				unblock()
				rateExpiryWait(t, done)
				var allowed int
				select {
				case allowed = <-others:
				case <-time.After(h2FixCeiling):
					t.Fatal("competing public admissions did not finish")
				}
				if <-first {
					allowed++
				}
				if visits.Load() != 1 || allowed != 2 || f.counter.state.Load()&rlCountMask != 3 || f.counter.blocked.Load() != f.now.Load()+f.block {
					t.Fatalf("expiry erased quota/block: hooks=%d allowed=%d count=%d blocked=%d now=%d", visits.Load(), allowed, f.counter.state.Load()&rlCountMask, f.counter.blocked.Load(), f.now.Load())
				}
				if f.check() {
					t.Fatal("published new block disappeared")
				}
			})
		}
	}
}

func TestRateLimitExpiryRetirementRetriesActualCaller(t *testing.T) {
	for _, engine := range []bool{false, true} {
		t.Run(fmt.Sprintf("engine=%v", engine), func(t *testing.T) {
			f := newRateExpiryFixture(t, engine, 1, time.Second, time.Hour)
			if !f.check() {
				t.Fatal("first admission refused")
			}
			oldState := f.counter.state.Load()
			stale := f.counter.reset.Load() + f.grace + 1
			f.now.Store(stale)
			if !f.retireOld(stale) {
				t.Fatal("unchanged stale entry not retired")
			}
			if _, ok := f.current(); ok {
				t.Fatal("retired pointer remains in map")
			}
			if allowed, _ := f.admitOld(); !allowed {
				t.Fatal("cached-pointer admission did not retry live lookup")
			}
			current, ok := f.current()
			if !ok || current == f.counter || current.state.Load()&rlCountMask != 1 || f.counter.state.Load() != oldState {
				t.Fatal("retry counted on orphan instead of fresh entry")
			}
			if f.check() {
				t.Fatal("cached-pointer admission was not charged on actual public path")
			}
		})
	}
}

func TestRateLimitExpiryCleanupRechecksFreshness(t *testing.T) {
	for _, engine := range []bool{false, true} {
		t.Run(fmt.Sprintf("engine=%v", engine), func(t *testing.T) {
			f := newRateExpiryFixture(t, engine, 1, time.Second, time.Hour)
			if !f.check() {
				t.Fatal("first admission refused")
			}
			sampled := f.counter
			stale := sampled.reset.Load() + f.grace + 1
			f.now.Store(stale)
			if !f.check() || f.check() {
				t.Fatal("intervening request did not refresh and block old pointer")
			}
			checkAt := sampled.reset.Load() + f.grace + 1
			if checkAt >= sampled.blocked.Load() {
				t.Fatal("fixture block does not survive stale reset threshold")
			}
			f.now.Store(checkAt)
			if f.retireOld(checkAt) {
				t.Fatal("stale observation deleted newly blocked entry")
			}
			if current, ok := f.current(); !ok || current != sampled {
				t.Fatal("retirement replaced refreshed state")
			}
			if f.check() {
				t.Fatal("fresh block lost after retirement attempt")
			}
		})
	}
}

func TestRateLimitExpiryCleanupResamplesClockAfterRefresh(t *testing.T) {
	for _, engine := range []bool{false, true} {
		t.Run(fmt.Sprintf("engine=%v", engine), func(t *testing.T) {
			f := newRateExpiryFixture(t, engine, 1, time.Second, time.Hour)
			original := f.now.Load()
			if !f.check() {
				t.Fatal("first admission refused")
			}
			cutoff := f.counter.reset.Load() + f.grace + 1
			f.now.Store(original - int64(time.Hour))
			if !f.check() || f.counter.state.Load()&rlCountMask != 1 {
				t.Fatal("public caller did not refresh counter after clock rollback")
			}
			if f.check() || f.counter.blocked.Load() <= f.now.Load() {
				t.Fatal("public caller did not publish an active block")
			}
			if cutoff <= f.counter.reset.Load()+f.grace || cutoff <= f.counter.blocked.Load() {
				t.Fatal("stale pass cutoff does not select the refreshed entry")
			}
			f.cleanup(cutoff)
			if current, ok := f.current(); !ok || current != f.counter {
				t.Fatal("stale janitor clock retired refreshed counter with an active block")
			}
			if f.check() {
				t.Fatal("janitor erased the active block observed by the public caller")
			}
		})
	}
}

func TestRateLimitExpiryRetirementKeepsPassCutoff(t *testing.T) {
	for _, engine := range []bool{false, true} {
		t.Run(fmt.Sprintf("engine=%v", engine), func(t *testing.T) {
			f := newRateExpiryFixture(t, engine, 1, time.Second, time.Hour)
			if !f.check() {
				t.Fatal("first admission refused")
			}
			cutoff := f.counter.reset.Load() + f.grace
			f.now.Store(cutoff + 1)
			if f.retireOld(cutoff) {
				t.Fatal("fresh clock advanced retirement beyond the pass cutoff")
			}
			if current, ok := f.current(); !ok || current != f.counter {
				t.Fatal("entry at strict pass boundary disappeared")
			}
			if !f.retireOld(cutoff + 1) {
				t.Fatal("entry eligible under both clocks was not retired")
			}
		})
	}
}

func TestRateLimitExpiryRetirementClockInsideExclusion(t *testing.T) {
	for _, engine := range []bool{false, true} {
		t.Run(fmt.Sprintf("engine=%v", engine), func(t *testing.T) {
			var counter *rateLimitCounter
			calls := 0
			now := func() int64 {
				calls++
				if counter.mu.TryLock() {
					counter.mu.Unlock()
					t.Error("retirement clock sampled outside entry exclusion")
				}
				return int64(2 * time.Minute)
			}
			var retire func() bool
			if engine {
				entry := &rlEntry{}
				counter = &entry.rateLimitCounter
				state := &RateLimitEngine{clients: alosmap.NewTyped[string, *rlEntry](), now: now}
				state.clients.Store("expiry", entry)
				retire = func() bool { return state.retireEntry("expiry", entry, int64(3*time.Minute)) }
			} else {
				entry := &rateLimitMWEntry{}
				counter = &entry.rateLimitCounter
				state := &rateLimitMiddlewareState{entries: alosmap.NewTyped[string, *rateLimitMWEntry](), now: now}
				state.entries.Store("expiry", entry)
				retire = func() bool { return state.retireEntry("expiry", entry, int64(3*time.Minute)) }
			}
			if !retire() || calls != 1 || !counter.retired {
				t.Fatalf("retirement did not sample its clock once and retire: calls=%d retired=%v", calls, counter.retired)
			}
		})
	}
}

func TestRateLimitExpiryCleanupIdentity(t *testing.T) {
	for _, engine := range []bool{false, true} {
		t.Run(fmt.Sprintf("engine=%v", engine), func(t *testing.T) {
			f := newRateExpiryFixture(t, engine, 1, time.Second, time.Hour)
			if !f.check() {
				t.Fatal("first admission refused")
			}
			stale := f.counter.reset.Load() + f.grace + 1
			replacement := f.replace()
			f.now.Store(stale)
			if f.retireOld(stale) {
				t.Fatal("retirement deleted a different pointer")
			}
			if f.counter.retired || replacement.retired {
				t.Fatal("failed identity deletion marked an entry retired")
			}
			if current, ok := f.current(); !ok || current != replacement {
				t.Fatal("replacement disappeared")
			}
		})
	}
}

func TestRateLimitExpiryJanitorBoundaryAndReachability(t *testing.T) {
	for _, engine := range []bool{false, true} {
		t.Run(fmt.Sprintf("engine=%v", engine), func(t *testing.T) {
			f := newRateExpiryFixture(t, engine, 1, time.Second, time.Hour)
			if !f.check() {
				t.Fatal("first admission refused")
			}
			at := f.counter.reset.Load() + f.grace
			f.now.Store(at)
			if f.retireOld(at) {
				t.Fatal("retirement changed strict reset boundary")
			}
			f.cleanup(at)
			if _, ok := f.current(); !ok {
				t.Fatal("cleanup changed strict reset boundary")
			}
			f.now.Store(at + 1)
			f.cleanup(at + 1)
			if _, ok := f.current(); ok || !f.counter.retired {
				t.Fatal("actual janitor path did not retire stale entry")
			}
		})
	}
}

func TestRateLimitExpiryBlockedBoundaryAndRemaining(t *testing.T) {
	counter := &rateLimitCounter{}
	var now atomic.Int64
	now.Store(int64(5 * time.Hour))
	if allowed, _, _ := counter.admit(now.Load, int64(time.Hour), 1, int64(time.Minute), nil); !allowed {
		t.Fatal("first admission refused")
	}
	if allowed, wait, _ := counter.admit(now.Load, int64(time.Hour), 1, int64(time.Minute), nil); allowed || wait != time.Minute {
		t.Fatal("block not published with configured duration")
	}
	state, reset, blocked := counter.state.Load(), counter.reset.Load(), counter.blocked.Load()
	now.Add(int64(time.Second))
	if allowed, wait, _ := counter.admit(now.Load, int64(time.Hour), 1, int64(time.Minute), nil); allowed || wait != 59*time.Second {
		t.Fatal("blocked request did not retain remaining duration")
	}
	if state != counter.state.Load() || reset != counter.reset.Load() || blocked != counter.blocked.Load() {
		t.Fatal("blocked request mutated count/reset/block")
	}
	now.Store(blocked)
	if allowed, _, _ := counter.admit(now.Load, int64(time.Hour), 1, int64(time.Minute), nil); !allowed || counter.state.Load()&rlCountMask != 1 {
		t.Fatal("exact expiry did not reset within same epoch")
	}
}

func TestRateLimitExpiryClockInsideExclusion(t *testing.T) {
	counter := &rateLimitCounter{}
	var calls int
	now := func() int64 {
		calls++
		if counter.mu.TryLock() {
			counter.mu.Unlock()
			t.Error("clock sampled outside entry exclusion")
		}
		return int64(5 * time.Hour)
	}
	if allowed, _, _ := counter.admit(now, int64(time.Hour), 1, int64(time.Minute), nil); !allowed || calls != 1 {
		t.Fatal("injected clock not used exactly once")
	}
}

func TestRateLimitExpiryInstanceClockIndependence(t *testing.T) {
	for _, engine := range []bool{false, true} {
		t.Run(fmt.Sprintf("engine=%v", engine), func(t *testing.T) {
			first := newRateExpiryFixture(t, engine, 1, time.Second, time.Hour)
			second := newRateExpiryFixture(t, engine, 1, time.Second, time.Hour)
			second.now.Add(int64(time.Hour))
			if !first.check() || !second.check() {
				t.Fatal("independent first admissions refused")
			}
			if first.counter.state.Load()&^rlCountMask != rlEpochOf(first.now.Load(), first.window) || second.counter.state.Load()&^rlCountMask != rlEpochOf(second.now.Load(), second.window) {
				t.Fatal("public callers ignored the exact injected clock epoch")
			}
			if first.counter.state.Load() == second.counter.state.Load() {
				t.Fatal("instances did not use their distinct injected clocks")
			}
			first.now.Add(int64(time.Second))
			if !first.check() || second.check() {
				t.Fatal("advancing one clock changed another instance")
			}
		})
	}
}

func TestRateLimitExpiryCallbacksRunUnlocked(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	var state *rateLimitMiddlewareState
	var callbacks int
	checkUnlocked := func() {
		entry := state.entryFor("callback")
		if !entry.mu.TryLock() {
			t.Error("user callback runs under entry lock")
		} else {
			entry.mu.Unlock()
		}
		callbacks++
	}
	middleware, created := newRateLimitMiddlewareWithClock(RateLimitMiddlewareConfig{MaxRequests: 1, Window: time.Hour, StopCh: stop, KeyFunc: func(*Request) string { return "callback" }, OnLimit: func(_ RateLimitEvent, _ *Request, _ *Response) bool { checkUnlocked(); return false }}, func() int64 { return int64(5 * time.Hour) })
	state = created
	handler := middleware(func(_ *Request, resp *Response) { checkUnlocked(); resp.Status(200) })
	req := &Request{RemoteAddr: "192.0.2.1:1234", Path: "/callback"}
	first, second := &Response{}, &Response{}
	handler(req, first)
	handler(req, second)
	if callbacks != 2 || first.StatusCode != 200 || second.StatusCode != 429 {
		t.Fatal("callback/default refusal path changed")
	}
	found := false
	for _, header := range second.Headers {
		if header[0] == "Retry-After" && header[1] == "30" {
			found = true
		}
	}
	if !found {
		t.Fatal("initial middleware Retry-After changed")
	}
}

func TestRateLimitExpiryEngineStopConcurrent(t *testing.T) {
	engine := NewRateLimitEngine()
	t.Cleanup(engine.Stop)
	start := make(chan struct{})
	var group sync.WaitGroup
	var panics atomic.Int32
	for range 128 {
		group.Add(1)
		go func() {
			defer group.Done()
			defer func() {
				if recover() != nil {
					panics.Add(1)
				}
			}()
			<-start
			engine.Stop()
		}()
	}
	close(start)
	group.Wait()
	engine.Stop()
	if panics.Load() != 0 {
		t.Fatalf("concurrent Stop panicked %d times", panics.Load())
	}
	select {
	case <-engine.stopCh:
	default:
		t.Fatal("Stop did not close janitor channel")
	}
}

func TestRateLimitExpiryEntryFootprint(t *testing.T) {
	if unsafe.Sizeof(rlEntry{}) != CacheLineSize {
		t.Fatalf("engine entry grew to %d bytes", unsafe.Sizeof(rlEntry{}))
	}
	t.Logf("engine=%d middleware=%d counter=%d", unsafe.Sizeof(rlEntry{}), unsafe.Sizeof(rateLimitMWEntry{}), unsafe.Sizeof(rateLimitCounter{}))
}

func TestRateLimitExpiryRetirementHoldsExclusionThroughDeletion(t *testing.T) {
	for _, engine := range []bool{false, true} {
		t.Run(fmt.Sprintf("engine=%v", engine), func(t *testing.T) {
			f := newRateExpiryFixture(t, engine, 1, time.Second, time.Hour)
			if !f.check() {
				t.Fatal("first admission refused")
			}
			stale := f.counter.reset.Load() + f.grace + 1
			entered, release, mapDone, retireDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			f.now.Store(stale)
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			go func() { defer close(mapDone); f.blockMap(entered, release) }()
			t.Cleanup(func() { unblock(); rateExpiryWait(t, mapDone); rateExpiryWait(t, retireDone) })
			rateExpiryWait(t, entered)
			result := make(chan bool, 1)
			go func() { defer close(retireDone); result <- f.retireOld(stale) }()
			start := time.Now()
			for f.counter.mu.TryLock() {
				f.counter.mu.Unlock()
				if time.Since(start) >= h2FixCeiling {
					t.Fatal("retirement did not exclude requests while waiting for identity deletion")
				}
				time.Sleep(time.Millisecond)
			}
			unblock()
			rateExpiryWait(t, retireDone)
			rateExpiryWait(t, mapDone)
			if !<-result || !f.counter.retired {
				t.Fatal("retirement did not finish under exclusion")
			}
		})
	}
}

func TestRateLimitExpiryEngineFallbackBlock(t *testing.T) {
	var now atomic.Int64
	now.Store(int64(5 * time.Hour))
	engine := newRateLimitEngineWithClock(now.Load)
	defer engine.Stop()
	engine.SetRules([]RateLimitRule{{Path: "/fallback", MaxReqs: 1, Window: time.Minute}})
	if allowed, _, _ := engine.Check("192.0.2.1", "/fallback"); !allowed {
		t.Fatal("first request refused")
	}
	if allowed, _, wait := engine.Check("192.0.2.1", "/fallback"); allowed || wait != time.Minute {
		t.Fatalf("configured window fallback changed: allowed=%v wait=%v", allowed, wait)
	}
}

func TestRateLimitExpiryMiddlewareDefaults(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	now := int64(5 * time.Hour)
	middleware, state := newRateLimitMiddlewareWithClock(RateLimitMiddlewareConfig{StopCh: stop}, func() int64 { return now })
	var admitted int
	handler := middleware(func(_ *Request, resp *Response) { admitted++; resp.Status(200) })
	request := &Request{RemoteAddr: "192.0.2.1:1234", Path: "/defaults"}
	for range 100 {
		handler(request, &Response{})
	}
	refused := &Response{}
	handler(request, refused)
	entry, ok := state.entries.Load("192.0.2.1")
	if !ok || admitted != 100 || refused.StatusCode != 429 || entry.reset.Load() != now+int64(time.Minute) || entry.blocked.Load() != now+int64(rateLimitBlockFor) {
		t.Fatal("middleware max/window/block defaults changed")
	}
}

func TestRateLimitExpiryRetiredCounterDoesNotReadClock(t *testing.T) {
	counter := &rateLimitCounter{retired: true}
	counter.state.Store(19)
	calls := 0
	allowed, wait, live := counter.admit(func() int64 { calls++; return int64(time.Hour) }, int64(time.Minute), 1, int64(time.Second), nil)
	if allowed || wait != 0 || live || calls != 0 || counter.state.Load() != 19 {
		t.Fatal("retired counter was treated as live or mutated")
	}
}

func TestRateLimitExpiryRetirementBlockedBoundary(t *testing.T) {
	for _, engine := range []bool{false, true} {
		t.Run(fmt.Sprintf("engine=%v", engine), func(t *testing.T) {
			f := newRateExpiryFixture(t, engine, 1, time.Second, time.Hour)
			if !f.check() || f.check() {
				t.Fatal("fixture did not publish block")
			}
			at := f.counter.blocked.Load()
			if at <= f.counter.reset.Load()+f.grace {
				t.Fatal("fixture reset is not stale at block boundary")
			}
			f.now.Store(at)
			if f.retireOld(at) {
				t.Fatal("retirement changed strict block boundary")
			}
			f.now.Store(at + 1)
			if !f.retireOld(at + 1) {
				t.Fatal("expired block prevented eligible retirement")
			}
		})
	}
}
