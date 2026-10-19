//go:build linux && amd64

package core

import (
	"bytes"
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func cacheBoundsWantCost(key string, entry *cacheEntry) int64 {
	cost := int64(unsafe.Sizeof(cacheEntry{})) + int64(unsafe.Sizeof(key)) + int64(len(key))
	cost += int64(cap(entry.headers)) * int64(unsafe.Sizeof([2]string{}))
	cost += int64(len(entry.contentType)) + int64(cap(entry.body)) + int64(cap(entry.gzipBody))
	for _, field := range entry.headers {
		cost += int64(len(field[0])) + int64(len(field[1]))
	}
	return cost
}

func cacheBoundsAssertTotals(t *testing.T, pc *ProxyCache) {
	t.Helper()
	var count, cost int64
	pc.entries.Range(func(key string, entry *cacheEntry) bool {
		count++
		want := cacheBoundsWantCost(key, entry)
		if entry.cost != want {
			t.Fatalf("entry records %d owned bytes, want %d", entry.cost, want)
		}
		cost += want
		return true
	})
	gotCount, gotCost, _, _ := pc.Stats()
	if gotCount != count || gotCost != cost {
		t.Fatalf("counters %d entries/%d bytes, live entries %d/%d", gotCount, gotCost, count, cost)
	}
}

func cacheBoundsWaitIdle(t *testing.T, pc *ProxyCache) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for pc.evicting.Load() {
		if time.Now().After(deadline) {
			t.Fatal("eviction ownership did not clear")
		}
		runtime.Gosched()
	}
}

func TestProxyCacheBoundsOwnedCost(t *testing.T) {
	for _, tc := range []struct {
		name, path, contentType string
		headers                 [][2]string
		body                    []byte
		gzip                    bool
	}{
		{name: "empty", path: "/empty"},
		{name: "key", path: "/" + strings.Repeat("q", 4096)},
		{name: "content_type", path: "/type", contentType: "application/example-special"},
		{name: "headers", path: "/fields", headers: [][2]string{{"x-long-name", strings.Repeat("v", 171)}, {"x-b", "second-value"}}},
		{name: "body", path: "/body", body: []byte("123456789")},
		{name: "gzip", path: "/gzip", body: bytes.Repeat([]byte("a long compressible line\n"), 100), contentType: "text/plain", gzip: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultProxyCacheConfig()
			cfg.PreCompress = tc.gzip
			pc := NewProxyCache(cfg)
			defer pc.Stop()
			pc.Put("GET", "h.test", tc.path, 200, tc.headers, tc.contentType, tc.body)
			entry, hit := pc.GetFP("GET", "h.test", tc.path, true)
			if !hit || !bytes.Equal(entry.body, tc.body) {
				t.Fatal("fixture did not retain its expected response")
			}
			if tc.gzip && len(entry.gzipBody) == 0 {
				t.Fatal("fixture did not produce a gzip variant")
			}
			cacheBoundsAssertTotals(t, pc)
		})
	}
}

func TestProxyCacheBoundsClonesRetainedStrings(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{})
	defer pc.Stop()
	backing := strings.Repeat("0123456789", 1024)
	name, value, contentType := backing[1:19], backing[31:70], backing[71:99]
	pc.Put("GET", "h.test", "/clones", 200, [][2]string{{name, value}, {"set-cookie", backing[100:300]}}, contentType, nil)
	entry, hit := pc.GetFP("GET", "h.test", "/clones", true)
	if !hit || len(entry.headers) != 1 {
		t.Fatal("expected retained safe header")
	}
	for _, pair := range [][2]string{{entry.headers[0][0], name}, {entry.headers[0][1], value}, {entry.contentType, contentType}} {
		if pair[0] != pair[1] || unsafe.StringData(pair[0]) == unsafe.StringData(pair[1]) {
			t.Fatal("cached string aliases the caller's larger backing string")
		}
	}
	for _, field := range entry.headers[len(entry.headers):cap(entry.headers)] {
		if field != [2]string{} {
			t.Fatal("filtered header remains retained past slice length")
		}
	}
	cacheBoundsAssertTotals(t, pc)
}

func TestProxyCacheBoundsEmptyBodiesReachByteTarget(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{MaxTotalBytes: 8 << 10})
	defer pc.Stop()
	pc.UpdateConfig(ProxyCacheConfig{})
	for i := 0; i < 500; i++ {
		pc.Put("GET", "h.test", fmt.Sprintf("/%d?%s", i, strings.Repeat("k", 512)), 200, nil, "", nil)
	}
	pc.UpdateConfig(ProxyCacheConfig{MaxTotalBytes: 8 << 10})
	pc.Put("GET", "h.test", "/pressure", 200, nil, "", nil)
	cacheBoundsWaitIdle(t, pc)
	entries, total, _, _ := pc.Stats()
	if entries == 0 || total <= 0 || total > (8<<10)*90/100 {
		t.Fatalf("empty response pressure left %d entries/%d bytes, expected positive retained bytes within 90%% target", entries, total)
	}
	if pc.config.Load().MaxEntries != 0 {
		t.Fatal("explicit disabled entry cap changed")
	}
	cacheBoundsAssertTotals(t, pc)
}

func TestProxyCacheBoundsReplacementAtEntryCap(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{MaxEntries: 1})
	defer pc.Stop()
	pc.Put("GET", "h.test", "/same", 200, nil, "", []byte("old"))
	pc.Put("GET", "h.test", "/same", 200, nil, "", []byte("replacement"))
	cacheBoundsWaitIdle(t, pc)
	entry, hit := pc.GetFP("GET", "h.test", "/same", true)
	if !hit || string(entry.body) != "replacement" {
		t.Fatal("replacement at full entry cap was refused or evicted")
	}
	cacheBoundsAssertTotals(t, pc)
}

func TestProxyCacheBoundsConcurrentStop(t *testing.T) {
	for round := 0; round < 50; round++ {
		pc := NewProxyCache(ProxyCacheConfig{})
		start := make(chan struct{})
		panics := make(chan any, 64)
		var workers sync.WaitGroup
		for i := 0; i < cap(panics); i++ {
			workers.Go(func() {
				defer func() {
					if failure := recover(); failure != nil {
						panics <- failure
					}
				}()
				<-start
				pc.Stop()
			})
		}
		close(start)
		workers.Wait()
		if len(panics) > 0 {
			t.Fatalf("concurrent Stop panicked: %v", <-panics)
		}
		select {
		case <-pc.stopCh:
		default:
			t.Fatal("Stop did not close the stop channel")
		}
		pc.Put("GET", "h.test", "/after-stop", 200, nil, "", []byte("still usable"))
		if entry, hit := pc.GetFP("GET", "h.test", "/after-stop", true); !hit || string(entry.body) != "still usable" {
			t.Fatal("Stop changed the existing post-stop cache-operation contract")
		}
	}
}

func TestProxyCacheBoundsConfigDisableCompatibility(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{MaxEntries: 2, MaxTotalBytes: 1 << 20})
	defer pc.Stop()
	pc.UpdateConfig(ProxyCacheConfig{})
	for i := 0; i < 20; i++ {
		pc.Put("GET", "h.test", fmt.Sprintf("/%d", i), 200, nil, "", []byte("stored"))
	}
	if entries, _, _, _ := pc.Stats(); entries != 20 {
		t.Fatalf("disabled update caps retained %d entries, want 20", entries)
	}
	cfg := *pc.config.Load()
	cfg.MaxEntries, cfg.MaxTotalBytes = 1, 1
	pc.UpdateConfig(cfg)
	if entries, _, _, _ := pc.Stats(); entries != 20 || pc.evicting.Load() {
		t.Fatal("UpdateConfig immediately purged or scheduled eviction")
	}
	cfg.MaxEntries, cfg.MaxTotalBytes = 0, math.MaxInt64
	pc.UpdateConfig(cfg)
	pc.Put("GET", "h.test", "/later", 200, nil, "", nil)
	if _, hit := pc.GetFP("GET", "h.test", "/later", true); !hit {
		t.Fatal("updated caps prevented an eligible store")
	}
}

func TestProxyCacheBoundsStaleRemovalAndLifecycle(t *testing.T) {
	pc := NewProxyCache(DefaultProxyCacheConfig())
	defer pc.Stop()
	path := "/same"
	key := pc.buildKey("GET", "h.test", path)
	pc.Put("GET", "h.test", path, 200, [][2]string{{"x-a", "old"}}, "text/plain", []byte("old"))
	old, _ := pc.entries.Load(key)
	pc.Put("GET", "h.test", path, 200, [][2]string{{"x-large", strings.Repeat("v", 37)}}, "text/html", []byte("new longer body"))
	pc.removeEntry(key, old)
	current, hit := pc.entries.Load(key)
	if !hit || current == old || string(current.body) != "new longer body" {
		t.Fatal("stale removal discarded the replacement")
	}
	cacheBoundsAssertTotals(t, pc)
	pc.removeEntry(key, current)
	pc.removeEntry(key, current)
	cacheBoundsAssertTotals(t, pc)
	if entries, cost, _, _ := pc.Stats(); entries != 0 || cost != 0 {
		t.Fatal("double removal changed final zero accounting")
	}
	for _, mode := range []string{"expired", "max_hits", "purge", "purge_domain", "purge_all"} {
		t.Run(mode, func(t *testing.T) {
			ttl, maxHits := time.Minute, uint64(0)
			if mode == "expired" {
				ttl = -time.Second
			}
			if mode == "max_hits" {
				maxHits = 1
			}
			pc.PutManual("GET", "h.test", path, 200, [][2]string{{"x-one", "field"}}, "text/plain", []byte("payload"), ttl, maxHits, false, 0)
			switch mode {
			case "expired":
				if _, hit := pc.GetFP("GET", "h.test", path, true); hit {
					t.Fatal("expired entry served")
				}
			case "max_hits":
				if entry, hit := pc.GetFP("GET", "h.test", path, true); !hit || string(entry.body) != "payload" {
					t.Fatal("last allowed hit not served")
				}
			case "purge":
				if !pc.Purge("GET", "h.test", path) {
					t.Fatal("purge did not remove its entry")
				}
			case "purge_domain":
				if pc.PurgeDomain("h.test") != 1 {
					t.Fatal("domain purge did not remove exactly one entry")
				}
			case "purge_all":
				pc.PurgeAll()
			}
			cacheBoundsAssertTotals(t, pc)
			if entries, cost, _, _ := pc.Stats(); entries != 0 || cost != 0 {
				t.Fatal("retirement did not return accounting to zero")
			}
		})
	}
}

func TestProxyCacheBoundsConcurrentPublication(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{MaxEntries: 7})
	defer pc.Stop()
	var publishers sync.WaitGroup
	start := make(chan struct{})
	for worker := 0; worker < 16; worker++ {
		publishers.Go(func() {
			<-start
			for round := 0; round < 50; round++ {
				path := fmt.Sprintf("/worker-%d/%d", worker, round)
				pc.Put("GET", "h.test", path, 200, nil, "text/plain", []byte("content"))
				pc.Put("GET", "h.test", "/shared", 200, nil, "text/html", []byte(path))
				if round%5 == 0 {
					pc.Purge("GET", "h.test", "/shared")
				}
			}
		})
	}
	close(start)
	publishers.Wait()
	cacheBoundsWaitIdle(t, pc)
	cacheBoundsAssertTotals(t, pc)
	if entries, cost, _, _ := pc.Stats(); entries > 7 || cost < 0 {
		t.Fatalf("invalid retained state: %d entries/%d bytes", entries, cost)
	}
	pc.PurgeAll()
	pc.Put("GET", "h.test", "/fresh", 200, nil, "", []byte("fresh content"))
	if entry, hit := pc.GetFP("GET", "h.test", "/fresh", true); !hit || string(entry.body) != "fresh content" {
		t.Fatal("cache failed to admit a fresh response after reclamation")
	}
	cacheBoundsAssertTotals(t, pc)
}

func TestProxyCacheBoundsPublicationUsesCurrentCaps(t *testing.T) {
	for _, mode := range []string{"entries", "body", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			pc := NewProxyCache(DefaultProxyCacheConfig())
			defer pc.Stop()
			pc.Put("GET", "h.test", "/existing", 200, nil, "", []byte("old"))
			cfg := *pc.config.Load()
			switch mode {
			case "entries":
				cfg.MaxEntries = 1
			case "body":
				cfg.MaxEntrySize = 3
			case "disabled":
				cfg.MaxEntries, cfg.MaxTotalBytes = 0, 0
			}
			pc.UpdateConfig(cfg)
			entry := &cacheEntry{statusCode: 200, body: []byte("prepared response"), bodyLen: 17, expiresAt: math.MaxInt64}
			key := pc.buildKey("GET", "h.test", "/prepared")
			cost, ok := proxyCacheEntryCost(key, entry)
			if !ok {
				t.Fatal("valid prepared entry cost rejected")
			}
			entry.cost = cost
			pc.storeEntry(key, entry, pc.purgeGeneration())
			cacheBoundsWaitIdle(t, pc)
			_, hit := pc.GetFP("GET", "h.test", "/prepared", true)
			if hit != (mode == "disabled") {
				t.Fatalf("publication with updated %s cap: hit=%v", mode, hit)
			}
			cacheBoundsAssertTotals(t, pc)
		})
	}
}

func TestProxyCacheEvictionStaleCandidateKeepsReplacement(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{})
	defer pc.Stop()
	pc.Put("GET", "h.test", "/same", 200, nil, "", []byte("old"))
	candidates := pc.evictionCandidates()
	if len(candidates) != 1 {
		t.Fatal("candidate fixture not populated")
	}
	pc.Put("GET", "h.test", "/same", 200, nil, "", []byte("replacement"))
	cfg := *pc.config.Load()
	cfg.MaxTotalBytes = 1
	pc.UpdateConfig(cfg)
	pc.evictCandidates(candidates)
	entry, hit := pc.GetFP("GET", "h.test", "/same", true)
	if !hit || string(entry.body) != "replacement" {
		t.Fatal("an old eviction candidate removed a new same-key response")
	}
	cacheBoundsAssertTotals(t, pc)
	pc.evictCandidates(pc.evictionCandidates())
	cacheBoundsAssertTotals(t, pc)
	if count, cost, _, _ := pc.Stats(); count != 0 || cost != 0 {
		t.Fatal("current candidate failed to reclaim its response")
	}
}

func TestProxyCacheEvictionTargetsAndDisabledCaps(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{})
	defer pc.Stop()
	for _, tc := range []struct {
		limit, total int64
		above        bool
	}{
		{0, 100, false}, {1, 1, true}, {11, 9, false}, {11, 10, true},
		{math.MaxInt64, 8301034833169298226, false}, {math.MaxInt64, 8301034833169298227, true},
	} {
		pc.UpdateConfig(ProxyCacheConfig{MaxTotalBytes: tc.limit})
		pc.mu.Lock()
		pc.totalBytes.Store(tc.total)
		above := pc.aboveEvictionTargetLocked()
		pc.totalBytes.Store(0)
		pc.mu.Unlock()
		if above != tc.above {
			t.Errorf("byte limit %d at %d: above=%v, want %v", tc.limit, tc.total, above, tc.above)
		}
	}
	for _, tc := range []struct {
		limit, count int64
		above        bool
	}{{0, 100, false}, {1, 0, false}, {1, 1, true}, {11, 10, false}, {11, 11, true}} {
		pc.UpdateConfig(ProxyCacheConfig{MaxEntries: tc.limit})
		pc.mu.Lock()
		pc.totalEntries.Store(tc.count)
		above := pc.aboveEvictionTargetLocked()
		pc.totalEntries.Store(0)
		pc.mu.Unlock()
		if above != tc.above {
			t.Errorf("entry limit %d at %d: above=%v, want %v", tc.limit, tc.count, above, tc.above)
		}
	}
}

func TestProxyCacheEvictionOwnershipReschedulesAfterStop(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{MaxTotalBytes: 4 << 10, MaxEntries: 7})
	defer pc.Stop()
	for cycle := 0; cycle < 4; cycle++ {
		var publishers sync.WaitGroup
		for worker := 0; worker < 8; worker++ {
			publishers.Go(func() {
				for i := 0; i < 100; i++ {
					pc.Put("GET", "h.test", fmt.Sprintf("/%d/%d/%d", cycle, worker, i), 200, nil, "", bytes.Repeat([]byte{'a'}, 512))
				}
			})
		}
		publishers.Wait()
		cacheBoundsWaitIdle(t, pc)
		cacheBoundsAssertTotals(t, pc)
		if count, cost, _, _ := pc.Stats(); count > 7 || cost > 4<<10 {
			t.Fatalf("cycle %d retained %d entries/%d bytes", cycle, count, cost)
		}
		pc.PurgeAll()
		pc.Stop()
	}
}

func TestProxyCacheBoundsInflatedCostAndClearedEncoding(t *testing.T) {
	pc := NewProxyCache(DefaultProxyCacheConfig())
	defer pc.Stop()
	raw := bytes.Repeat([]byte("expanded upstream response\n"), 150)
	encoded := proxyFixEncode(t, "gzip", raw)
	pc.Put("GET", "h.test", "/inflated", 200, [][2]string{{"x-kept", "value"}, {"content-encoding", "gzip"}}, "text/plain", encoded)
	entry, hit := pc.GetFP("GET", "h.test", "/inflated", true)
	if !hit || !bytes.Equal(entry.body, raw) || len(entry.gzipBody) == 0 {
		t.Fatal("fixture did not inflate and retain its gzip variant")
	}
	for _, field := range entry.headers[len(entry.headers):cap(entry.headers)] {
		if field != [2]string{} {
			t.Fatal("removed encoding still retains strings past header length")
		}
	}
	cacheBoundsAssertTotals(t, pc)
}

func TestProxyCacheBoundsStoreCostOverflowRejected(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{})
	defer pc.Stop()
	pc.UpdateConfig(ProxyCacheConfig{})
	pc.Put("GET", "h.test", "/existing", 200, nil, "", []byte("preserved"))
	entry := &cacheEntry{statusCode: 200, body: []byte("new"), bodyLen: 3, expiresAt: math.MaxInt64}
	key := pc.buildKey("GET", "h.test", "/overflow")
	cost, ok := proxyCacheEntryCost(key, entry)
	if !ok {
		t.Fatal("fixture cost rejected")
	}
	entry.cost = cost
	_, actual, _, _ := pc.Stats()
	before := int64(math.MaxInt64) - cost + 1
	pc.totalBytes.Store(before)
	defer pc.totalBytes.Store(actual)
	pc.storeEntry(key, entry, pc.purgeGeneration())
	if _, stored := pc.entries.Load(key); stored {
		t.Fatal("overflowing aggregate cost was published")
	}
	if entries, total, _, _ := pc.Stats(); entries != 1 || total != before {
		t.Fatalf("overflow rejection changed counters to %d entries/%d bytes", entries, total)
	}
	if old, hit := pc.GetFP("GET", "h.test", "/existing", true); !hit || string(old.body) != "preserved" {
		t.Fatal("overflow rejection removed the retained response")
	}
}
