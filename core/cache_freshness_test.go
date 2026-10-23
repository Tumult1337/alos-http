//go:build linux && amd64

package core

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	cacheEvictSmall  = 500
	cacheEvictLarge  = 50000
	cacheEvictMisses = 2000
	cacheEvictTrials = 3
	cacheEvictRatio  = 10
)

func cacheFreshHandler(headers ...[2]string) HandlerFunc {
	return func(req *Request, resp *Response) {
		for _, h := range headers {
			resp.SetHeader(h[0], h[1])
		}
		resp.Status(200).String("body")
	}
}

func cacheFreshStored(t *testing.T, rc *ResponseCache, path string) (*cachedResponse, bool) {
	t.Helper()
	return rc.store.Load(rc.key(cReq("GET", "x", path, "")))
}

func TestCache_HonorsResponseFreshness(t *testing.T) {
	now := time.Unix(0, turbo.UnixNano())
	date := now.UTC().Format(http.TimeFormat)
	cc := func(v string) [2]string { return [2]string{"Cache-Control", v} }
	cases := []struct {
		name    string
		headers [][2]string
		ttl     time.Duration
		stored  bool
	}{
		{name: "no-explicit-expiry", ttl: time.Minute, stored: true},
		{name: "max-age-below-ttl", headers: [][2]string{cc("max-age=5")}, ttl: 5 * time.Second, stored: true},
		{name: "max-age-above-ttl", headers: [][2]string{cc("max-age=3600")}, ttl: time.Minute, stored: true},
		{name: "s-maxage-wins", headers: [][2]string{cc("max-age=100, s-maxage=3")}, ttl: 3 * time.Second, stored: true},
		{name: "first-max-age-wins", headers: [][2]string{cc("max-age=4"), cc("max-age=50")}, ttl: 4 * time.Second, stored: true},
		{name: "age-subtracted", headers: [][2]string{cc("max-age=60"), {"Age", "50"}}, ttl: 10 * time.Second, stored: true},
		{name: "age-exhausts-lifetime", headers: [][2]string{cc("max-age=60"), {"Age", "70"}}},
		{name: "max-age-zero", headers: [][2]string{cc("max-age=0")}},
		{name: "max-age-invalid", headers: [][2]string{cc("max-age=soon")}},
		{name: "expires-from-date", headers: [][2]string{{"Date", date}, {"Expires", now.Add(30 * time.Second).UTC().Format(http.TimeFormat)}}, ttl: 30 * time.Second, stored: true},
		{name: "expires-past", headers: [][2]string{{"Date", date}, {"Expires", now.Add(-time.Second).UTC().Format(http.TimeFormat)}}},
		{name: "expires-invalid", headers: [][2]string{{"Expires", "0"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := NewResponseCache(CacheConfig{TTL: time.Minute})
			defer rc.Stop()
			rc.handle(cacheFreshHandler(tc.headers...), cReq("GET", "x", "/f", ""), cResp())
			ent, ok := cacheFreshStored(t, rc, "/f")
			if ok != tc.stored {
				t.Fatalf("stored %v, want %v", ok, tc.stored)
			}
			if !ok {
				return
			}
			if got := time.Duration(ent.expiresAtNs - ent.storedAtNs); got != tc.ttl {
				t.Fatalf("freshness %v, want %v", got, tc.ttl)
			}
		})
	}
}

func TestCache_HitCarriesAge(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	h := cacheFreshHandler([2]string{"Cache-Control", "max-age=600"}, [2]string{"Age", "50"})
	miss := cResp()
	rc.handle(h, cReq("GET", "x", "/a", ""), miss)
	if age, _ := respHeader(miss, "Age"); age != "50" {
		t.Fatalf("miss Age %q, want the handler's 50", age)
	}
	ent, ok := cacheFreshStored(t, rc, "/a")
	if !ok {
		t.Fatal("response not stored")
	}
	if _, stored := respHeaderIn(ent.headers, "Age"); stored {
		t.Fatal("stored headers keep the handler's Age")
	}
	ent.storedAtNs -= int64(7 * time.Second)
	hit := cResp()
	rc.handle(h, cReq("GET", "x", "/a", ""), hit)
	if ages := respHeaderValues(hit, "Age"); len(ages) != 1 || ages[0] != "57" {
		t.Fatalf("hit Age %v, want [57]", ages)
	}
	plain := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer plain.Stop()
	plain.handle(cacheFreshHandler(), cReq("GET", "x", "/b", ""), cResp())
	hit = cResp()
	plain.handle(cacheFreshHandler(), cReq("GET", "x", "/b", ""), hit)
	if ages := respHeaderValues(hit, "Age"); len(ages) != 1 || ages[0] != "0" {
		t.Fatalf("hit Age %v, want [0]", ages)
	}
}

func respHeaderIn(headers [][2]string, name string) (string, bool) {
	for i := range headers {
		if EqualFoldASCII(headers[i][0], name) {
			return headers[i][1], true
		}
	}
	return "", false
}

func TestCache_FullCacheEvictsOldestForNewEntry(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, MaxEntries: 3})
	defer rc.Stop()
	for _, path := range []string{"/a", "/b", "/c", "/d"} {
		rc.handle(cacheFreshHandler(), cReq("GET", "x", path, ""), cResp())
	}
	if rc.Len() != 3 {
		t.Fatalf("Len %d, want 3", rc.Len())
	}
	if _, ok := cacheFreshStored(t, rc, "/a"); ok {
		t.Fatal("oldest entry /a survived a full-cache insert")
	}
	for _, path := range []string{"/b", "/c", "/d"} {
		if _, ok := cacheFreshStored(t, rc, path); !ok {
			t.Fatalf("entry %s missing", path)
		}
	}
	rc.handle(cacheFreshHandler(), cReq("GET", "x", "/b", ""), cResp())
	rc.handle(cacheFreshHandler(), cReq("GET", "x", "/e", ""), cResp())
	if _, ok := cacheFreshStored(t, rc, "/b"); ok {
		t.Fatal("a hit must not refresh insertion order: /b should be the next victim")
	}
	if _, ok := cacheFreshStored(t, rc, "/e"); !ok || rc.Len() != 3 {
		t.Fatalf("after /e: Len %d", rc.Len())
	}
}

func cacheFullMissCost(n int) time.Duration {
	rc := NewResponseCache(CacheConfig{TTL: time.Hour, MaxEntries: n})
	defer rc.Stop()
	h := cacheFreshHandler()
	for i := range n {
		rc.handle(h, cReq("GET", "x", "/fill", strconv.Itoa(i)), cResp())
	}
	best := time.Duration(1 << 62)
	for trial := range cacheEvictTrials {
		start := time.Now()
		for i := range cacheEvictMisses {
			rc.handle(h, cReq("GET", "x", "/miss", strconv.Itoa(trial*cacheEvictMisses+i)), cResp())
		}
		best = min(best, time.Since(start))
	}
	return best
}

func TestCache_FullCacheMissCostDoesNotScaleWithSize(t *testing.T) {
	small := cacheFullMissCost(cacheEvictSmall)
	large := cacheFullMissCost(cacheEvictLarge)
	if large > small*cacheEvictRatio {
		t.Fatalf("%d misses on a full cache: %v at %d entries, %v at %d entries (over %dx)",
			cacheEvictMisses, small, cacheEvictSmall, large, cacheEvictLarge, cacheEvictRatio)
	}
}
func TestCache_OrderQueueStaysBounded(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, MaxEntries: 4})
	defer rc.Stop()
	for range 1000 {
		rc.handle(cacheFreshHandler(), cReq("GET", "x", "/k", ""), cResp())
		ent, ok := cacheFreshStored(t, rc, "/k")
		if !ok {
			t.Fatal("entry not stored")
		}
		rc.evictEntry(rc.key(cReq("GET", "x", "/k", "")), ent)
	}
	rc.orderMu.Lock()
	queued := len(rc.order)
	rc.orderMu.Unlock()
	if limit := 2*rc.cfg.MaxEntries + 1; queued > limit {
		t.Fatalf("order queue holds %d refs after evictions outside the queue, want at most %d", queued, limit)
	}
	rc.handle(cacheFreshHandler(), cReq("GET", "x", "/p", ""), cResp())
	rc.Purge()
	rc.orderMu.Lock()
	queued = len(rc.order)
	rc.orderMu.Unlock()
	if queued != 0 || rc.entries.Load() != 0 || rc.Len() != 0 {
		t.Fatalf("after Purge: %d refs, %d counted, %d stored", queued, rc.entries.Load(), rc.Len())
	}
}

func TestCache_ReplacedEntryCountsOnce(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, MaxEntries: 2})
	defer rc.Stop()
	now := turbo.UnixNano()
	entry := func() *cachedResponse {
		return &cachedResponse{status: 200, expiresAtNs: now + int64(time.Hour), storedAtNs: now}
	}
	rc.storeBounded("a", entry())
	rc.storeBounded("b", entry())
	for range 5 {
		rc.storeBounded("a", entry())
	}
	if _, ok := rc.store.Load("b"); !ok || rc.entries.Load() != 2 {
		t.Fatalf("replacing a: b present %v, counted %d, want true and 2", ok, rc.entries.Load())
	}
}
