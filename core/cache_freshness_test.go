//go:build linux && amd64

package core

import (
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
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
		dated   bool
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
		{name: "expires-from-date", headers: [][2]string{{"Date", date}, {"Expires", now.Add(30 * time.Second).UTC().Format(http.TimeFormat)}}, ttl: 30 * time.Second, stored: true, dated: true},
		{name: "expires-past", headers: [][2]string{{"Date", date}, {"Expires", now.Add(-time.Second).UTC().Format(http.TimeFormat)}}},
		{name: "expires-invalid", headers: [][2]string{{"Expires", "0"}}},
		{name: "expires-from-past-date", headers: [][2]string{{"Date", now.Add(-100 * time.Second).UTC().Format(http.TimeFormat)}, {"Expires", now.Add(30 * time.Second).UTC().Format(http.TimeFormat)}}, ttl: 30 * time.Second, stored: true, dated: true},
		{name: "date-past-no-age", headers: [][2]string{cc("max-age=3600"), {"Date", now.Add(-2 * time.Hour).UTC().Format(http.TimeFormat)}}},
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
			got := time.Duration(ent.expiresAtNs - ent.storedAtNs)
			if tc.dated && got <= tc.ttl && got > tc.ttl-2*time.Second {
				return
			}
			if got != tc.ttl {
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

func TestCache_ApparentAgeOverridesSmallerAgeHeader(t *testing.T) {
	now := time.Unix(0, turbo.UnixNano())
	date := now.Add(-100 * time.Second).UTC().Format(http.TimeFormat)
	rc := NewResponseCache(CacheConfig{TTL: time.Hour})
	defer rc.Stop()
	h := cacheFreshHandler([2]string{"Cache-Control", "max-age=130"}, [2]string{"Date", date}, [2]string{"Age", "10"})
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	ent, ok := cacheFreshStored(t, rc, "/a")
	if !ok {
		t.Fatal("response with remaining freshness not stored")
	}
	if ttl := time.Duration(ent.expiresAtNs - ent.storedAtNs); ttl > 30*time.Second || ttl <= 28*time.Second {
		t.Fatalf("freshness %v, want max-age 130s minus an apparent age of about 100s", ttl)
	}
	hit := cResp()
	rc.handle(h, cReq("GET", "x", "/a", ""), hit)
	ages := respHeaderValues(hit, "Age")
	if len(ages) != 1 {
		t.Fatalf("hit Age %v", ages)
	}
	if age, err := strconv.Atoi(ages[0]); err != nil || age < 100 || age > 102 {
		t.Fatalf("hit Age %v, want the apparent age of about 100", ages)
	}
}

func TestCache_SweepCompactsExpiredOrderRefs(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, MaxEntries: 100})
	defer rc.Stop()
	for i := range 100 {
		rc.handle(cacheFreshHandler(), cReq("GET", "x", "/e", strconv.Itoa(i)), cResp())
	}
	past := turbo.UnixNano() - 1
	rc.store.Range(func(key string, ent *cachedResponse) bool {
		ent.expiresAtNs = past
		return true
	})
	rc.sweep()
	rc.orderMu.Lock()
	queued := len(rc.order)
	rc.orderMu.Unlock()
	if queued != 0 || rc.Len() != 0 || rc.entries.Load() != 0 {
		t.Fatalf("after the sweep: %d refs, %d stored, %d counted", queued, rc.Len(), rc.entries.Load())
	}
}

func TestCache_ConcurrentStoresNeverExceedMaxEntries(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, MaxEntries: 10, Gzip: true, GzipMinBytes: 10})
	defer rc.Stop()
	h := func(req *Request, resp *Response) { resp.Status(200).String(bigBody(300)) }
	var over atomic.Int64
	var writers sync.WaitGroup
	stop := make(chan struct{})
	watcher := make(chan struct{})
	go func() {
		defer close(watcher)
		for {
			select {
			case <-stop:
				return
			default:
			}
			rc.orderMu.Lock()
			if n := int64(rc.Len()); n > 10 {
				over.Store(n)
			}
			rc.orderMu.Unlock()
			rc.sweep()
		}
	}()
	for w := range 16 {
		writers.Go(func() {
			for i := range 500 {
				rc.handle(h, cReq("GET", "x", "/c", strconv.Itoa(w*1000+i%40), gzHdr()), cResp())
			}
		})
	}
	writers.Wait()
	close(stop)
	<-watcher
	if n := over.Load(); n != 0 {
		t.Fatalf("store held %d entries, MaxEntries 10", n)
	}
	if got, counted := rc.Len(), rc.entries.Load(); int64(got) != counted || got > 10 {
		t.Fatalf("store holds %d entries, counter says %d", got, counted)
	}
}

const cacheHostileYear1 = "Mon, 01 Jan 0001 00:00:00 GMT"

func TestCache_HostileFreshnessIsNotStored(t *testing.T) {
	now := time.Unix(0, turbo.UnixNano())
	date := now.UTC().Format(http.TimeFormat)
	cases := []struct {
		name    string
		headers [][2]string
	}{
		{name: "expires-year-1-with-age", headers: [][2]string{{"Date", date}, {"Expires", cacheHostileYear1}, {"Age", "10"}}},
		{name: "expires-invalid-with-age", headers: [][2]string{{"Date", date}, {"Expires", "garbage"}, {"Age", "10"}}},
		{name: "expires-invalid-no-date", headers: [][2]string{{"Expires", "garbage"}}},
		{name: "date-year-1", headers: [][2]string{{"Cache-Control", "max-age=3600"}, {"Date", cacheHostileYear1}}},
		{name: "age-overflow", headers: [][2]string{{"Cache-Control", "max-age=3600"}, {"Age", "99999999999999999999"}}},
		{name: "date-1700-expires-1900", headers: [][2]string{{"Date", "Fri, 01 Jan 1700 00:00:00 GMT"}, {"Expires", "Mon, 01 Jan 1900 00:00:00 GMT"}}},
		{name: "date-0001-expires-2000", headers: [][2]string{{"Date", cacheHostileYear1}, {"Expires", "Sat, 01 Jan 2000 00:00:00 GMT"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := NewResponseCache(CacheConfig{TTL: time.Minute})
			defer rc.Stop()
			rc.handle(cacheFreshHandler(tc.headers...), cReq("GET", "x", "/h", ""), cResp())
			if _, ok := cacheFreshStored(t, rc, "/h"); ok {
				t.Fatal("hostile freshness headers produced a stored response")
			}
		})
	}
}

func TestCacheFreshnessAgeIsClamped(t *testing.T) {
	now := time.Unix(0, turbo.UnixNano())
	maxAge := time.Duration(cacheDeltaSecondsMax) * time.Second
	cases := []struct {
		name    string
		headers [][2]string
		want    time.Duration
	}{
		{name: "date-year-1", headers: [][2]string{{"Date", cacheHostileYear1}}, want: maxAge},
		{name: "date-year-9999", headers: [][2]string{{"Date", "Fri, 31 Dec 9999 23:59:59 GMT"}}, want: 0},
		{name: "age-overflow", headers: [][2]string{{"Age", "99999999999999999999"}}, want: maxAge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseCacheFreshness(tc.headers, now).age; got != tc.want {
				t.Fatalf("age %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCache_SetAgeSaturates(t *testing.T) {
	now := turbo.UnixNano()
	cases := []struct {
		name string
		ent  cachedResponse
		want string
	}{
		{name: "max-initial-age-plus-resident", ent: cachedResponse{initialAge: time.Duration(cacheDeltaSecondsMax) * time.Second, storedAtNs: now - int64(time.Hour)}, want: "2147483648"},
		{name: "negative-initial-age", ent: cachedResponse{initialAge: -5 * time.Second, storedAtNs: now}, want: "0"},
		{name: "stored-in-future", ent: cachedResponse{storedAtNs: now + int64(time.Hour)}, want: "0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := cResp()
			tc.ent.setAge(resp, now)
			if ages := respHeaderValues(resp, "Age"); len(ages) != 1 || ages[0] != tc.want {
				t.Fatalf("Age %v, want [%s]", ages, tc.want)
			}
		})
	}
}
