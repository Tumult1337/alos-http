//go:build linux && amd64

package core

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

const proxyCacheFreshTTL = time.Hour

func proxyCacheFreshCache(t *testing.T, cfg ProxyCacheConfig) *ProxyCache {
	t.Helper()
	if cfg.DefaultMaxAge == 0 {
		cfg.DefaultMaxAge = proxyCacheFreshTTL
	}
	pc := NewProxyCache(cfg)
	t.Cleanup(pc.Stop)
	return pc
}

func proxyCacheFreshPut(pc *ProxyCache, path string, headers ...[2]string) {
	pc.put("GET", "h", path, 200, headers, "text/plain", []byte("body"), cachePutOptions{generation: pc.purgeGeneration()})
}

func proxyCacheFreshEntry(pc *ProxyCache, path string) (*cacheEntry, bool) {
	return pc.entries.Load(pc.buildKey("GET", "h", path))
}

func proxyCacheHTTPDate(t time.Time) string { return t.UTC().Format(http.TimeFormat) }

func TestProxyCacheHonorsResponseFreshness(t *testing.T) {
	now := time.Unix(0, CoarseNanotime())
	date := proxyCacheHTTPDate(now)
	cc := func(v string) [2]string { return [2]string{"Cache-Control", v} }
	for _, tc := range []struct {
		name    string
		headers [][2]string
		want    time.Duration
	}{
		{"no freshness information uses the configured ttl", nil, proxyCacheFreshTTL},
		{"max-age=0", [][2]string{cc("max-age=0")}, 0},
		{"max-age=0 with must-revalidate", [][2]string{cc("max-age=0, must-revalidate")}, 0},
		{"s-maxage=0 overrides max-age", [][2]string{cc("max-age=600, s-maxage=0")}, 0},
		{"max-age below the configured ttl", [][2]string{cc("max-age=60")}, 60 * time.Second},
		{"s-maxage wins over max-age", [][2]string{cc("max-age=600, s-maxage=30")}, 30 * time.Second},
		{"max-age above the configured ttl is capped", [][2]string{cc("max-age=999999")}, proxyCacheFreshTTL},
		{"delta-seconds overflow saturates and is capped", [][2]string{cc("max-age=99999999999999999999999")}, proxyCacheFreshTTL},
		{"age is subtracted", [][2]string{cc("max-age=100"), {"Age", "40"}}, 60 * time.Second},
		{"age list uses its first member", [][2]string{cc("max-age=100"), {"Age", "40, 90"}}, 60 * time.Second},
		{"invalid age is ignored", [][2]string{cc("max-age=100"), {"Age", "-5"}}, 100 * time.Second},
		{"age past the lifetime", [][2]string{cc("max-age=100"), {"Age", "200"}}, 0},
		{"directives over two lines", [][2]string{cc("public"), cc("max-age=45")}, 45 * time.Second},
		{"first max-age wins", [][2]string{cc("max-age=45, max-age=900")}, 45 * time.Second},
		{"uppercase directive", [][2]string{cc("MAX-AGE=45")}, 45 * time.Second},
		{"quoted max-age is invalid", [][2]string{cc(`max-age="45"`)}, 0},
		{"non-numeric max-age is invalid", [][2]string{cc("max-age=abc")}, 0},
		{"empty max-age is invalid", [][2]string{cc("max-age=")}, 0},
		{"expires minus date minus apparent age", [][2]string{{"Date", proxyCacheHTTPDate(now.Add(-30 * time.Second))}, {"Expires", proxyCacheHTTPDate(now.Add(90 * time.Second))}}, 90 * time.Second},
		{"apparent age past max-age", [][2]string{{"Date", proxyCacheHTTPDate(now.Add(-2 * time.Hour))}, cc("max-age=3600")}, 0},
		{"apparent age wins over a smaller age", [][2]string{{"Date", proxyCacheHTTPDate(now.Add(-100 * time.Second))}, cc("max-age=130"), {"Age", "10"}}, 30 * time.Second},
		{"ancient date and expires", [][2]string{{"Date", "Mon, 01 Jan 1700 00:00:00 GMT"}, {"Expires", "Mon, 01 Jan 1900 00:00:00 GMT"}}, 0},
		{"expires without date uses the receive time", [][2]string{{"Expires", proxyCacheHTTPDate(now.Add(120 * time.Second))}}, 120 * time.Second},
		{"expires in the past", [][2]string{{"Date", date}, {"Expires", proxyCacheHTTPDate(now.Add(-time.Second))}}, 0},
		{"invalid expires is in the past", [][2]string{{"Expires", "0"}}, 0},
		{"expires with a non-GMT zone is invalid", [][2]string{{"Date", date}, {"Expires", "Monday, 02-Jan-40 15:04:05 PST"}}, 0},
		{"max-age wins over expires", [][2]string{{"Date", date}, {"Expires", proxyCacheHTTPDate(now.Add(-time.Hour))}, cc("max-age=50")}, 50 * time.Second},
		{"expires minus age", [][2]string{{"Date", date}, {"Expires", proxyCacheHTTPDate(now.Add(120 * time.Second))}, {"Age", "20"}}, 100 * time.Second},
	} {
		pc := proxyCacheFreshCache(t, ProxyCacheConfig{})
		proxyCacheFreshPut(pc, "/p", tc.headers...)
		entry, stored := proxyCacheFreshEntry(pc, "/p")
		if tc.want == 0 {
			if stored {
				t.Errorf("%s: stored with ttl %v, want not stored", tc.name, time.Duration(entry.expiresAt-entry.createdAt))
			}
			continue
		}
		if !stored {
			t.Errorf("%s: not stored, want ttl %v", tc.name, tc.want)
			continue
		}
		if got := time.Duration(entry.expiresAt - entry.createdAt); got < tc.want-2*time.Second || got > tc.want {
			t.Errorf("%s: ttl %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestProxyCacheHitCarriesAge(t *testing.T) {
	pc := proxyCacheFreshCache(t, ProxyCacheConfig{})
	proxyCacheFreshPut(pc, "/p", [2]string{"Cache-Control", "max-age=600"}, [2]string{"Age", "40"})
	entry, ok := pc.GetFP("GET", "h", "/p", true)
	if !ok {
		t.Fatalf("entry not cached")
	}
	entry.createdAt -= int64(5 * time.Second)
	resp := newTestResp()
	pc.ServeCached(entry, newTestReq(), resp)
	ages := respHeaderValues(resp, "age")
	if len(ages) != 1 {
		t.Fatalf("hit carried Age values %q, want exactly one", ages)
	}
	if age, err := strconv.Atoi(ages[0]); err != nil || age < 45 || age > 46 {
		t.Fatalf("Age %q, want 45 (40 at store plus 5 resident)", ages[0])
	}
}

func TestProxyCacheHitWithoutUpstreamAgeCountsResidentTime(t *testing.T) {
	pc := proxyCacheFreshCache(t, ProxyCacheConfig{})
	proxyCacheFreshPut(pc, "/p")
	entry, ok := pc.GetFP("GET", "h", "/p", true)
	if !ok {
		t.Fatalf("entry not cached")
	}
	entry.createdAt -= int64(7 * time.Second)
	resp := newTestResp()
	pc.ServeCached(entry, newTestReq(), resp)
	if got := hdr(resp, "age"); got != "7" && got != "8" {
		t.Fatalf("Age %q, want 7", got)
	}
}

func TestProxyCacheRevalidationDirectivesForbidStaleServing(t *testing.T) {
	for _, tc := range []struct {
		cc        string
		wantStale bool
	}{
		{"max-age=60", true},
		{"max-age=60, must-revalidate", false},
		{"max-age=60, proxy-revalidate", false},
		{"s-maxage=60", false},
	} {
		pc := proxyCacheFreshCache(t, ProxyCacheConfig{StaleWhileRev: time.Hour})
		proxyCacheFreshPut(pc, "/p", [2]string{"Cache-Control", tc.cc})
		entry, ok := proxyCacheFreshEntry(pc, "/p")
		if !ok {
			t.Fatalf("%s: not stored", tc.cc)
		}
		entry.expiresAt = CoarseNanotime() - int64(time.Second)
		if _, hit := pc.GetFP("GET", "h", "/p", true); hit != tc.wantStale {
			t.Errorf("%s: stale hit = %v, want %v", tc.cc, hit, tc.wantStale)
		}
	}
}
