//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	proxyFix2CacheHost      = "cache.test"
	proxyFix2SmallPageBytes = 4 << 10
	proxyFix2BombBytes      = 2 << 20
)

var proxyFix2CacheEncodings = []string{"gzip", "deflate", "br"}

func proxyFix2BusyTransformCache(t *testing.T) *ProxyCache {
	t.Helper()
	pc := NewProxyCache(DefaultProxyCacheConfig())
	t.Cleanup(pc.Stop)
	pc.transforms.Store(int32(max(1, runtime.GOMAXPROCS(0)/cacheTransformCPUShare)))
	return pc
}

func proxyFix2PutEncoded(pc *ProxyCache, path, encoding string, encoded []byte) {
	headers := [][2]string{{"Content-Encoding", encoding}, {"Vary", "Accept-Encoding"}}
	pc.put("GET", proxyFix2CacheHost, path, http.StatusOK, headers, "text/html", encoded, cachePutOptions{generation: pc.purgeGeneration(), offload: true})
}

func TestProxyFix2CacheSmallEncodedStoreSurvivesBusyTransformSlots(t *testing.T) {
	raw := []byte(strings.Repeat("<p>small cached page</p>", proxyFix2SmallPageBytes/24))
	for _, encoding := range proxyFix2CacheEncodings {
		t.Run(encoding, func(t *testing.T) {
			pc := proxyFix2BusyTransformCache(t)
			proxyFix2PutEncoded(pc, "/small", encoding, proxyFixEncode(t, encoding, raw))
			entry, hit := pc.GetFP("GET", proxyFix2CacheHost, "/small", true)
			if !hit {
				t.Fatalf("a %d-byte %s page was not cached while the transform slots were busy", len(raw), encoding)
			}
			if !bytes.Equal(entry.body, raw) {
				t.Fatalf("cached body is %d bytes, want the %d inflated bytes", len(entry.body), len(raw))
			}
			if enc, _ := detectBackendEncoding(entry.headers); enc {
				t.Fatalf("cached headers still carry Content-Encoding: %v", entry.headers)
			}
		})
	}
}

func TestProxyFix2CacheInlineInflateStaysBounded(t *testing.T) {
	bomb := make([]byte, proxyFix2BombBytes)
	for _, encoding := range proxyFix2CacheEncodings {
		t.Run(encoding, func(t *testing.T) {
			encoded := proxyFixEncode(t, encoding, bomb)
			if len(encoded) > cacheInlineTransformLimit {
				t.Fatalf("test bomb is %d encoded bytes, want <= %d", len(encoded), cacheInlineTransformLimit)
			}
			pc := proxyFix2BusyTransformCache(t)
			proxyFix2PutEncoded(pc, "/bomb", encoding, encoded)
			if _, hit := pc.GetFP("GET", proxyFix2CacheHost, "/bomb", true); hit {
				t.Fatalf("a %s body inflating to %d bytes was inflated on the caller with no transform slot free", encoding, len(bomb))
			}
		})
	}
}

func BenchmarkProxyFix2CachePutSmallGzipPage(b *testing.B) {
	pc := NewProxyCache(DefaultProxyCacheConfig())
	defer pc.Stop()
	encoded := proxyFixEncode(b, "gzip", []byte(strings.Repeat("<p>small cached page</p>", proxyFix2SmallPageBytes/24)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		proxyFix2PutEncoded(pc, "/small", "gzip", encoded)
	}
}

func BenchmarkProxyFix2CachePutSmallPlainPage(b *testing.B) {
	pc := NewProxyCache(DefaultProxyCacheConfig())
	defer pc.Stop()
	raw := []byte(strings.Repeat("<p>small cached page</p>", proxyFix2SmallPageBytes/24))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pc.put("GET", proxyFix2CacheHost, "/small", http.StatusOK, nil, "text/html", raw, cachePutOptions{generation: pc.purgeGeneration(), offload: true})
	}
}

func TestProxyFix2CacheUnrelatedPurgeKeepsInFlightFill(t *testing.T) {
	o := newProxyFixHeldOrigin(t, false)
	srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.SetProxyCache(DefaultProxyCacheConfig())
	})
	c := proxyFixDial(t, addr)
	defer c.Close()
	if _, err := io.WriteString(c, proxyFixGet(proxyFixDomain, "/doc")); err != nil {
		t.Fatalf("write: %v", err)
	}
	proxyFixEventually(t, "the cache miss reached the origin", func() bool { return o.received.Load() == 1 })
	srv.PurgeProxyCache("GET", proxyFixDomain, proxyFix2PathInOtherStripe(t, srv.activeProxyCache(), proxyFixDomain, "/doc"))
	o.releaseOnce()
	if resp, body := proxyFixReadResponse(t, bufio.NewReader(c)); resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("in-flight response: %d %q", resp.StatusCode, body)
	}
	stored := func() bool { entries, _, _, _ := srv.ProxyCacheStats(); return entries == 1 }
	if !proxyFixWaitFor(stored) {
		t.Fatalf("purging a path in another purge stripe discarded the in-flight fill of /doc")
	}
}

func TestProxyFix2CachePurgeScopesInFlightFills(t *testing.T) {
	body := []byte("fill")
	for _, tc := range []struct {
		name      string
		purge     func(pc *ProxyCache)
		wantStore bool
	}{
		{"other_url", func(pc *ProxyCache) {
			pc.Purge("GET", proxyFix2CacheHost, proxyFix2PathInOtherStripe(t, pc, proxyFix2CacheHost, "/fill"))
		}, true},
		{"same_url", func(pc *ProxyCache) { pc.Purge("GET", proxyFix2CacheHost, "/fill") }, false},
		{"same_domain", func(pc *ProxyCache) { pc.PurgeDomain(proxyFix2CacheHost) }, false},
		{"all", func(pc *ProxyCache) { pc.PurgeAll() }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := NewProxyCache(DefaultProxyCacheConfig())
			defer pc.Stop()
			gen := pc.purgeGeneration()
			tc.purge(pc)
			pc.put("GET", proxyFix2CacheHost, "/fill", http.StatusOK, nil, "text/plain", body, cachePutOptions{generation: gen})
			if _, hit := pc.GetFP("GET", proxyFix2CacheHost, "/fill", true); hit != tc.wantStore {
				t.Fatalf("fill begun before purge %s: stored=%v, want %v", tc.name, hit, tc.wantStore)
			}
			fresh := pc.purgeGeneration()
			pc.put("GET", proxyFix2CacheHost, "/later", http.StatusOK, nil, "text/plain", body, cachePutOptions{generation: fresh})
			if _, hit := pc.GetFP("GET", proxyFix2CacheHost, "/later", true); !hit {
				t.Fatalf("fill begun after purge %s was not stored", tc.name)
			}
		})
	}
}

func proxyFix2PathInOtherStripe(t *testing.T, pc *ProxyCache, host, path string) string {
	t.Helper()
	taken := pc.keyPurgeStripe(pc.buildKey("GET", host, path))
	for i := 0; i < cachePurgeStripes*4; i++ {
		other := "/other-" + strconv.Itoa(i)
		if pc.keyPurgeStripe(pc.buildKey("GET", host, other)) != taken {
			return other
		}
	}
	t.Fatalf("no path outside the purge stripe of %s", path)
	return ""
}

const proxyFix2WarmPurges = 3

func proxyFix2HeldMissThenSwapCache(t *testing.T, tune func(s *Server), afterSwap func(s *Server)) *Server {
	t.Helper()
	o := newProxyFixHeldOrigin(t, false)
	srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), tune)
	c := proxyFixDial(t, addr)
	defer c.Close()
	if _, err := io.WriteString(c, proxyFixGet(proxyFixDomain, "/doc")); err != nil {
		t.Fatalf("write: %v", err)
	}
	proxyFixEventually(t, "the cache miss reached the origin", func() bool { return o.received.Load() == 1 })
	srv.SetProxyCache(DefaultProxyCacheConfig())
	afterSwap(srv)
	o.releaseOnce()
	if resp, body := proxyFixReadResponse(t, bufio.NewReader(c)); resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("in-flight response: %d %q", resp.StatusCode, body)
	}
	return srv
}

func TestProxyFix2CacheSwapMidFillDoesNotOutlivePurge(t *testing.T) {
	srv := proxyFix2HeldMissThenSwapCache(t, func(s *Server) {
		s.SetProxyCache(DefaultProxyCacheConfig())
		for i := 0; i < proxyFix2WarmPurges; i++ {
			s.PurgeProxyCache("GET", proxyFixDomain, "/warm")
		}
	}, func(s *Server) { s.PurgeAllProxyCache() })
	if entries, _, _, _ := srv.ProxyCacheStats(); entries != 0 {
		t.Fatalf("a fill begun before SetProxyCache and PurgeAll landed in the new cache (%d entries)", entries)
	}
}

func TestProxyFix2CacheEnabledMidFillStoresNoOrphan(t *testing.T) {
	srv := proxyFix2HeldMissThenSwapCache(t, func(s *Server) {
		s.proxy.Load().OnResponse = func(pr *ProxyResponse) { pr.CacheThis(time.Minute, 0) }
	}, func(*Server) {})
	if entries, _, _, _ := srv.ProxyCacheStats(); entries != 0 {
		t.Fatalf("a fill begun with no cache stored %d entries into the cache enabled mid-flight", entries)
	}
}
