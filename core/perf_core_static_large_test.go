//go:build linux && amd64

package core

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	perfCoreLargeCacheBytes = 3 << 20
	perfCoreLargeFileSize   = 700 << 10
	perfCoreLargeFitCount   = 4
	perfCoreSmallFileSize   = 10 << 10
)

func perfCoreFillFromDisk(t *testing.T, cache *staticFileCache, root, rel string, fillLarge bool) *staticCacheEntry {
	t.Helper()
	fd, err := unix.Open(filepath.Join(root, rel), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	sc := &staticScratch{}
	if err := unix.Fstat(fd, &sc.st); err != nil {
		t.Fatal(err)
	}
	return cache.lookupOrFill(sc, fd, rel, fillLarge)
}

func TestPerfCoreStaticLargeFillNeverEvicts(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	names := []string{"a.bin", "b.bin", "c.bin", "d.bin", "e.bin"}
	for _, n := range names {
		perfCoreWriteStatic(t, filepath.Join(root, n), serveContentPattern(perfCoreLargeFileSize))
	}
	perfCoreWriteStatic(t, filepath.Join(root, "small.css"), serveContentPattern(perfCoreSmallFileSize))
	cache := newStaticFileCache(StaticConfig{CacheMaxBytes: perfCoreLargeCacheBytes})
	if cache.maxFileSize != perfCoreLargeCacheBytes/staticCacheDefaultFileShare {
		t.Fatalf("default per-file cap %d", cache.maxFileSize)
	}
	for _, n := range names[:perfCoreLargeFitCount] {
		if perfCoreFillFromDisk(t, cache, root, n, true) == nil {
			t.Fatalf("%s was not cached", n)
		}
	}
	if perfCoreFillFromDisk(t, cache, root, names[perfCoreLargeFitCount], true) != nil {
		t.Fatal("a large file was admitted into a full cache")
	}
	if got := cache.entries.Len(); got != perfCoreLargeFitCount {
		t.Fatalf("large admission evicted entries: %d left", got)
	}
	if cache.bytes.Load() > perfCoreLargeCacheBytes {
		t.Fatalf("accounted bytes %d above the cap", cache.bytes.Load())
	}
	if perfCoreFillFromDisk(t, cache, root, "small.css", true) == nil {
		t.Fatal("small file not served from a full cache")
	}
	if cache.bytes.Load() > perfCoreLargeCacheBytes {
		t.Fatalf("accounted bytes %d above the cap after a small fill", cache.bytes.Load())
	}
}

func TestPerfCoreStaticLargeFillIsSingleFlight(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	perfCoreWriteStatic(t, filepath.Join(root, "big.bin"), serveContentPattern(perfCoreLargeFileSize))
	cache := newStaticFileCache(StaticConfig{})
	cache.filling.Store("big.bin", struct{}{})
	if perfCoreFillFromDisk(t, cache, root, "big.bin", true) != nil || cache.entries.Len() != 0 || cache.bytes.Load() != 0 {
		t.Fatal("a second filler loaded a file that is already being filled")
	}
	cache.filling.Delete("big.bin")
	if e := perfCoreFillFromDisk(t, cache, root, "big.bin", false); e == nil || e.data != nil || cache.entries.Len() != 1 {
		t.Fatal("a sendfile-capable request must get a descriptor-only entry, not file bytes")
	}
	if e := perfCoreFillFromDisk(t, cache, root, "big.bin", true); e == nil || e.data == nil || cache.entries.Len() != 1 {
		t.Fatal("large file not cached")
	}
	if _, busy := cache.filling.Load("big.bin"); busy {
		t.Fatal("fill marker left behind")
	}
}

func TestPerfCoreStaticLargeFileCachedForTLSNotPlain(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	content := serveContentPattern(1<<20 + 5)
	perfCoreWriteStatic(t, filepath.Join(root, "big.bin"), content)
	for _, useTLS := range []bool{false, true} {
		var cache *staticFileCache
		ts := newTestServer(t, testServerOptions{TLS: useTLS, Routes: func(r *Router) {
			h, c := newStaticHandler("/s", StaticConfig{Root: root})
			cache = c
			r.GET("/s/*filepath", h)
		}})
		alpns := []string{"http/1.1"}
		if useTLS {
			alpns = append(alpns, "h2")
		}
		for round := 0; round < 2; round++ {
			for _, alpn := range alpns {
				if err := perfCoreStaticFetch(ts.client(t, alpn), ts.url("/s/big.bin"), content, map[string]int{"http/1.1": 1, "h2": 2}[alpn]); err != nil {
					t.Fatalf("tls=%v %s round %d: %v", useTLS, alpn, round, err)
				}
			}
		}
		e, ok := cache.entries.Load("big.bin")
		if !ok || (e.data != nil) != useTLS {
			t.Fatalf("tls=%v: entry %v, holds bytes %v", useTLS, ok, ok && e.data != nil)
		}
	}
}
