//go:build linux && amd64

package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func perfCoreStaticGet(handler HandlerFunc, path string, headers ...string) *Response {
	req := &Request{Method: "GET", Path: path}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Headers = append(req.Headers, [2]string{headers[i], headers[i+1]})
	}
	resp := &Response{}
	resp.Reset()
	resp.lazyReq = req
	handler(req, resp)
	return resp
}

func perfCoreWriteStatic(t testing.TB, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPerfCoreStaticCacheServesAndRevalidates(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	perfCoreWriteStatic(t, file, []byte("version-1"))
	handler, cache := newStaticHandler("/s", StaticConfig{Root: root, CacheTTL: -1})
	if cache == nil {
		t.Fatal("static cache must be on by default")
	}
	first := perfCoreStaticGet(handler, "/s/app.js")
	if first.StatusCode != 200 || string(first.GetBody()) != "version-1" || !first.fileBody {
		t.Fatalf("first = %d %q cached=%v", first.StatusCode, first.GetBody(), first.fileBody)
	}
	if cache.entries.Len() != 1 {
		t.Fatalf("entries = %d, want 1", cache.entries.Len())
	}
	perfCoreWriteStatic(t, file, []byte("version-2"))
	if got := perfCoreStaticGet(handler, "/s/app.js"); string(got.GetBody()) != "version-2" {
		t.Fatalf("after rewrite got %q", got.GetBody())
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	mtime := fi.ModTime()
	perfCoreWriteStatic(t, file, []byte("version-3"))
	if err := os.Chtimes(file, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if got := perfCoreStaticGet(handler, "/s/app.js"); string(got.GetBody()) != "version-3" {
		t.Fatalf("same size and restored mtime got %q, want version-3", got.GetBody())
	}
	replacement := filepath.Join(root, "app.js.new")
	perfCoreWriteStatic(t, replacement, []byte("version-4"))
	if err := os.Chtimes(replacement, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, file); err != nil {
		t.Fatal(err)
	}
	if got := perfCoreStaticGet(handler, "/s/app.js"); string(got.GetBody()) != "version-4" {
		t.Fatalf("renamed-over file got %q, want version-4", got.GetBody())
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if got := perfCoreStaticGet(handler, "/s/app.js"); got.StatusCode != 404 {
		t.Fatalf("deleted file = %d %q", got.StatusCode, got.GetBody())
	}
}

func TestPerfCoreStaticCacheSkipsUnsettledFiles(t *testing.T) {
	root := t.TempDir()
	perfCoreWriteStatic(t, filepath.Join(root, "fresh.txt"), []byte("fresh"))
	handler, cache := newStaticHandler("/", StaticConfig{Root: root})
	got := perfCoreStaticGet(handler, "/fresh.txt")
	if got.StatusCode != 200 || string(got.GetBody()) != "fresh" {
		t.Fatalf("fresh file = %d %q", got.StatusCode, got.GetBody())
	}
	if got.fileBody || cache.entries.Len() != 0 {
		t.Fatalf("a file changed within the settle window must not be cached (cached=%v entries=%d)", got.fileBody, cache.entries.Len())
	}
}

func TestPerfCoreStaticCacheDisabled(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	perfCoreWriteStatic(t, filepath.Join(root, "a.txt"), []byte("plain"))
	handler, cache := newStaticHandler("/", StaticConfig{Root: root, DisableCache: true})
	if cache != nil {
		t.Fatal("DisableCache must not build a cache")
	}
	got := perfCoreStaticGet(handler, "/a.txt")
	if got.StatusCode != 200 || string(got.GetBody()) != "plain" || got.fileBody {
		t.Fatalf("uncached = %d %q cached=%v", got.StatusCode, got.GetBody(), got.fileBody)
	}
}

func TestPerfCoreStaticCacheMemoryCap(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	const files, size = 12, 1000
	for i := 0; i < files; i++ {
		perfCoreWriteStatic(t, filepath.Join(root, "f"+strconv.Itoa(i)), bytes.Repeat([]byte{byte('a' + i)}, size))
	}
	limit := int64(3 * (size + staticCacheEntryOverhead + 8))
	handler, cache := newStaticHandler("/", StaticConfig{Root: root, CacheMaxBytes: limit})
	for round := 0; round < 2; round++ {
		for i := 0; i < files; i++ {
			got := perfCoreStaticGet(handler, "/f"+strconv.Itoa(i))
			if got.StatusCode != 200 || !bytes.Equal(got.GetBody(), bytes.Repeat([]byte{byte('a' + i)}, size)) {
				t.Fatalf("f%d = %d len %d", i, got.StatusCode, got.BodyLen())
			}
			if used := cache.bytes.Load(); used > limit {
				t.Fatalf("cache uses %d bytes, cap %d", used, limit)
			}
		}
	}
	var sum int64
	cache.entries.Range(func(_ string, e *staticCacheEntry) bool {
		sum += e.cost
		return true
	})
	if sum != cache.bytes.Load() {
		t.Fatalf("accounted %d bytes, entries hold %d", cache.bytes.Load(), sum)
	}
	big := filepath.Join(root, "big")
	perfCoreWriteStatic(t, big, bytes.Repeat([]byte{'z'}, int(limit)+1))
	if got := perfCoreStaticGet(handler, "/big"); got.StatusCode != 200 || got.BodyLen() != int(limit)+1 || got.fileBody {
		t.Fatalf("file above the per-file cap = %d len %d cached=%v", got.StatusCode, got.BodyLen(), got.fileBody)
	}
}

func TestPerfCoreStaticCacheValidatorsAndRanges(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	content := serveContentPattern(5000)
	file := filepath.Join(root, "c.bin")
	perfCoreWriteStatic(t, file, content)
	modTime := time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC)
	if err := os.Chtimes(file, modTime, modTime); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := newStaticHandler("/", StaticConfig{Root: root})
	full := perfCoreStaticGet(handler, "/c.bin")
	if full.StatusCode != 200 || !bytes.Equal(full.GetBody(), content) || !full.fileBody {
		t.Fatalf("full = %d len %d cached=%v", full.StatusCode, full.BodyLen(), full.fileBody)
	}
	if etag, _ := respHeader(full, "ETag"); etag != expectedETag(fi) {
		t.Fatalf("etag %q, want %q", etag, expectedETag(fi))
	}
	if lm, _ := respHeader(full, "Last-Modified"); lm != modTime.Format("Mon, 02 Jan 2006 15:04:05 GMT") {
		t.Fatalf("last-modified %q", lm)
	}
	if ar, _ := respHeader(full, "Accept-Ranges"); ar != "bytes" {
		t.Fatalf("accept-ranges %q", ar)
	}
	if full.ContentType != "application/octet-stream" {
		t.Fatalf("content type %q", full.ContentType)
	}
	part := perfCoreStaticGet(handler, "/c.bin", "Range", "bytes=100-199")
	if part.StatusCode != 206 || !bytes.Equal(part.GetBody(), content[100:200]) {
		t.Fatalf("range = %d len %d", part.StatusCode, part.BodyLen())
	}
	if cr, _ := respHeader(part, "Content-Range"); cr != "bytes 100-199/5000" {
		t.Fatalf("content-range %q", cr)
	}
	if bad := perfCoreStaticGet(handler, "/c.bin", "Range", "bytes=9000-"); bad.StatusCode != 416 {
		t.Fatalf("unsatisfiable = %d", bad.StatusCode)
	} else if cr, _ := respHeader(bad, "Content-Range"); cr != "bytes */5000" {
		t.Fatalf("416 content-range %q", cr)
	}
	if nm := perfCoreStaticGet(handler, "/c.bin", "If-None-Match", expectedETag(fi)); nm.StatusCode != 304 || nm.BodyLen() != 0 {
		t.Fatalf("if-none-match = %d len %d", nm.StatusCode, nm.BodyLen())
	}
	if pf := perfCoreStaticGet(handler, "/c.bin", "If-Match", `"other"`); pf.StatusCode != 412 {
		t.Fatalf("if-match = %d", pf.StatusCode)
	}
	head := &Request{Method: "HEAD", Path: "/c.bin"}
	hresp := &Response{}
	hresp.Reset()
	hresp.lazyReq = head
	handler(head, hresp)
	if hresp.StatusCode != 200 || hresp.headerContentLength() != len(content) || hresp.transmittedBodyLen() != 0 {
		t.Fatalf("head = %d cl %d sent %d", hresp.StatusCode, hresp.headerContentLength(), hresp.transmittedBodyLen())
	}
}

func TestPerfCoreStaticCacheKeepsContainment(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	perfCoreWriteStatic(t, filepath.Join(root, "in.txt"), []byte("inside"))
	perfCoreWriteStatic(t, filepath.Join(outside, "secret.txt"), []byte("secret"))
	appFixSymlinkOrSkip(t, filepath.Join(outside, "secret.txt"), filepath.Join(root, "escape.txt"))
	appFixSymlinkOrSkip(t, "../outside", filepath.Join(root, "escapedir"))
	appFixSymlinkOrSkip(t, filepath.Join(root, "in.txt"), filepath.Join(root, "abs-inside.txt"))
	appFixSymlinkOrSkip(t, "in.txt", filepath.Join(root, "rel-inside.txt"))
	handler, _ := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: -1})
	for _, path := range []string{"/escape.txt", "/escapedir/secret.txt"} {
		if got := perfCoreStaticGet(handler, path); got.StatusCode != 403 || string(got.GetBody()) == "secret" {
			t.Fatalf("%s = %d %q, want 403", path, got.StatusCode, got.GetBody())
		}
	}
	for _, path := range []string{"/abs-inside.txt", "/rel-inside.txt", "/in.txt"} {
		if got := perfCoreStaticGet(handler, path); got.StatusCode != 200 || string(got.GetBody()) != "inside" {
			t.Fatalf("%s = %d %q, want 200 inside", path, got.StatusCode, got.GetBody())
		}
	}
	perfCoreStaticGet(handler, "/in.txt")
	if err := os.Remove(filepath.Join(root, "in.txt")); err != nil {
		t.Fatal(err)
	}
	appFixSymlinkOrSkip(t, filepath.Join(outside, "secret.txt"), filepath.Join(root, "in.txt"))
	if got := perfCoreStaticGet(handler, "/in.txt"); got.StatusCode != 403 {
		t.Fatalf("cached path swapped to an escaping symlink = %d %q, want 403", got.StatusCode, got.GetBody())
	}
}

func TestPerfCoreStaticCacheFollowsRootRepoint(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	base := t.TempDir()
	rel1 := filepath.Join(base, "releases", "1")
	rel2 := filepath.Join(base, "releases", "2")
	perfCoreWriteStatic(t, filepath.Join(rel1, "app.js"), []byte("release-1"))
	perfCoreWriteStatic(t, filepath.Join(rel2, "app.js"), []byte("release-2"))
	current := filepath.Join(base, "current")
	appFixSymlinkOrSkip(t, rel1, current)
	handler, _ := newStaticHandler("/", StaticConfig{Root: current, CacheTTL: -1})
	for i := 0; i < 2; i++ {
		if got := perfCoreStaticGet(handler, "/app.js"); string(got.GetBody()) != "release-1" || !got.fileBody {
			t.Fatalf("before repoint %d: %q cached=%v", i, got.GetBody(), got.fileBody)
		}
	}
	appFix2RepointSymlink(t, rel2, current)
	if got := perfCoreStaticGet(handler, "/app.js"); string(got.GetBody()) != "release-2" {
		t.Fatalf("after repoint got %q, want release-2", got.GetBody())
	}
	if err := os.Rename(rel2, rel2+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(rel1, rel2); err != nil {
		t.Fatal(err)
	}
	if got := perfCoreStaticGet(handler, "/app.js"); string(got.GetBody()) != "release-1" {
		t.Fatalf("after swapping the directory behind the link got %q, want release-1", got.GetBody())
	}
}

func TestPerfCoreStaticCacheSkipsCompression(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	perfCoreWriteStatic(t, filepath.Join(root, "t.txt"), bytes.Repeat([]byte("compressible "), 200))
	handler, _ := newStaticHandler("/", StaticConfig{Root: root})
	wrapped := Chain(handler, Compress(CompressConfig{}))
	got := perfCoreStaticGet(wrapped, "/t.txt", "Accept-Encoding", "gzip")
	if ce, ok := respHeader(got, "Content-Encoding"); ok {
		t.Fatalf("static file body was compressed (%q); streamed static files never were", ce)
	}
	if got.BodyLen() != 2600 {
		t.Fatalf("len %d", got.BodyLen())
	}
}

func TestPerfCoreStaticCacheHitZeroAlloc(t *testing.T) {
	perfCoreSkipAllocLockUnderRace(t)
	perfCoreSettleStaticFiles(t)
	root, data := perfCoreStaticRoot(t)
	rig := newPerfCoreStaticRig(root, true)
	rig.serve()
	if !rig.resp.fileBody || !bytes.Equal(rig.resp.GetBody(), data) {
		t.Fatalf("warm-up was not served from the cache (cached=%v len=%d)", rig.resp.fileBody, rig.resp.BodyLen())
	}
	if allocs := testing.AllocsPerRun(200, rig.serve); allocs != 0 {
		t.Fatalf("cached static hit allocates %.1f/op, want 0", allocs)
	}
}

func perfCoreSanitizeStaticPathReference(p string) (string, bool) {
	if strings.ContainsAny(p, "\x00\\") || strings.Contains(p, "..") {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if len(seg) > 0 && seg[0] == '.' && seg != ".well-known" {
			return "", false
		}
	}
	return p, true
}

var perfCoreSanitizeSeeds = []string{
	"", "/", "/a", "/.well-known/x", "/.well-knownx", "/a/.b", ".x", "/a/./b", "/a/..", "/a\b", "/a\x00", "//.well-known",
	"/.well-known/.well-known", "/a.b/c.d", "/.", "/a/.", ".well-known", "/x/.well-known/", "/.git/config",
}

func TestPerfCoreSanitizeStaticPathMatchesReference(t *testing.T) {
	for _, p := range perfCoreSanitizeSeeds {
		gotPath, gotOK := sanitizeStaticPath(p)
		wantPath, wantOK := perfCoreSanitizeStaticPathReference(p)
		if gotPath != wantPath || gotOK != wantOK {
			t.Fatalf("sanitizeStaticPath(%q) = %q %v, want %q %v", p, gotPath, gotOK, wantPath, wantOK)
		}
	}
}

func FuzzPerfCoreSanitizeStaticPath(f *testing.F) {
	for _, p := range perfCoreSanitizeSeeds {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		gotPath, gotOK := sanitizeStaticPath(p)
		wantPath, wantOK := perfCoreSanitizeStaticPathReference(p)
		if gotPath != wantPath || gotOK != wantOK {
			t.Fatalf("sanitizeStaticPath(%q) = %q %v, want %q %v", p, gotPath, gotOK, wantPath, wantOK)
		}
	})
}

func BenchmarkPerfCoreStaticSyscalls(b *testing.B) {
	root, _ := perfCoreStaticRoot(b)
	rootZ := append([]byte(root), 0)
	sc := &staticScratch{path: make([]byte, 0, staticScratchPathCap)}
	dir := sc.openDirHandle(rootZ)
	if dir == nil {
		b.Fatal("open root")
	}
	defer dir.release()
	b.Run("stat_root", func(b *testing.B) {
		for b.Loop() {
			sc.statPathZ(rootZ)
		}
	})
	for _, mode := range []struct {
		name  string
		flags uint64
	}{{"rdonly", staticFileOpenFlags}, {"opath", unix.O_PATH | unix.O_CLOEXEC}} {
		b.Run("openat2_fstat_close_"+mode.name, func(b *testing.B) {
			for b.Loop() {
				sc.path = append(append(sc.path[:0], perfCoreStaticFileName...), 0)
				sc.how = unix.OpenHow{Flags: mode.flags, Resolve: staticFileResolveFlags}
				fd, _, errno := unix.Syscall6(unix.SYS_OPENAT2, syscallFD(dir.fd), uintptr(unsafe.Pointer(&sc.path[0])), uintptr(unsafe.Pointer(&sc.how)), unsafe.Sizeof(sc.how), 0, 0)
				if errno != 0 {
					b.Fatal(errno)
				}
				_ = unix.Fstat(int(fd), &sc.st)
				_ = unix.Close(int(fd))
			}
		})
	}
}
