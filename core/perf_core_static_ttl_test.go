//go:build linux && amd64

package core

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	perfCoreStaticTinyTTL      = 150 * time.Millisecond
	perfCoreStaticLongTTL      = time.Hour
	perfCoreStaticPollCeiling  = 3 * time.Second
	perfCoreStaticPollInterval = 15 * time.Millisecond
)

func perfCoreStaticPoll(t *testing.T, what string, cond func() bool) {
	t.Helper()
	perfCoreStaticPollWithin(t, what, perfCoreStaticPollCeiling, cond)
}

func perfCoreStaticPollWithin(t *testing.T, what string, ceiling time.Duration, cond func() bool) {
	t.Helper()
	deadline := turbo.Deadline(ceiling)
	for !cond() {
		if turbo.Until(deadline) <= 0 {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(perfCoreStaticPollInterval)
	}
}

func perfCoreStaticBody(handler HandlerFunc, path string) (int, string) {
	resp := perfCoreStaticGet(handler, path)
	return resp.StatusCode, string(resp.GetBody())
}

func TestPerfCoreStaticTTLHitTouchesNoFile(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	base := t.TempDir()
	root := filepath.Join(base, "root")
	perfCoreWriteStatic(t, filepath.Join(root, "app.js"), []byte("cached-body"))
	perfCoreWriteStatic(t, filepath.Join(root, "other.js"), []byte("other"))
	handler, cache := newStaticHandler("/s", StaticConfig{Root: root, CacheTTL: perfCoreStaticLongTTL})
	if got := perfCoreStaticGet(handler, "/s/app.js"); got.StatusCode != 200 || !got.fileBody {
		t.Fatalf("fill = %d cached=%v", got.StatusCode, got.fileBody)
	}
	if err := os.Rename(root, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		got := perfCoreStaticGet(handler, "/s/app.js")
		if got.StatusCode != 200 || string(got.GetBody()) != "cached-body" || !got.fileBody {
			t.Fatalf("hit %d with the root gone = %d %q cached=%v; a hit inside the TTL must not open, stat or read anything", i, got.StatusCode, got.GetBody(), got.fileBody)
		}
	}
	if status, _ := perfCoreStaticBody(handler, "/s/other.js"); status != 404 {
		t.Fatalf("uncached path with the root gone = %d, want 404", status)
	}
	if cache.entries.Len() != 1 {
		t.Fatalf("entries = %d, want 1", cache.entries.Len())
	}
}

func TestPerfCoreStaticTTLRevalidatesAfterExpiry(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	file := filepath.Join(root, "app.js")
	perfCoreWriteStatic(t, file, []byte("version-1"))
	handler, cache := newStaticHandler("/s", StaticConfig{Root: root, CacheTTL: perfCoreStaticTinyTTL})
	if _, body := perfCoreStaticBody(handler, "/s/app.js"); body != "version-1" {
		t.Fatalf("fill got %q", body)
	}
	first, ok := cache.entries.Load("app.js")
	if !ok {
		t.Fatal("entry not cached")
	}
	perfCoreStaticPoll(t, "the TTL to lapse", func() bool { return turbo.Now() >= first.freshUntil.Load() })
	if _, body := perfCoreStaticBody(handler, "/s/app.js"); body != "version-1" {
		t.Fatalf("unchanged file after TTL got %q", body)
	}
	if again, _ := cache.entries.Load("app.js"); again != first || turbo.Now() >= first.freshUntil.Load() {
		t.Fatal("an unchanged file must keep its entry and get a renewed TTL")
	}

	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	mtime := fi.ModTime()
	perfCoreWriteStatic(t, file, []byte("version-2"))
	if err := os.Chtimes(file, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	perfCoreStaticPoll(t, "same-size rewrite with restored mtime", func() bool {
		_, body := perfCoreStaticBody(handler, "/s/app.js")
		return body == "version-2"
	})

	replacement := filepath.Join(root, "app.js.new")
	perfCoreWriteStatic(t, replacement, []byte("version-3"))
	if err := os.Chtimes(replacement, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, file); err != nil {
		t.Fatal(err)
	}
	perfCoreStaticPoll(t, "renamed-over replacement with a new inode", func() bool {
		_, body := perfCoreStaticBody(handler, "/s/app.js")
		return body == "version-3"
	})

	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	perfCoreStaticPoll(t, "deleted file to 404", func() bool {
		status, _ := perfCoreStaticBody(handler, "/s/app.js")
		return status == 404
	})
	if cache.entries.Len() != 0 || cache.bytes.Load() != 0 {
		t.Fatalf("deleted file left entries=%d bytes=%d", cache.entries.Len(), cache.bytes.Load())
	}
}

func TestPerfCoreStaticTTLNegativeValidatesEveryRequest(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	file := filepath.Join(root, "a.txt")
	perfCoreWriteStatic(t, file, []byte("one"))
	handler, cache := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: -1})
	if got := perfCoreStaticGet(handler, "/a.txt"); !got.fileBody || cache.entries.Len() != 1 {
		t.Fatalf("negative TTL must still cache (cached=%v entries=%d)", got.fileBody, cache.entries.Len())
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if status, _ := perfCoreStaticBody(handler, "/a.txt"); status != 404 {
		t.Fatalf("negative TTL served a deleted file: %d", status)
	}
}

func TestPerfCoreStaticTTLDefaultsToTwoSeconds(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want int64
	}{{0, int64(2 * time.Second)}, {-1, 0}, {-time.Hour, 0}, {perfCoreStaticTinyTTL, int64(perfCoreStaticTinyTTL)}} {
		if got := newStaticFileCache(StaticConfig{CacheTTL: tc.in}).ttl; got != tc.want {
			t.Fatalf("CacheTTL %v -> ttl %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestPerfCoreStaticTTLSkipsUnsettledFiles(t *testing.T) {
	root := t.TempDir()
	perfCoreWriteStatic(t, filepath.Join(root, "fresh.txt"), []byte("fresh"))
	handler, cache := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: perfCoreStaticLongTTL})
	for i := 0; i < 3; i++ {
		if got := perfCoreStaticGet(handler, "/fresh.txt"); got.StatusCode != 200 || got.fileBody {
			t.Fatalf("request %d: %d cached=%v", i, got.StatusCode, got.fileBody)
		}
	}
	if cache.entries.Len() != 0 {
		t.Fatalf("a file modified in the settle window was cached (%d entries)", cache.entries.Len())
	}
}

func TestPerfCoreStaticTTLConditionalAndRangeFromCache(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	content := serveContentPattern(5000)
	file := filepath.Join(root, "c.bin")
	perfCoreWriteStatic(t, file, content)
	modTime := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(file, modTime, modTime); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	etag := expectedETag(fi)
	handler, _ := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: perfCoreStaticLongTTL})
	if got := perfCoreStaticGet(handler, "/c.bin"); !got.fileBody {
		t.Fatal("fill was not cached")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	full := perfCoreStaticGet(handler, "/c.bin")
	if full.StatusCode != 200 || !bytes.Equal(full.GetBody(), content) || full.ContentType != "application/octet-stream" {
		t.Fatalf("full = %d len %d type %q", full.StatusCode, full.BodyLen(), full.ContentType)
	}
	if got, _ := respHeader(full, "ETag"); got != etag {
		t.Fatalf("etag %q, want %q", got, etag)
	}
	if got, _ := respHeader(full, "Last-Modified"); got != "Tue, 02 Jan 2024 03:04:05 GMT" {
		t.Fatalf("last-modified %q", got)
	}
	if nm := perfCoreStaticGet(handler, "/c.bin", "If-None-Match", etag); nm.StatusCode != 304 || nm.BodyLen() != 0 {
		t.Fatalf("if-none-match = %d len %d", nm.StatusCode, nm.BodyLen())
	}
	if ims := perfCoreStaticGet(handler, "/c.bin", "If-Modified-Since", "Tue, 02 Jan 2024 03:04:05 GMT"); ims.StatusCode != 304 {
		t.Fatalf("if-modified-since = %d", ims.StatusCode)
	}
	if old := perfCoreStaticGet(handler, "/c.bin", "If-Modified-Since", "Mon, 01 Jan 2024 00:00:00 GMT"); old.StatusCode != 200 || old.BodyLen() != len(content) {
		t.Fatalf("older if-modified-since = %d len %d", old.StatusCode, old.BodyLen())
	}
	part := perfCoreStaticGet(handler, "/c.bin", "Range", "bytes=4990-")
	if part.StatusCode != 206 || !bytes.Equal(part.GetBody(), content[4990:]) {
		t.Fatalf("range = %d len %d", part.StatusCode, part.BodyLen())
	}
	if cr, _ := respHeader(part, "Content-Range"); cr != "bytes 4990-4999/5000" {
		t.Fatalf("content-range %q", cr)
	}
	if bad := perfCoreStaticGet(handler, "/c.bin", "Range", "bytes=5000-"); bad.StatusCode != 416 {
		t.Fatalf("unsatisfiable = %d", bad.StatusCode)
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

func TestPerfCoreStaticTTLRejectsUnsafePathsWithWarmCache(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	base := t.TempDir()
	root := filepath.Join(base, "root")
	perfCoreWriteStatic(t, filepath.Join(root, "a.txt"), []byte("public"))
	perfCoreWriteStatic(t, filepath.Join(root, ".env"), []byte("dotfile"))
	perfCoreWriteStatic(t, filepath.Join(base, "secret.txt"), []byte("secret"))
	handler, cache := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: perfCoreStaticLongTTL})
	if got := perfCoreStaticGet(handler, "/a.txt"); !got.fileBody {
		t.Fatal("warm-up was not cached")
	}
	warm, _ := cache.entries.Load("a.txt")
	for _, key := range []string{".env", "../secret.txt", "a.txt/../a.txt", "x/../a.txt", ".git/config", "a.txt\x00", `a\a.txt`} {
		cache.entries.Store(key, warm)
	}
	for _, path := range []string{"/.env", "/../secret.txt", "/a.txt/../a.txt", "/x/../a.txt", "/.git/config", "/a.txt\x00", `/a\a.txt`} {
		if got := perfCoreStaticGet(handler, path); got.StatusCode != 400 || got.fileBody {
			t.Fatalf("%q = %d %q cached=%v, want 400 before any cache lookup", path, got.StatusCode, got.GetBody(), got.fileBody)
		}
	}
}

func TestPerfCoreStaticTTLContainmentAfterExpiry(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	perfCoreWriteStatic(t, filepath.Join(root, "in.txt"), []byte("inside"))
	perfCoreWriteStatic(t, filepath.Join(outside, "secret.txt"), []byte("secret"))
	handler, _ := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: perfCoreStaticTinyTTL})
	if _, body := perfCoreStaticBody(handler, "/in.txt"); body != "inside" {
		t.Fatalf("warm-up got %q", body)
	}
	if err := os.Remove(filepath.Join(root, "in.txt")); err != nil {
		t.Fatal(err)
	}
	appFixSymlinkOrSkip(t, filepath.Join(outside, "secret.txt"), filepath.Join(root, "in.txt"))
	perfCoreStaticPoll(t, "escaping symlink to be refused", func() bool {
		status, body := perfCoreStaticBody(handler, "/in.txt")
		if body == "secret" {
			t.Fatal("served content from outside the root")
		}
		return status == 403
	})
}

func TestPerfCoreStaticTTLFollowsRootRepoint(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	base := t.TempDir()
	rel1 := filepath.Join(base, "releases", "1")
	rel2 := filepath.Join(base, "releases", "2")
	perfCoreWriteStatic(t, filepath.Join(rel1, "app.js"), []byte("release-1"))
	perfCoreWriteStatic(t, filepath.Join(rel2, "app.js"), []byte("release-2"))
	current := filepath.Join(base, "current")
	appFixSymlinkOrSkip(t, rel1, current)
	handler, _ := newStaticHandler("/", StaticConfig{Root: current, CacheTTL: perfCoreStaticTinyTTL})
	if _, body := perfCoreStaticBody(handler, "/app.js"); body != "release-1" {
		t.Fatalf("before repoint got %q", body)
	}
	appFix2RepointSymlink(t, rel2, current)
	perfCoreStaticPoll(t, "root repoint", func() bool {
		_, body := perfCoreStaticBody(handler, "/app.js")
		return body == "release-2"
	})
}

func TestPerfCoreStaticTTLMemoryCapUnderManyFiles(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	const files, size, workers = 400, 2000, 8
	for i := 0; i < files; i++ {
		perfCoreWriteStatic(t, filepath.Join(root, "f"+strconv.Itoa(i)), bytes.Repeat([]byte{byte(i)}, size))
	}
	limit := int64(10 * (size + staticCacheEntryOverhead + 8))
	handler, cache := newStaticHandler("/", StaticConfig{Root: root, CacheMaxBytes: limit, CacheTTL: perfCoreStaticLongTTL})
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < files*2; i += workers {
				n := i % files
				got := perfCoreStaticGet(handler, "/f"+strconv.Itoa(n))
				if got.StatusCode != 200 || !bytes.Equal(got.GetBody(), bytes.Repeat([]byte{byte(n)}, size)) {
					errs <- fmt.Sprintf("f%d = %d len %d", n, got.StatusCode, got.BodyLen())
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	var sum int64
	cache.entries.Range(func(_ string, e *staticCacheEntry) bool {
		sum += e.cost
		return true
	})
	if used := cache.bytes.Load(); used > limit || sum != used {
		t.Fatalf("cache accounts %d bytes, entries hold %d, cap %d", used, sum, limit)
	}
}

type perfCoreStaticWireFile struct {
	path string
	data []byte
}

func perfCoreStaticFetch(client *http.Client, url string, want []byte, wantProto int) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 || resp.ProtoMajor != wantProto || !bytes.Equal(body, want) {
		return fmt.Errorf("%s: status %d proto %d len %d (want %d), bytes equal=%v", url, resp.StatusCode, resp.ProtoMajor, len(body), len(want), bytes.Equal(body, want))
	}
	return nil
}

func TestPerfCoreStaticCachedBodySharedAcrossProtocols(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	files := []perfCoreStaticWireFile{
		{"small.css", serveContentPattern(3000)},
		{"mid.bin", serveContentPattern(64 << 10)},
		{"big.bin", serveContentPattern(1<<20 + 77)},
	}
	for _, f := range files {
		perfCoreWriteStatic(t, filepath.Join(root, f.path), f.data)
	}
	var plainCache, tlsCache *staticFileCache
	routes := func(cache **staticFileCache) func(*Router) {
		return func(r *Router) {
			h, c := newStaticHandler("/s", StaticConfig{Root: root, CacheMaxFileSize: 2 << 20, CacheTTL: perfCoreStaticLongTTL})
			*cache = c
			r.GET("/s/*filepath", h)
		}
	}
	plain := newTestServer(t, testServerOptions{Routes: routes(&plainCache)})
	secure := newTestServer(t, testServerOptions{TLS: true, Routes: routes(&tlsCache)})

	h1 := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 16}, Timeout: harnessIOTimeout}
	h2cTransport := &http.Transport{Protocols: new(http.Protocols)}
	h2cTransport.Protocols.SetUnencryptedHTTP2(true)
	h2c := &http.Client{Transport: h2cTransport, Timeout: harnessIOTimeout}
	tlsH1 := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 16, TLSClientConfig: secure.tlsConfig("http/1.1")}, Timeout: harnessIOTimeout}
	tlsH2 := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: secure.tlsConfig("h2")}, Timeout: harnessIOTimeout}
	t.Cleanup(func() {
		for _, c := range []*http.Client{h1, h2c, tlsH1, tlsH2} {
			c.CloseIdleConnections()
		}
	})
	clients := []struct {
		name   string
		client *http.Client
		srv    *testServer
		proto  int
	}{{"h1", h1, plain, 1}, {"h2c", h2c, plain, 2}, {"tls", tlsH1, secure, 1}, {"h2", tlsH2, secure, 2}}

	for _, c := range clients {
		for _, f := range files {
			if err := perfCoreStaticFetch(c.client, c.srv.url("/s/"+f.path), f.data, c.proto); err != nil {
				t.Fatalf("%s warm-up: %v", c.name, err)
			}
		}
	}
	for _, cache := range []*staticFileCache{plainCache, tlsCache} {
		if cache.entries.Len() != len(files) {
			t.Fatalf("expected every file cached, have %d", cache.entries.Len())
		}
	}

	const workersPerClient, rounds = 6, 8
	var wg sync.WaitGroup
	errs := make(chan error, len(clients)*workersPerClient)
	for _, c := range clients {
		for w := 0; w < workersPerClient; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for r := 0; r < rounds; r++ {
					f := files[(r+w)%len(files)]
					if err := perfCoreStaticFetch(c.client, c.srv.url("/s/"+f.path), f.data, c.proto); err != nil {
						errs <- fmt.Errorf("%s: %w", c.name, err)
						return
					}
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for _, cache := range []*staticFileCache{plainCache, tlsCache} {
		for _, f := range files {
			e, ok := cache.entries.Load(f.path)
			if !ok || !bytes.Equal(e.data, f.data) {
				t.Fatalf("cached body of %s was modified or evicted (present=%v)", f.path, ok)
			}
		}
	}
}

func BenchmarkPerfCoreW6StaticTTL(b *testing.B) {
	perfCoreSettleStaticFiles(b)
	root, _ := perfCoreStaticRoot(b)
	for _, mode := range []struct {
		name string
		ttl  time.Duration
	}{{"ttl_hit", 0}, {"validate_every_request", -1}} {
		b.Run(mode.name, func(b *testing.B) {
			rig := newPerfCoreStaticRig(root, true)
			rig.handler = Static(perfCoreStaticPrefix, StaticConfig{Root: root, CacheTTL: mode.ttl})
			rig.serve()
			b.SetBytes(perfCoreStaticFileSize)
			b.ReportAllocs()
			for b.Loop() {
				rig.serve()
			}
			if rig.resp.StatusCode != 200 || !rig.resp.fileBody {
				b.Fatalf("status %d cached=%v", rig.resp.StatusCode, rig.resp.fileBody)
			}
		})
	}
}
