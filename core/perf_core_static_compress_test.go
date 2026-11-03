//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/guno1928/turbo"
)

const (
	perfCoreStaticAE          = "br, gzip"
	perfCoreStaticFirstWave   = 64
	perfCoreStaticWaveRepeats = 4

	perfCoreStaticCompressCeiling = time.Minute
)

func perfCoreStaticText(n int) []byte {
	var b bytes.Buffer
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "line %d: static assets compress well because their structure repeats\n", i)
	}
	return b.Bytes()[:n]
}

func perfCoreStaticHeader(resp *Response, name string) string {
	v, _ := respHeader(resp, name)
	return v
}

func perfCoreStaticDecode(t testing.TB, encoding string, body []byte) []byte {
	t.Helper()
	var r io.Reader
	switch encoding {
	case "":
		return body
	case "br":
		r = brotli.NewReader(bytes.NewReader(body))
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("gzip header: %v", err)
		}
		r = zr
	default:
		t.Fatalf("unexpected content-encoding %q", encoding)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decode %s: %v", encoding, err)
	}
	return out
}

func perfCoreStaticAwaitVariant(t *testing.T, handler HandlerFunc, path, accept string) *Response {
	t.Helper()
	var got *Response
	perfCoreStaticPollWithin(t, "compressed variant of "+path, perfCoreStaticCompressCeiling, func() bool {
		got = perfCoreStaticGet(handler, path, "Accept-Encoding", accept)
		return perfCoreStaticHeader(got, "Content-Encoding") != ""
	})
	return got
}

func perfCoreStaticVariantETag(identity, suffix string) string {
	return identity[:len(identity)-1] + suffix + `"`
}

func TestPerfCoreStaticIndexRootUsesCache(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	base := t.TempDir()
	root := filepath.Join(base, "root")
	home := perfCoreStaticText(3000)
	perfCoreWriteStatic(t, filepath.Join(root, "index.html"), home)
	handler, cache := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: perfCoreStaticLongTTL})
	got := perfCoreStaticGet(handler, "/")
	if got.StatusCode != 200 || !bytes.Equal(got.GetBody(), home) || !got.fileBody {
		t.Fatalf("GET / = %d len %d cached=%v", got.StatusCode, got.BodyLen(), got.fileBody)
	}
	if _, ok := cache.entries.Load("index.html"); !ok || cache.entries.Len() != 1 {
		t.Fatalf("GET / must fill the index.html entry (entries=%d)", cache.entries.Len())
	}
	if got := perfCoreStaticGet(handler, "/index.html"); got.StatusCode != 200 || !got.fileBody || cache.entries.Len() != 1 {
		t.Fatalf("/index.html = %d cached=%v entries=%d; it must share the GET / entry", got.StatusCode, got.fileBody, cache.entries.Len())
	}
	if err := os.Rename(root, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		got := perfCoreStaticGet(handler, "/")
		if got.StatusCode != 200 || !bytes.Equal(got.GetBody(), home) || !got.fileBody {
			t.Fatalf("hit %d with the root gone = %d; GET / inside the TTL must be served from the cache without touching the filesystem", i, got.StatusCode)
		}
	}
}

func TestPerfCoreStaticIndexSubdirAndBrowse(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	perfCoreWriteStatic(t, filepath.Join(root, "sub", "index.html"), []byte("sub index"))
	perfCoreWriteStatic(t, filepath.Join(root, "empty", "note.txt"), []byte("note"))
	handler, cache := newStaticHandler("/s", StaticConfig{Root: root, CacheTTL: perfCoreStaticLongTTL})
	got := perfCoreStaticGet(handler, "/s/sub/")
	if got.StatusCode != 200 || string(got.GetBody()) != "sub index" || !got.fileBody {
		t.Fatalf("/s/sub/ = %d %q cached=%v", got.StatusCode, got.GetBody(), got.fileBody)
	}
	if _, ok := cache.entries.Load("sub/index.html"); !ok {
		t.Fatal("/s/sub/ must be cached under sub/index.html")
	}
	noSlash := perfCoreStaticGet(handler, "/s/sub")
	if noSlash.StatusCode != 200 || string(noSlash.GetBody()) != "sub index" {
		t.Fatalf("/s/sub = %d %q, want the index served without a redirect as before", noSlash.StatusCode, noSlash.GetBody())
	}
	if loc := perfCoreStaticHeader(noSlash, "Location"); loc != "" {
		t.Fatalf("/s/sub must not redirect, got Location %q", loc)
	}
	for _, path := range []string{"/s/empty/", "/s/missing/"} {
		if status, _ := perfCoreStaticBody(handler, path); status != 404 {
			t.Fatalf("%s = %d, want 404", path, status)
		}
	}

	browse, _ := newStaticHandler("/s", StaticConfig{Root: root, Browse: true, CacheTTL: perfCoreStaticLongTTL})
	if status, body := perfCoreStaticBody(browse, "/s/empty/"); status != 200 || !bytes.Contains([]byte(body), []byte("note.txt")) {
		t.Fatalf("browse listing = %d %q", status, body)
	}
	if status, body := perfCoreStaticBody(browse, "/s/sub/"); status != 200 || body != "sub index" {
		t.Fatalf("browse with an index = %d %q", status, body)
	}
}

func TestPerfCoreStaticIndexContainment(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	secret := filepath.Join(outside, "secret.html")
	perfCoreWriteStatic(t, secret, []byte("secret"))
	perfCoreWriteStatic(t, filepath.Join(outside, "index.html"), []byte("secret"))
	perfCoreWriteStatic(t, filepath.Join(root, "keep.txt"), []byte("keep"))
	if err := os.MkdirAll(filepath.Join(root, "abs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "rel"), 0o755); err != nil {
		t.Fatal(err)
	}
	appFixSymlinkOrSkip(t, secret, filepath.Join(root, "abs", "index.html"))
	appFixSymlinkOrSkip(t, filepath.Join("..", "..", "outside", "secret.html"), filepath.Join(root, "rel", "index.html"))
	appFixSymlinkOrSkip(t, outside, filepath.Join(root, "linkdir"))
	handler, _ := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: perfCoreStaticLongTTL})
	for path, want := range map[string]int{"/abs/": 404, "/rel/": 404, "/linkdir/": 403} {
		for i := 0; i < 2; i++ {
			status, body := perfCoreStaticBody(handler, path)
			if body == "secret" || status != want {
				t.Fatalf("%s request %d = %d %q, want %d without the outside file", path, i, status, body, want)
			}
		}
	}
	for _, path := range []string{"/../outside/secret.html", "/abs/../../outside/", "/./", "/..", "/.hidden/"} {
		if status, body := perfCoreStaticBody(handler, path); status != 400 || body == "secret" {
			t.Fatalf("%s = %d %q, want 400", path, status, body)
		}
	}
}

func TestPerfCoreStaticIndexSymlinkSwapRefusedAfterTTL(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	perfCoreWriteStatic(t, filepath.Join(outside, "secret.html"), perfCoreStaticText(4000))
	secret := perfCoreStaticText(4000)
	home := perfCoreStaticText(2000)
	perfCoreWriteStatic(t, filepath.Join(root, "index.html"), home)
	perfCoreWriteStatic(t, filepath.Join(root, "app.js"), home)
	handler, _ := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: perfCoreStaticTinyTTL})
	if got := perfCoreStaticGet(handler, "/"); got.StatusCode != 200 || !bytes.Equal(got.GetBody(), home) {
		t.Fatalf("warm-up / = %d", got.StatusCode)
	}
	perfCoreStaticAwaitVariant(t, handler, "/app.js", "br")
	for _, name := range []string{"index.html", "app.js"} {
		if err := os.Remove(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
		appFixSymlinkOrSkip(t, filepath.Join(outside, "secret.html"), filepath.Join(root, name))
	}
	refused := func(path string, want int) func() bool {
		return func() bool {
			got := perfCoreStaticGet(handler, path, "Accept-Encoding", "br")
			if bytes.Equal(perfCoreStaticDecode(t, perfCoreStaticHeader(got, "Content-Encoding"), got.GetBody()), secret) {
				t.Fatalf("%s served the file outside the root", path)
			}
			return got.StatusCode == want
		}
	}
	perfCoreStaticPoll(t, "the swapped index to be refused", refused("/", 404))
	perfCoreStaticPoll(t, "the swapped compressed file to be refused", refused("/app.js", 403))
}

func TestPerfCoreStaticAcceptEncodingSelection(t *testing.T) {
	small, large := make([]byte, 10), make([]byte, 20)
	entry := func(brotliBody, gzipBody []byte) *staticCacheEntry {
		e := &staticCacheEntry{compressible: true}
		v := &staticVariants{}
		if brotliBody != nil {
			v.brotli = &staticVariant{body: brotliBody, encoding: "br"}
		}
		if gzipBody != nil {
			v.gzip = &staticVariant{body: gzipBody, encoding: "gzip"}
		}
		slot := &staticVariantSlot{}
		slot.state.Store(v)
		e.slot.Store(slot)
		return e
	}
	c := &staticFileCache{}
	pick := func(e *staticCacheEntry, headers ...string) string {
		req := &Request{Method: "GET"}
		for i := 0; i+1 < len(headers); i += 2 {
			req.Headers = append(req.Headers, [2]string{headers[i], headers[i+1]})
		}
		if v := c.variantFor(e, req); v != nil {
			return v.encoding
		}
		return "identity"
	}
	brSmaller := entry(small, large)
	cases := []struct{ accept, want string }{
		{"br, gzip", "br"},
		{"gzip", "gzip"},
		{"br;q=0, gzip", "gzip"},
		{"identity;q=0", "identity"},
		{"identity;q=0, br", "br"},
		{"identity", "identity"},
		{"*;q=0", "identity"},
		{"*", "br"},
		{"gzip;q=0, *", "br"},
		{"br;q=0, *;q=0", "identity"},
		{"br;q=0, *", "gzip"},
		{"x-gzip", "gzip"},
		{"BR;Q=1.0", "br"},
		{"br;q=0.000, gzip;q=0", "identity"},
		{"deflate", "identity"},
		{"br;q=0.5, gzip;q=1", "br"},
		{" gzip ; q=0.8 , br ; q=0 ", "gzip"},
		{"compress, zstd", "identity"},
	}
	for _, tc := range cases {
		if got := pick(brSmaller, "Accept-Encoding", tc.accept); got != tc.want {
			t.Errorf("Accept-Encoding %q -> %s, want %s", tc.accept, got, tc.want)
		}
	}
	if got := pick(brSmaller); got != "identity" {
		t.Errorf("no Accept-Encoding -> %s, want identity", got)
	}
	if got := pick(entry(large, small), "Accept-Encoding", "br, gzip"); got != "gzip" {
		t.Errorf("smaller gzip variant -> %s, want gzip", got)
	}
	if got := pick(entry(small, nil), "Accept-Encoding", "gzip"); got != "identity" {
		t.Errorf("missing gzip variant -> %s, want identity", got)
	}
	if got := pick(brSmaller, "Accept-Encoding", "br", "Range", "bytes=0-1"); got != "identity" {
		t.Errorf("Range request -> %s, want identity", got)
	}
}

func TestPerfCoreStaticCompressibleTypes(t *testing.T) {
	for _, name := range []string{"a.html", "a.css", "a.js", "a.mjs", "a.json", "a.xml", "a.txt", "a.csv", "a.svg", "a.ico", "a.ttf", "a.otf", "a.wasm", "a.yaml", "a.md"} {
		if !staticCompressibleType(detectMIME(name)) {
			t.Errorf("%s (%s) must be compressible", name, detectMIME(name))
		}
	}
	for _, name := range []string{"a.png", "a.jpg", "a.gif", "a.webp", "a.avif", "a.mp4", "a.webm", "a.mp3", "a.ogg", "a.wav", "a.woff", "a.woff2", "a.pdf", "a.zip", "a.gz", "a.tar", "a.bin", "noext"} {
		if staticCompressibleType(detectMIME(name)) {
			t.Errorf("%s (%s) must not be compressed", name, detectMIME(name))
		}
	}
}

func TestPerfCoreStaticCompressedVariantSemantics(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	content := perfCoreStaticText(64 << 10)
	perfCoreWriteStatic(t, filepath.Join(root, "app.js"), content)
	perfCoreWriteStatic(t, filepath.Join(root, "pic.png"), perfCoreStaticText(4096))
	perfCoreWriteStatic(t, filepath.Join(root, "tiny.txt"), []byte("tiny"))
	handler, _ := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: perfCoreStaticLongTTL})

	identity := perfCoreStaticGet(handler, "/app.js")
	etag := perfCoreStaticHeader(identity, "ETag")
	if identity.StatusCode != 200 || !bytes.Equal(identity.GetBody(), content) || perfCoreStaticHeader(identity, "Vary") != "Accept-Encoding" || perfCoreStaticHeader(identity, "Content-Encoding") != "" || etag == "" {
		t.Fatalf("identity = %d vary=%q ce=%q etag=%q", identity.StatusCode, perfCoreStaticHeader(identity, "Vary"), perfCoreStaticHeader(identity, "Content-Encoding"), etag)
	}
	brotliResp := perfCoreStaticAwaitVariant(t, handler, "/app.js", perfCoreStaticAE)
	brotliTag := perfCoreStaticVariantETag(etag, "-br")
	if perfCoreStaticHeader(brotliResp, "Content-Encoding") != "br" || perfCoreStaticHeader(brotliResp, "ETag") != brotliTag || perfCoreStaticHeader(brotliResp, "Vary") != "Accept-Encoding" {
		t.Fatalf("br variant headers %v", brotliResp.Headers)
	}
	if brotliResp.BodyLen() >= len(content) || !bytes.Equal(perfCoreStaticDecode(t, "br", brotliResp.GetBody()), content) {
		t.Fatalf("br variant len %d does not decode to the file", brotliResp.BodyLen())
	}
	gzipResp := perfCoreStaticGet(handler, "/app.js", "Accept-Encoding", "gzip")
	gzipTag := perfCoreStaticVariantETag(etag, "-gz")
	if perfCoreStaticHeader(gzipResp, "Content-Encoding") != "gzip" || perfCoreStaticHeader(gzipResp, "ETag") != gzipTag || !bytes.Equal(perfCoreStaticDecode(t, "gzip", gzipResp.GetBody()), content) {
		t.Fatalf("gzip variant headers %v", gzipResp.Headers)
	}

	notModified := perfCoreStaticGet(handler, "/app.js", "Accept-Encoding", perfCoreStaticAE, "If-None-Match", brotliTag)
	if notModified.StatusCode != 304 || perfCoreStaticHeader(notModified, "ETag") != brotliTag || perfCoreStaticHeader(notModified, "Vary") != "Accept-Encoding" {
		t.Fatalf("If-None-Match br tag = %d %v", notModified.StatusCode, notModified.Headers)
	}
	if got := perfCoreStaticGet(handler, "/app.js", "Accept-Encoding", "gzip", "If-None-Match", brotliTag); got.StatusCode != 200 || perfCoreStaticHeader(got, "ETag") != gzipTag {
		t.Fatalf("br tag with a gzip-only client = %d etag %q, want 200 gzip", got.StatusCode, perfCoreStaticHeader(got, "ETag"))
	}
	if got := perfCoreStaticGet(handler, "/app.js", "Accept-Encoding", "br", "If-None-Match", etag); got.StatusCode != 200 || perfCoreStaticHeader(got, "Content-Encoding") != "br" {
		t.Fatalf("identity tag with a br client = %d, want 200 br", got.StatusCode)
	}
	if got := perfCoreStaticGet(handler, "/app.js", "If-None-Match", etag); got.StatusCode != 304 || perfCoreStaticHeader(got, "Vary") != "Accept-Encoding" {
		t.Fatalf("identity tag without Accept-Encoding = %d", got.StatusCode)
	}
	if got := perfCoreStaticGet(handler, "/app.js", "Accept-Encoding", "br", "If-Match", `"other"`); got.StatusCode != 412 {
		t.Fatalf("If-Match mismatch on a variant = %d, want 412", got.StatusCode)
	}

	ranged := perfCoreStaticGet(handler, "/app.js", "Accept-Encoding", perfCoreStaticAE, "Range", "bytes=10-19")
	if ranged.StatusCode != 206 || perfCoreStaticHeader(ranged, "Content-Encoding") != "" || !bytes.Equal(ranged.GetBody(), content[10:20]) ||
		perfCoreStaticHeader(ranged, "Content-Range") != "bytes 10-19/"+strconv.Itoa(len(content)) || perfCoreStaticHeader(ranged, "ETag") != etag || perfCoreStaticHeader(ranged, "Vary") != "Accept-Encoding" {
		t.Fatalf("Range on a compressible file = %d %v", ranged.StatusCode, ranged.Headers)
	}
	ifRange := perfCoreStaticGet(handler, "/app.js", "Accept-Encoding", perfCoreStaticAE, "Range", "bytes=10-19", "If-Range", brotliTag)
	if ifRange.StatusCode != 200 || perfCoreStaticHeader(ifRange, "Content-Encoding") != "" || !bytes.Equal(ifRange.GetBody(), content) {
		t.Fatalf("If-Range with the br tag = %d, want the full identity file", ifRange.StatusCode)
	}

	head := &Request{Method: "HEAD", Path: "/app.js", Headers: [][2]string{{"Accept-Encoding", "br"}}}
	headResp := &Response{}
	headResp.Reset()
	headResp.lazyReq = head
	handler(head, headResp)
	if headResp.StatusCode != 200 || perfCoreStaticHeader(headResp, "Content-Encoding") != "br" || headResp.headerContentLength() != brotliResp.BodyLen() || headResp.transmittedBodyLen() != 0 {
		t.Fatalf("HEAD br = %d ce=%q content-length %d (want %d) transmitted %d", headResp.StatusCode, perfCoreStaticHeader(headResp, "Content-Encoding"), headResp.headerContentLength(), brotliResp.BodyLen(), headResp.transmittedBodyLen())
	}

	for _, path := range []string{"/pic.png", "/tiny.txt"} {
		for i := 0; i < 3; i++ {
			got := perfCoreStaticGet(handler, path, "Accept-Encoding", perfCoreStaticAE)
			if got.StatusCode != 200 || perfCoreStaticHeader(got, "Content-Encoding") != "" || perfCoreStaticHeader(got, "Vary") != "" {
				t.Fatalf("%s must stay uncompressed without Vary: %d %v", path, got.StatusCode, got.Headers)
			}
		}
	}
}

func TestPerfCoreStaticCompressSingleFlight(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	content := perfCoreStaticText(128 << 10)
	perfCoreWriteStatic(t, filepath.Join(root, "bundle.js"), content)
	handler, cache := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: perfCoreStaticLongTTL})
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan string, perfCoreStaticFirstWave)
	for i := 0; i < perfCoreStaticFirstWave; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for r := 0; r < perfCoreStaticWaveRepeats; r++ {
				got := perfCoreStaticGet(handler, "/bundle.js", "Accept-Encoding", perfCoreStaticAE)
				if got.StatusCode != 200 {
					errs <- fmt.Sprintf("status %d", got.StatusCode)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	got := perfCoreStaticAwaitVariant(t, handler, "/bundle.js", perfCoreStaticAE)
	if !bytes.Equal(perfCoreStaticDecode(t, perfCoreStaticHeader(got, "Content-Encoding"), got.GetBody()), content) {
		t.Fatal("variant does not decode to the file")
	}
	for i := 0; i < perfCoreStaticFirstWave; i++ {
		perfCoreStaticGet(handler, "/bundle.js", "Accept-Encoding", "gzip")
	}
	if builds := cache.builds.Load(); builds != 1 {
		t.Fatalf("variants built %d times for one file version, want 1", builds)
	}
}

func perfCoreStaticAccounted(cache *staticFileCache) int64 {
	var sum int64
	cache.entries.Range(func(_ string, e *staticCacheEntry) bool {
		sum += e.cost
		return true
	})
	cache.variantSlots.Range(func(_ string, slot *staticVariantSlot) bool {
		if v := slot.state.Load(); v != nil {
			sum += v.cost
		}
		return true
	})
	return sum
}

func TestPerfCoreStaticCompressBudgetAndInvalidation(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	file := filepath.Join(root, "site.css")
	v1 := perfCoreStaticText(8 << 10)
	perfCoreWriteStatic(t, file, v1)

	tight := staticCacheEntryCost("site.css", int64(len(v1))) + staticVariantOverhead/2
	starved, starvedCache := newStaticHandler("/", StaticConfig{Root: root, CacheMaxBytes: tight, CacheMaxFileSize: tight, CacheTTL: perfCoreStaticLongTTL})
	perfCoreStaticGet(starved, "/site.css", "Accept-Encoding", "br")
	e, ok := starvedCache.entries.Load("site.css")
	if !ok {
		t.Fatal("entry not cached under the tight budget")
	}
	perfCoreStaticPollWithin(t, "the variant build to finish", perfCoreStaticCompressCeiling, func() bool {
		slot, ok := starvedCache.variantSlots.Load("site.css")
		return ok && slot.state.Load() == staticVariantsNone
	})
	for i := 0; i < 8; i++ {
		got := perfCoreStaticGet(starved, "/site.css", "Accept-Encoding", "br")
		if got.StatusCode != 200 || perfCoreStaticHeader(got, "Content-Encoding") != "" || !bytes.Equal(got.GetBody(), v1) {
			t.Fatalf("over-budget variants must not be served: %d %v", got.StatusCode, got.Headers)
		}
	}
	if builds, used := starvedCache.builds.Load(), starvedCache.bytes.Load(); builds != 1 || used != e.cost || used > tight {
		t.Fatalf("over budget: builds %d (want 1), bytes %d (want %d, cap %d)", builds, used, e.cost, tight)
	}

	handler, cache := newStaticHandler("/", StaticConfig{Root: root, CacheTTL: perfCoreStaticTinyTTL})
	first := perfCoreStaticAwaitVariant(t, handler, "/site.css", "br")
	if !bytes.Equal(perfCoreStaticDecode(t, "br", first.GetBody()), v1) {
		t.Fatal("v1 variant does not decode")
	}
	if used, sum := cache.bytes.Load(), perfCoreStaticAccounted(cache); used != sum || used <= staticCacheEntryCost("site.css", int64(len(v1))) {
		t.Fatalf("bytes %d, entries+variants %d; the variant must be counted", used, sum)
	}
	v2 := perfCoreStaticText(9 << 10)
	v2[0] = 'X'
	perfCoreWriteStatic(t, file, v2)
	perfCoreStaticPollWithin(t, "a new variant for the new file version", perfCoreStaticCompressCeiling, func() bool {
		got := perfCoreStaticGet(handler, "/site.css", "Accept-Encoding", "br")
		return perfCoreStaticHeader(got, "Content-Encoding") == "br" && bytes.Equal(perfCoreStaticDecode(t, "br", got.GetBody()), v2)
	})
	if got := perfCoreStaticGet(handler, "/site.css", "Accept-Encoding", "br"); perfCoreStaticHeader(got, "ETag") == perfCoreStaticHeader(first, "ETag") {
		t.Fatal("a new file version must get a new variant ETag")
	}
	if used, sum := cache.bytes.Load(), perfCoreStaticAccounted(cache); used != sum || cache.entries.Len() != 1 {
		t.Fatalf("after invalidation bytes %d, entries+variants %d, entries %d", used, sum, cache.entries.Len())
	}
	if builds := cache.builds.Load(); builds != 2 {
		t.Fatalf("builds = %d, want one per file version (2)", builds)
	}
}

func TestPerfCoreStaticDisableCompression(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	content := perfCoreStaticText(16 << 10)
	perfCoreWriteStatic(t, filepath.Join(root, "app.js"), content)
	for _, cfg := range []StaticConfig{
		{Root: root, DisableCompression: true, CacheTTL: perfCoreStaticLongTTL},
		{Root: root, DisableCache: true},
	} {
		handler, cache := newStaticHandler("/", cfg)
		if cache != nil && cache.compressQueue != nil {
			t.Fatalf("%+v: compression must be off", cfg)
		}
		for i := 0; i < 6; i++ {
			got := perfCoreStaticGet(handler, "/app.js", "Accept-Encoding", perfCoreStaticAE)
			if got.StatusCode != 200 || perfCoreStaticHeader(got, "Content-Encoding") != "" || perfCoreStaticHeader(got, "Vary") != "" || !bytes.Equal(got.GetBody(), content) {
				t.Fatalf("%+v request %d: %d %v", cfg, i, got.StatusCode, got.Headers)
			}
		}
		if cache != nil && cache.builds.Load() != 0 {
			t.Fatalf("%+v: %d variant builds with compression disabled", cfg, cache.builds.Load())
		}
	}
}

func perfCoreStaticWireHead(t *testing.T, ts *testServer, path, accept string) *http.Response {
	t.Helper()
	c := ts.dial(t)
	raw := "HEAD " + path + " HTTP/1.1\r\nHost: " + ts.addr + "\r\n"
	if accept != "" {
		raw += "Accept-Encoding: " + accept + "\r\n"
	}
	if _, err := io.WriteString(c, raw+"\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, body := readH1Response(t, bufio.NewReader(c), "HEAD")
	if len(body) != 0 {
		t.Fatalf("HEAD %s returned %d body bytes", path, len(body))
	}
	return resp
}

func TestPerfCoreStaticCompressedOverTheWire(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	files := map[string][]byte{
		"big.js":  perfCoreStaticText(300 << 10),
		"page.js": perfCoreStaticText(40 << 10),
	}
	for name, data := range files {
		perfCoreWriteStatic(t, filepath.Join(root, name), data)
	}
	ts := newTestServer(t, testServerOptions{Routes: func(r *Router) {
		r.GET("/s/*filepath", Static("/s", StaticConfig{Root: root, CacheTTL: perfCoreStaticLongTTL}))
	}})
	h1 := &http.Client{Transport: &http.Transport{DisableCompression: true}, Timeout: harnessIOTimeout}
	h2cTransport := &http.Transport{Protocols: new(http.Protocols), DisableCompression: true}
	h2cTransport.Protocols.SetUnencryptedHTTP2(true)
	h2c := &http.Client{Transport: h2cTransport, Timeout: harnessIOTimeout}
	t.Cleanup(h1.CloseIdleConnections)
	t.Cleanup(h2c.CloseIdleConnections)

	fetch := func(client *http.Client, path, accept string) (*http.Response, []byte) {
		req, err := http.NewRequest(http.MethodGet, ts.url(path), nil)
		if err != nil {
			t.Fatal(err)
		}
		if accept != "" {
			req.Header.Set("Accept-Encoding", accept)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return resp, body
	}
	for name, data := range files {
		path := "/s/" + name
		var wire []byte
		perfCoreStaticPollWithin(t, "wire variant of "+name, perfCoreStaticCompressCeiling, func() bool {
			resp, body := fetch(h1, path, "br")
			if resp.StatusCode != 200 || resp.Header.Get("Vary") != "Accept-Encoding" {
				t.Fatalf("%s: %d vary %q", name, resp.StatusCode, resp.Header.Get("Vary"))
			}
			wire = body
			return resp.Header.Get("Content-Encoding") == "br"
		})
		if !bytes.Equal(perfCoreStaticDecode(t, "br", wire), data) {
			t.Fatalf("%s br over h1 does not decode", name)
		}
		for _, client := range []*http.Client{h1, h2c} {
			resp, body := fetch(client, path, "gzip")
			if resp.Header.Get("Content-Encoding") != "gzip" || resp.ContentLength != int64(len(body)) || !bytes.Equal(perfCoreStaticDecode(t, "gzip", body), data) {
				t.Fatalf("%s gzip proto %d: ce=%q length %d body %d", name, resp.ProtoMajor, resp.Header.Get("Content-Encoding"), resp.ContentLength, len(body))
			}
			resp, body = fetch(client, path, "")
			if resp.Header.Get("Content-Encoding") != "" || !bytes.Equal(body, data) || resp.Header.Get("Vary") != "Accept-Encoding" {
				t.Fatalf("%s identity proto %d: ce=%q len %d", name, resp.ProtoMajor, resp.Header.Get("Content-Encoding"), len(body))
			}
		}
		head := perfCoreStaticWireHead(t, ts, path, "br")
		if head.StatusCode != 200 || head.Header.Get("Content-Encoding") != "br" || head.ContentLength != int64(len(wire)) {
			t.Fatalf("HEAD %s br = %d ce=%q length %d want %d", name, head.StatusCode, head.Header.Get("Content-Encoding"), head.ContentLength, len(wire))
		}
		head = perfCoreStaticWireHead(t, ts, path, "")
		if head.StatusCode != 200 || head.Header.Get("Content-Encoding") != "" || head.ContentLength != int64(len(data)) || head.Header.Get("Vary") != "Accept-Encoding" {
			t.Fatalf("HEAD %s identity = %d length %d want %d vary %q", name, head.StatusCode, head.ContentLength, len(data), head.Header.Get("Vary"))
		}
	}
	resp, body := fetch(h1, "/s/big.js", "")
	if resp.StatusCode != 200 || !bytes.Equal(body, files["big.js"]) {
		t.Fatal("identity sendfile path broken after compression")
	}
}

func TestPerfCoreCacheCompressSingleFlight(t *testing.T) {
	const misses = 8
	body := string(perfCoreStaticText(64 << 10))
	rc := NewResponseCache(CacheConfig{TTL: perfCoreStaticLongTTL, Brotli: true, BrotliLevel: 11, Gzip: true, GzipLevel: 9})
	t.Cleanup(rc.Stop)
	var inHandler sync.WaitGroup
	inHandler.Add(misses)
	release := make(chan struct{})
	next := func(req *Request, resp *Response) {
		inHandler.Done()
		<-release
		resp.Status(200).SetHeader("Content-Type", "text/plain; charset=utf-8")
		resp.ContentType = "text/plain; charset=utf-8"
		resp.String(body)
	}
	var done sync.WaitGroup
	results := make([]*Response, misses)
	for i := 0; i < misses; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			req := &Request{Method: "GET", Path: "/bundle.txt", Host: "example.test", Headers: [][2]string{{"Accept-Encoding", perfCoreStaticAE}}}
			resp := &Response{}
			resp.Reset()
			resp.lazyReq = req
			rc.handle(next, req, resp)
			results[i] = resp
		}(i)
	}
	waited := make(chan struct{})
	go func() { inHandler.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-turbo.After(perfCoreStaticPollCeiling):
		t.Fatal("concurrent misses never reached the handler together")
	}
	close(release)
	done.Wait()
	if builds := rc.builds.Load(); builds != 1 {
		t.Fatalf("%d concurrent misses compressed %d times, want 1", misses, builds)
	}
	for i, resp := range results {
		ce, _ := respHeader(resp, "Content-Encoding")
		if string(perfCoreStaticDecode(t, ce, resp.GetBody())) != body {
			t.Fatalf("response %d (%q) does not decode to the body", i, ce)
		}
	}
	hit := &Request{Method: "GET", Path: "/bundle.txt", Host: "example.test", Headers: [][2]string{{"Accept-Encoding", "br"}}}
	hitResp := &Response{}
	hitResp.Reset()
	hitResp.lazyReq = hit
	rc.handle(func(*Request, *Response) { t.Fatal("hit must not reach the handler") }, hit, hitResp)
	if ce, _ := respHeader(hitResp, "Content-Encoding"); ce != "br" || string(perfCoreStaticDecode(t, "br", hitResp.GetBody())) != body {
		t.Fatalf("cached br hit ce=%q", ce)
	}
}

func TestPerfCoreCompressOnceWindowFitsBody(t *testing.T) {
	for _, n := range []int{300, 70 << 10, 300 << 10, 5 << 20} {
		body := perfCoreStaticText(n)
		for _, level := range []int{4, 11} {
			if n > staticCompressLargeSize && level == 11 {
				continue
			}
			out := compressOnce(body, encodingBrotli, level)
			if out == nil || len(out) >= n || !bytes.Equal(perfCoreStaticDecode(t, "br", out), body) {
				t.Fatalf("brotli q%d of %d bytes: %d bytes, round-trip failed", level, n, len(out))
			}
		}
		if out := compressOnce(body, encodingGzip, staticGzipLevel); out == nil || !bytes.Equal(perfCoreStaticDecode(t, "gzip", out), body) {
			t.Fatalf("gzip of %d bytes failed", n)
		}
	}
	if out := compressOnce(serveContentPattern(4096), encodingBrotli, staticBrotliLevel); len(out) >= 4096 {
		t.Fatalf("an incompressible body must not yield a larger variant (%d bytes)", len(out))
	}
}
