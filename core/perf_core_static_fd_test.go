//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	perfCoreFDMidSize   = 64<<10 + 3
	perfCoreFDBigSize   = 4<<20 + 333
	perfCoreFDSmallSize = 1000
)

type perfCoreFDRig struct {
	ts    *testServer
	cache *staticFileCache
	root  string
	mid   []byte
	big   []byte
}

func newPerfCoreFDRig(t *testing.T, ttl time.Duration) *perfCoreFDRig {
	t.Helper()
	perfCoreSettleStaticFiles(t)
	rig := &perfCoreFDRig{root: t.TempDir(), mid: serveContentPattern(perfCoreFDMidSize), big: serveContentPattern(perfCoreFDBigSize)}
	perfCoreWriteStatic(t, filepath.Join(rig.root, "mid.bin"), rig.mid)
	perfCoreWriteStatic(t, filepath.Join(rig.root, "big.bin"), rig.big)
	perfCoreWriteStatic(t, filepath.Join(rig.root, "small.txt"), serveContentPattern(perfCoreFDSmallSize))
	rig.ts = newTestServer(t, testServerOptions{Routes: func(r *Router) {
		h, c := newStaticHandler("/s", StaticConfig{Root: rig.root, CacheTTL: ttl})
		rig.cache = c
		r.GET("/s/*filepath", h)
		r.HEAD("/s/*filepath", h)
	}})
	return rig
}

func (rig *perfCoreFDRig) conn(t *testing.T) (net.Conn, *bufio.Reader) {
	c := rig.ts.dial(t)
	return c, bufio.NewReader(c)
}

func (rig *perfCoreFDRig) get(t *testing.T, c net.Conn, br *bufio.Reader, path string, extra string) (*http.Response, []byte) {
	t.Helper()
	writeAll(t, c, "GET "+path+" HTTP/1.1\r\nHost: "+rig.ts.domain+"\r\n"+extra+"\r\n")
	return readH1Response(t, br, http.MethodGet)
}

func (rig *perfCoreFDRig) entry(t *testing.T, rel string) *staticCacheEntry {
	t.Helper()
	e, ok := rig.cache.entries.Load(rel)
	if !ok {
		t.Fatalf("%s not cached", rel)
	}
	return e
}

func perfCoreFDLive(e *staticCacheEntry) *staticFD {
	h := e.fd.Load()
	if h == nil || h == staticFDRetired {
		return nil
	}
	return h
}

func TestPerfCoreStaticFDServesFromCachedDescriptor(t *testing.T) {
	rig := newPerfCoreFDRig(t, perfCoreStaticLongTTL)
	c, br := rig.conn(t)
	for round := 0; round < 3; round++ {
		for _, f := range []struct {
			path string
			want []byte
		}{{"/s/mid.bin", rig.mid}, {"/s/big.bin", rig.big}} {
			resp, body := rig.get(t, c, br, f.path, "")
			if resp.StatusCode != 200 || !bytes.Equal(body, f.want) || resp.Header.Get("Content-Length") != strconv.Itoa(len(f.want)) {
				t.Fatalf("round %d %s: %d len %d", round, f.path, resp.StatusCode, len(body))
			}
			if resp.Header.Get("ETag") == "" || resp.Header.Get("Last-Modified") == "" || resp.Header.Get("Accept-Ranges") != "bytes" || resp.Header.Get("Date") == "" {
				t.Fatalf("headers: %v", resp.Header)
			}
		}
	}
	mid, big := rig.entry(t, "mid.bin"), rig.entry(t, "big.bin")
	if mid.data == nil || perfCoreFDLive(mid) == nil {
		t.Fatal("mid entry must hold data and a descriptor")
	}
	if big.data != nil || perfCoreFDLive(big) == nil {
		t.Fatal("big entry on plain h1 must hold only a descriptor")
	}
	if rig.cache.fds.Load() != 2 {
		t.Fatalf("fds %d, want 2", rig.cache.fds.Load())
	}
	etag := mid.validators.etag
	writeAll(t, c, "GET /s/big.bin HTTP/1.1\r\nHost: "+rig.ts.domain+"\r\nRange: bytes=1000-1999\r\n\r\n"+
		"HEAD /s/big.bin HTTP/1.1\r\nHost: "+rig.ts.domain+"\r\n\r\n"+
		"GET /s/mid.bin HTTP/1.1\r\nHost: "+rig.ts.domain+"\r\nIf-None-Match: "+etag+"\r\n\r\n"+
		"GET /s/big.bin HTTP/1.1\r\nHost: "+rig.ts.domain+"\r\nRange: bytes=-5\r\n\r\n"+
		"GET /s/mid.bin HTTP/1.1\r\nHost: "+rig.ts.domain+"\r\nRange: bytes=99999999-\r\n\r\n"+
		"GET /s/small.txt HTTP/1.1\r\nHost: "+rig.ts.domain+"\r\n\r\n")
	if part, body := readH1Response(t, br, http.MethodGet); part.StatusCode != 206 || !bytes.Equal(body, rig.big[1000:2000]) {
		t.Fatalf("range: %d len %d", part.StatusCode, len(body))
	}
	if head, body := readH1Response(t, br, http.MethodHead); head.StatusCode != 200 || len(body) != 0 || head.Header.Get("Content-Length") != strconv.Itoa(perfCoreFDBigSize) {
		t.Fatalf("head: %d len %d", head.StatusCode, len(body))
	}
	if nm, body := readH1Response(t, br, http.MethodGet); nm.StatusCode != 304 || len(body) != 0 {
		t.Fatalf("if-none-match: %d len %d", nm.StatusCode, len(body))
	}
	if tail, body := readH1Response(t, br, http.MethodGet); tail.StatusCode != 206 || !bytes.Equal(body, rig.big[len(rig.big)-5:]) {
		t.Fatalf("suffix range: %d %q", tail.StatusCode, body)
	}
	if bad, _ := readH1Response(t, br, http.MethodGet); bad.StatusCode != 416 {
		t.Fatalf("unsatisfiable range: %d", bad.StatusCode)
	}
	if small, body := readH1Response(t, br, http.MethodGet); small.StatusCode != 200 || len(body) != perfCoreFDSmallSize {
		t.Fatalf("small: %d len %d", small.StatusCode, len(body))
	}
	if perfCoreFDLive(rig.entry(t, "small.txt")) != nil {
		t.Fatal("a file below the sendfile threshold must not hold a descriptor")
	}
}

func TestPerfCoreStaticFDRevalidatesAfterTTL(t *testing.T) {
	rig := newPerfCoreFDRig(t, perfCoreStaticTinyTTL)
	c, br := rig.conn(t)
	if resp, body := rig.get(t, c, br, "/s/big.bin", ""); resp.StatusCode != 200 || !bytes.Equal(body, rig.big) {
		t.Fatalf("first: %d len %d", resp.StatusCode, len(body))
	}
	first := rig.entry(t, "big.bin")
	old := perfCoreFDLive(first)
	if old == nil {
		t.Fatal("no descriptor cached")
	}
	perfCoreStaticPoll(t, "the TTL to lapse", func() bool { return turbo.Now() >= first.freshUntil.Load() })
	if resp, body := rig.get(t, c, br, "/s/big.bin", ""); resp.StatusCode != 200 || !bytes.Equal(body, rig.big) {
		t.Fatalf("unchanged after TTL: %d len %d", resp.StatusCode, len(body))
	}
	if again := rig.entry(t, "big.bin"); again != first || perfCoreFDLive(again) != old {
		t.Fatal("an unchanged file must keep its entry and descriptor")
	}
	replacement := serveContentPattern(perfCoreFDBigSize / 2)
	tmp := filepath.Join(rig.root, "big.bin.new")
	perfCoreWriteStatic(t, tmp, replacement)
	if err := os.Rename(tmp, filepath.Join(rig.root, "big.bin")); err != nil {
		t.Fatal(err)
	}
	perfCoreStaticPoll(t, "the replacement to be served", func() bool {
		resp, body := rig.get(t, c, br, "/s/big.bin", "")
		return resp.StatusCode == 200 && bytes.Equal(body, replacement)
	})
	if first.fd.Load() != staticFDRetired {
		t.Fatal("replaced entry kept its descriptor")
	}
	perfCoreStaticPoll(t, "the replaced descriptor to close", func() bool { return old.refs.Load() == 0 })
	if rig.cache.fds.Load() != 1 {
		t.Fatalf("fds %d, want 1", rig.cache.fds.Load())
	}
	if err := os.Remove(filepath.Join(rig.root, "big.bin")); err != nil {
		t.Fatal(err)
	}
	perfCoreStaticPoll(t, "the deleted file to 404", func() bool {
		resp, _ := rig.get(t, c, br, "/s/big.bin", "")
		return resp.StatusCode == 404
	})
	perfCoreStaticPoll(t, "the descriptor count to drop", func() bool { return rig.cache.fds.Load() == 0 })
}

func TestPerfCoreStaticFDSurvivesRetireMidBody(t *testing.T) {
	rig := newPerfCoreFDRig(t, perfCoreStaticLongTTL)
	c, br := rig.conn(t)
	if resp, _ := rig.get(t, c, br, "/s/big.bin", ""); resp.StatusCode != 200 {
		t.Fatalf("warm: %d", resp.StatusCode)
	}
	slow := rig.ts.dial(t)
	if tcp, ok := slow.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(16 << 10)
	}
	writeAll(t, slow, "GET /s/big.bin HTTP/1.1\r\nHost: "+rig.ts.domain+"\r\n\r\n")
	time.Sleep(perfCoreSendfilePause)
	e := rig.entry(t, "big.bin")
	h := perfCoreFDLive(e)
	rig.cache.forget("big.bin")
	if e.fd.Load() != staticFDRetired {
		t.Fatal("forget did not retire the descriptor")
	}
	_ = slow.SetDeadline(wallDeadline(harnessIOTimeout))
	resp, body := readH1Response(t, bufio.NewReader(slow), http.MethodGet)
	if resp.StatusCode != 200 || !bytes.Equal(body, rig.big) {
		t.Fatalf("in-flight body after retire: %d len %d", resp.StatusCode, len(body))
	}
	perfCoreStaticPoll(t, "the last reference to close the descriptor", func() bool { return h.refs.Load() == 0 })
	if resp, body := rig.get(t, c, br, "/s/big.bin", ""); resp.StatusCode != 200 || !bytes.Equal(body, rig.big) {
		t.Fatalf("refetch: %d len %d", resp.StatusCode, len(body))
	}
}

func TestPerfCoreStaticFDCapFallsBack(t *testing.T) {
	rig := newPerfCoreFDRig(t, perfCoreStaticLongTTL)
	rig.cache.fds.Store(staticCacheMaxFDs)
	c, br := rig.conn(t)
	for round := 0; round < 2; round++ {
		for _, f := range []struct {
			path string
			want []byte
		}{{"/s/mid.bin", rig.mid}, {"/s/big.bin", rig.big}} {
			if resp, body := rig.get(t, c, br, f.path, ""); resp.StatusCode != 200 || !bytes.Equal(body, f.want) {
				t.Fatalf("at the descriptor cap %s: %d len %d", f.path, resp.StatusCode, len(body))
			}
		}
	}
	if perfCoreFDLive(rig.entry(t, "mid.bin")) != nil || rig.cache.fds.Load() != staticCacheMaxFDs {
		t.Fatalf("a descriptor was cached above the cap (fds %d)", rig.cache.fds.Load())
	}
}

func perfCoreDetachedCacheFD(t *testing.T, root string) *staticFD {
	t.Helper()
	cache := newStaticFileCache(StaticConfig{})
	fd, err := unix.Open(filepath.Join(root, "mid.bin"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	sc := &staticScratch{}
	if err := unix.Fstat(fd, &sc.st); err != nil {
		t.Fatal(err)
	}
	e := cache.lookupOrFill(sc, fd, "mid.bin", false)
	if e == nil {
		t.Fatal("not cached")
	}
	h := cache.attachFD(e, fd)
	if h == nil {
		t.Fatal("descriptor not attached")
	}
	h.release()
	return h
}

func TestPerfCoreStaticFDReleasedWithTheCache(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	perfCoreWriteStatic(t, filepath.Join(root, "mid.bin"), serveContentPattern(perfCoreFDMidSize))
	h := perfCoreDetachedCacheFD(t, root)
	if h.refs.Load() != 1 {
		t.Fatalf("refs %d, want the entry's 1", h.refs.Load())
	}
	perfCoreStaticPoll(t, "an unreachable cache to release its descriptor", func() bool {
		runtime.GC()
		return h.refs.Load() == 0
	})
}
