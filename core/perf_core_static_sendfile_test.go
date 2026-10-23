//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	perfCoreSendfileSize  = 4<<20 + 333
	perfCoreSendfilePause = 150 * time.Millisecond
)

func TestPerfCoreStaticSendfileSlowReaderKeepAlive(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		for _, disableCache := range []bool{false, true} {
			t.Run("tls="+strconv.FormatBool(useTLS)+"/nocache="+strconv.FormatBool(disableCache), func(t *testing.T) { perfCoreStaticSlowReader(t, useTLS, disableCache) })
		}
	}
}

func perfCoreStaticSlowReader(t *testing.T, useTLS, disableCache bool) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	content := serveContentPattern(perfCoreSendfileSize)
	perfCoreWriteStatic(t, filepath.Join(root, "big.bin"), content)
	var cache *staticFileCache
	ts := newTestServer(t, testServerOptions{TLS: useTLS, Routes: func(r *Router) {
		h, c := newStaticHandler("/s", StaticConfig{Root: root, CacheMaxFileSize: staticCacheEvictingFileSize, DisableCache: disableCache})
		cache = c
		r.GET("/s/*filepath", h)
	}})
	c := ts.dialRecvBuf(t, 16<<10)
	br := bufio.NewReaderSize(c, 4<<10)
	host := "Host: " + ts.domain + "\r\n"
	writeAll(t, c, "GET /s/big.bin HTTP/1.1\r\n"+host+"\r\n")
	time.Sleep(perfCoreSendfilePause)
	_ = c.SetDeadline(wallDeadline(harnessIOTimeout))
	resp, body := readH1Response(t, br, http.MethodGet)
	if resp.StatusCode != 200 || !bytes.Equal(body, content) {
		t.Fatalf("slow reader: status %d len %d equal=%v", resp.StatusCode, len(body), bytes.Equal(body, content))
	}
	if resp.Header.Get("Content-Length") != strconv.Itoa(perfCoreSendfileSize) || resp.Header.Get("Date") == "" {
		t.Fatalf("headers: %v", resp.Header)
	}
	writeAll(t, c, "GET /s/big.bin HTTP/1.1\r\n"+host+"Range: bytes=1000-1999\r\n\r\n"+
		"HEAD /s/big.bin HTTP/1.1\r\n"+host+"\r\n"+
		"GET /s/big.bin HTTP/1.1\r\n"+host+"Range: bytes=-5\r\n\r\n")
	part, partBody := readH1Response(t, br, http.MethodGet)
	if part.StatusCode != 206 || !bytes.Equal(partBody, content[1000:2000]) {
		t.Fatalf("pipelined range: %d len %d", part.StatusCode, len(partBody))
	}
	head, headBody := readH1Response(t, br, http.MethodHead)
	if head.StatusCode != 200 || len(headBody) != 0 || head.Header.Get("Content-Length") != strconv.Itoa(perfCoreSendfileSize) {
		t.Fatalf("head: %d len %d cl %q", head.StatusCode, len(headBody), head.Header.Get("Content-Length"))
	}
	tail, tailBody := readH1Response(t, br, http.MethodGet)
	if tail.StatusCode != 206 || !bytes.Equal(tailBody, content[len(content)-5:]) {
		t.Fatalf("suffix range: %d %q", tail.StatusCode, tailBody)
	}
	if cache == nil {
		return
	}
	cache.entries.Range(func(rel string, e *staticCacheEntry) bool {
		if e.data != nil {
			t.Fatalf("a file above CacheMaxFileSize was cached in memory (%s)", rel)
		}
		return true
	})
}

func TestPerfCoreStaticLargeFileOverTLS(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	content := serveContentPattern(1<<20 + 5)
	perfCoreWriteStatic(t, filepath.Join(root, "big.bin"), content)
	ts := newTestServer(t, testServerOptions{TLS: true, Routes: func(r *Router) {
		r.GET("/s/*filepath", Static("/s", StaticConfig{Root: root}))
	}})
	for _, alpn := range []string{"http/1.1", "h2"} {
		if err := perfCoreStaticFetch(ts.client(t, alpn), ts.url("/s/big.bin"), content, map[string]int{"http/1.1": 1, "h2": 2}[alpn]); err != nil {
			t.Fatalf("%s: %v", alpn, err)
		}
	}
}

func TestPerfCoreStaticSendfileClientGoneMidBody(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run("tls="+strconv.FormatBool(useTLS), func(t *testing.T) { perfCoreStaticClientGone(t, useTLS) })
	}
}

func perfCoreStaticClientGone(t *testing.T, useTLS bool) {
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	content := serveContentPattern(perfCoreSendfileSize)
	perfCoreWriteStatic(t, filepath.Join(root, "big.bin"), content)
	ts := newTestServer(t, testServerOptions{TLS: useTLS, Routes: func(r *Router) {
		r.GET("/s/*filepath", Static("/s", StaticConfig{Root: root}))
	}})
	for i := 0; i < 4; i++ {
		c := ts.dial(t)
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.SetReadBuffer(16 << 10)
		}
		writeAll(t, c, "GET /s/big.bin HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n")
		buf := make([]byte, 32<<10)
		if _, err := c.Read(buf); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	got := ts.dial(t)
	writeAll(t, got, "GET /s/big.bin HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n")
	resp, body := readH1Response(t, bufio.NewReader(got), http.MethodGet)
	if resp.StatusCode != 200 || !bytes.Equal(body, content) {
		t.Fatalf("after aborted transfers: %d len %d", resp.StatusCode, len(body))
	}
}
