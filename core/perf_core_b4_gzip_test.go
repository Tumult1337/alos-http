//go:build linux && amd64

package core

import "testing"

const b4WantGzipDefault = 2

func TestB4GzipDefaultLevelIsTwo(t *testing.T) {
	if got := normalizeCompressConfig(CompressConfig{}).Level; got != b4WantGzipDefault {
		t.Fatalf("Compress default level %d, want %d", got, b4WantGzipDefault)
	}
	if got := normalizeCompressConfig(CompressConfig{Level: 6}).Level; got != 6 {
		t.Fatalf("explicit level 6 became %d", got)
	}
	if got := DefaultConfig().CompressLevel; got != b4WantGzipDefault {
		t.Fatalf("DefaultConfig CompressLevel %d, want %d", got, b4WantGzipDefault)
	}
	if got := New(Config{}).config.CompressLevel; got != b4WantGzipDefault {
		t.Fatalf("New(Config{}) CompressLevel %d, want %d", got, b4WantGzipDefault)
	}
	if got := New(Config{CompressLevel: 9}).config.CompressLevel; got != 9 {
		t.Fatalf("explicit Config.CompressLevel 9 became %d", got)
	}
	if got := DefaultProxyCacheConfig().CompressLevel; got != b4WantGzipDefault {
		t.Fatalf("DefaultProxyCacheConfig CompressLevel %d, want %d", got, b4WantGzipDefault)
	}
	if got := NewProxyCache(ProxyCacheConfig{}).gzipLevel; got != b4WantGzipDefault {
		t.Fatalf("NewProxyCache default gzip level %d, want %d", got, b4WantGzipDefault)
	}
	rc := NewResponseCache(CacheConfig{})
	defer rc.Stop()
	if got := rc.cfg.GzipLevel; got != b4WantGzipDefault {
		t.Fatalf("NewResponseCache GzipLevel %d, want %d", got, b4WantGzipDefault)
	}
}

func TestB4GzipDefaultPooledZeroAlloc(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates")
	}
	text := perfCoreText16K()
	h := perfCoreCompressHandler(CompressConfig{}, text)
	req := perfCoreCompressReq("gzip")
	resp := perfCoreResp()
	run := func() {
		req.headerCacheMask = 0
		resp.resetFastH1()
		h(req, resp)
	}
	run()
	if got := perfCoreDecode(t, "gzip", resp.GetBody()); string(got) != text {
		t.Fatalf("gzip round trip mismatch (%d bytes)", len(got))
	}
	if allocs := testing.AllocsPerRun(200, run); allocs != 0 {
		t.Fatalf("default gzip response allocates %.1f/op, want 0", allocs)
	}
}
