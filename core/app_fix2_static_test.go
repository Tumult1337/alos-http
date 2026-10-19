//go:build linux && amd64

package core

import (
	"os"
	"path/filepath"
	"testing"
)

func appFix2WriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appFix2RepointSymlink(t *testing.T, target, link string) {
	t.Helper()
	next := link + ".next"
	appFixSymlinkOrSkip(t, target, next)
	if err := os.Rename(next, link); err != nil {
		t.Fatal(err)
	}
}

func TestAppFix2StaticFollowsRepointedRootSymlink(t *testing.T) {
	base := t.TempDir()
	rel1 := filepath.Join(base, "releases", "1")
	rel2 := filepath.Join(base, "releases", "2")
	appFix2WriteFile(t, filepath.Join(rel1, "app.js"), "release-1")
	appFix2WriteFile(t, filepath.Join(rel2, "app.js"), "release-2")
	current := filepath.Join(base, "current")
	appFixSymlinkOrSkip(t, rel1, current)
	handler := Static("/", StaticConfig{Root: current})
	if status, body := appFixServeStatic(handler, "/app.js"); status != 200 || body != "release-1" {
		t.Fatalf("before re-point got %d %q, want 200 release-1", status, body)
	}
	appFix2RepointSymlink(t, rel2, current)
	if status, body := appFixServeStatic(handler, "/app.js"); status != 200 || body != "release-2" {
		t.Fatalf("after re-pointing Root got %d %q, want 200 release-2", status, body)
	}
	if status, body := appFixServeStatic(handler, "/"); status != 404 {
		t.Fatalf("directory without index after re-point got %d %q, want 404", status, body)
	}
}

func TestAppFix2StaticRootCreatedAfterStartUnderSymlinkedParent(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	appFixSymlinkOrSkip(t, realDir, link)
	handler := Static("/", StaticConfig{Root: filepath.Join(link, "site")})
	appFix2WriteFile(t, filepath.Join(realDir, "site", "a.txt"), "late")
	if status, body := appFixServeStatic(handler, "/a.txt"); status != 200 || body != "late" {
		t.Fatalf("Root created after Static() under a symlinked parent got %d %q, want 200 late", status, body)
	}
}

func TestAppFix2StaticStillRefusesEscapeAfterRootRecheck(t *testing.T) {
	base := t.TempDir()
	rel1 := filepath.Join(base, "releases", "1")
	appFix2WriteFile(t, filepath.Join(rel1, "ok.txt"), "ok")
	appFix2WriteFile(t, filepath.Join(base, "secret.txt"), "SECRET")
	appFixSymlinkOrSkip(t, filepath.Join(base, "secret.txt"), filepath.Join(rel1, "leak.txt"))
	current := filepath.Join(base, "current")
	appFixSymlinkOrSkip(t, rel1, current)
	handler := Static("/", StaticConfig{Root: current})
	for i := 0; i < 2; i++ {
		if status, body := appFixServeStatic(handler, "/leak.txt"); status != 403 {
			t.Fatalf("symlink escaping Root got %d %q, want 403", status, body)
		}
		if status, body := appFixServeStatic(handler, "/ok.txt"); status != 200 || body != "ok" {
			t.Fatalf("file inside Root got %d %q, want 200 ok", status, body)
		}
	}
}

func BenchmarkAppFix2StaticServeSmallFile(b *testing.B) {
	root := b.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("console.log(1)"), 0o644); err != nil {
		b.Fatal(err)
	}
	handler := Static("/", StaticConfig{Root: root})
	req := &Request{Method: "GET", Path: "/app.js"}
	resp := &Response{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp.Reset()
		handler(req, resp)
	}
	if resp.StatusCode != 200 {
		b.Fatalf("status %d", resp.StatusCode)
	}
}
