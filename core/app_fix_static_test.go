//go:build linux && amd64

package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func appFixServeStatic(handler HandlerFunc, path string) (int, string) {
	req := &Request{Method: "GET", Path: path}
	resp := &Response{}
	resp.Reset()
	handler(req, resp)
	return resp.StatusCode, string(resp.GetBody())
}

func appFixSymlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func TestAppFixStaticServesThroughSymlinkedRoot(t *testing.T) {
	base := t.TempDir()
	release := filepath.Join(base, "releases", "123")
	if err := os.MkdirAll(release, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "index.html"), []byte("release-123"), 0o644); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(base, "current")
	appFixSymlinkOrSkip(t, release, current)
	handler := Static("/", StaticConfig{Root: current})
	if status, body := appFixServeStatic(handler, "/index.html"); status != 200 || body != "release-123" {
		t.Fatalf("file under a symlinked Root got %d %q, want 200", status, body)
	}
}

func TestAppFixStaticRefusesEscapingIndexAndLoops(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "site")
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(base, "secret.txt")
	if err := os.WriteFile(secret, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	appFixSymlinkOrSkip(t, secret, filepath.Join(root, "docs", "index.html"))
	appFixSymlinkOrSkip(t, "loop", filepath.Join(root, "loop"))
	handler := Static("/", StaticConfig{Root: root})
	if status, body := appFixServeStatic(handler, "/docs/"); status == 200 || strings.Contains(body, "SECRET") {
		t.Fatalf("directory index symlinked outside Root was served: %d %q", status, body)
	}
	if status, _ := appFixServeStatic(handler, "/loop"); status != 403 {
		t.Fatalf("symlink loop got %d, want 403", status)
	}
}

func TestAppFixStaticBrowseHidesRefusedDotfiles(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".env", "visible.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{".git", ".well-known"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	status, body := appFixServeStatic(Static("/", StaticConfig{Root: root, Browse: true}), "/")
	if status != 200 || !strings.Contains(body, "visible.txt") || !strings.Contains(body, ".well-known/") {
		t.Fatalf("listing got %d %q", status, body)
	}
	if strings.Contains(body, ".env") || strings.Contains(body, ".git/") {
		t.Fatalf("listing discloses dotfiles that are never served: %q", body)
	}
}
