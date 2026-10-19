//go:build linux && amd64

package core

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestProxyFixProductionCodeAvoidsMathRand(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		f, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == "math/rand" || path == "math/rand/v2" {
				t.Errorf("%s imports %s; non-crypto randomness uses github.com/guno1928/turbo", name, path)
			}
		}
	}
}

const (
	proxyFixRandomBackends = 4
	proxyFixRandomPicks    = 4000
	proxyFixRandomMinShare = proxyFixRandomPicks / proxyFixRandomBackends / 2
)

func TestProxyFixRandomBalancerSpreadsAcrossAvailableBackends(t *testing.T) {
	backends := make([]*backend, proxyFixRandomBackends)
	for i := range backends {
		backends[i] = &backend{Addr: "b" + strconv.Itoa(i)}
		backends[i].Healthy.Store(true)
	}
	lb := newBalancer(LBRandom, backends)
	counts := make([]int, len(backends))
	for i := 0; i < proxyFixRandomPicks; i++ {
		idx := lb.pick(backends, "", 0)
		if idx < 0 || idx >= len(backends) {
			t.Fatalf("pick returned %d", idx)
		}
		counts[idx]++
	}
	for i, n := range counts {
		if n < proxyFixRandomMinShare {
			t.Fatalf("backend %d picked %d of %d times: %v", i, n, proxyFixRandomPicks, counts)
		}
	}
}
