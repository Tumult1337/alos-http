//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

const proxyFixCachedAsset = "/static/app.js"

var proxyFixNonCanonicalTargets = []string{
	"/uploads/x/../../static/app.js",
	"/./static/app.js",
	"//static/app.js",
	"/static//app.js",
}

func proxyFixCachingLabelProxy(t *testing.T) (*proxyFixLabelOrigin, string) {
	t.Helper()
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()),
		func(s *Server) { s.SetProxyCache(DefaultProxyCacheConfig()) })
	return o, addr
}

func TestProxyFixCacheKeyMatchesForwardedTargetH1(t *testing.T) {
	for _, target := range proxyFixNonCanonicalTargets {
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			_, addr := proxyFixCachingLabelProxy(t)
			proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, target))
			_, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, proxyFixCachedAsset))
			if body != "ORIGIN:"+proxyFixCachedAsset {
				t.Fatalf("after %s, GET %s served %q: the cache keyed the normalised path while the backend got the raw target",
					target, proxyFixCachedAsset, body)
			}
		})
	}
}

func TestProxyFixCacheKeyMatchesForwardedTargetH2(t *testing.T) {
	for _, target := range proxyFixNonCanonicalTargets {
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			_, addr := proxyFixCachingLabelProxy(t)
			proxyFixH2Fetch(t, addr, proxyFixDomain, target)
			_, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, proxyFixCachedAsset))
			if body != "ORIGIN:"+proxyFixCachedAsset {
				t.Fatalf("after h2 %s, GET %s served %q", target, proxyFixCachedAsset, body)
			}
		})
	}
}

func TestProxyFixCanonicalTargetsForwardedVerbatim(t *testing.T) {
	_, addr := proxyFixCachingLabelProxy(t)
	for _, target := range []string{"/a%2Fb/c", "/q?x=1&y=%2e%2e", "/plain"} {
		_, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, target))
		if body != "ORIGIN:"+target {
			t.Fatalf("canonical target %s reached the backend as %q", target, strings.TrimPrefix(body, "ORIGIN:"))
		}
	}
}
