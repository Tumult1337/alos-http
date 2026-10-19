//go:build linux && amd64

package core

import (
	"strings"
	"testing"
	"time"
)

func TestAppFixCacheKeyHostPathBoundaryIsUnambiguous(t *testing.T) {
	rc := NewResponseCache(CacheConfig{})
	defer rc.Stop()
	victim := rc.key(cReq("GET", "victim.example", "/admin/", ""))
	smuggled := rc.key(cReq("GET", "victim.example/admin", "/", ""))
	if victim == smuggled {
		t.Fatalf("Host+Path pairs (victim.example,/admin/) and (victim.example/admin,/) share cache key %q", victim)
	}
}

func TestAppFixCacheSkipsHostsLongerThanTheKeyEncodes(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	calls := 0
	h := func(req *Request, resp *Response) {
		calls++
		resp.Status(200).String("x")
	}
	longHost := strings.Repeat("h", cacheKeyMaxHostLen+1)
	rc.handle(h, cReq("GET", longHost, "/", ""), cResp())
	rc.handle(h, cReq("GET", longHost, "/", ""), cResp())
	if calls != 2 || rc.Len() != 0 {
		t.Fatalf("over-long host: handler calls %d, cached entries %d; want 2 calls and nothing cached", calls, rc.Len())
	}
}

func TestAppFixCachedHeadKeepsTheBodyLength(t *testing.T) {
	const body = "sixteen byte bod"
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Methods: []string{"GET", "HEAD"}})
	defer rc.Stop()
	calls := 0
	h := func(req *Request, resp *Response) {
		calls++
		resp.Status(200).String(body)
	}
	headOnce := func() *Response {
		req := cReq("HEAD", "x", "/file", "")
		resp := cResp()
		resp.lazyReq = req
		rc.handle(h, req, resp)
		return resp
	}
	first := headOnce()
	second := headOnce()
	if calls != 1 {
		t.Fatalf("HEAD not served from cache: handler calls %d", calls)
	}
	if first.BodyLen() != len(body) || second.BodyLen() != len(body) {
		t.Fatalf("HEAD Content-Length source: first %d, cached %d, want %d", first.BodyLen(), second.BodyLen(), len(body))
	}
}
