//go:build linux && amd64

package core

import (
	"testing"
	"unsafe"
)

func TestPromoteSizesAFreshArenaToTheRequest(t *testing.T) {
	buf, names, vals := benchAliasSource(14, 18, 42)
	path := unsafe.String(&buf[0], 24)
	host := unsafe.String(&buf[0], 11)
	req := &Request{}
	reAlias(req, names, vals, path, host)
	promoteRequestStrings(req)
	need := len("GET") + len(path) + len(host) + 14*(18+42)
	if got := cap(req.promoteBuf); got != need {
		t.Fatalf("fresh arena holds %d bytes, want exactly the %d this request needs", got, need)
	}
	first := req.promoteBuf

	reAlias(req, names, vals, path, host)
	promoteRequestStrings(req)
	if got := cap(req.promoteBuf); got != promoteArenaChunk {
		t.Fatalf("a keep-alive request that outgrows the arena got %d bytes, want a %d chunk", got, promoteArenaChunk)
	}
	if &first[0] == &req.promoteBuf[0] {
		t.Fatal("the first request's strings were overwritten in place")
	}
	if req.Path != path || req.Headers[13][1] != vals[13] {
		t.Fatal("promoted strings changed value")
	}
}
