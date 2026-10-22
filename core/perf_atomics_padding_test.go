//go:build linux && amd64

package core

import (
	"testing"
	"unsafe"
)

const perfAtomicWordSize = 8

type perfHotWord struct {
	name   string
	offset uintptr
	size   uintptr
}

func perfRequireOwnLine(t *testing.T, hot perfHotWord, neighbours []perfHotWord) {
	t.Helper()
	for _, n := range neighbours {
		var gap uintptr
		if n.offset >= hot.offset+hot.size {
			gap = n.offset - (hot.offset + hot.size)
		} else {
			gap = hot.offset - (n.offset + n.size)
		}
		if gap < CacheLineSize-perfAtomicWordSize {
			t.Errorf("%s at %d shares a cache line with %s at %d (gap %d)", hot.name, hot.offset, n.name, n.offset, gap)
		}
	}
}

func TestPerfAtomicsServerHotCountersOwnLines(t *testing.T) {
	var s Server
	budget := perfHotWord{"activeReqs+inFlightBodyBytes", unsafe.Offsetof(s.activeReqs), unsafe.Sizeof(s.activeReqs) + unsafe.Sizeof(s.inFlightBodyBytes)}
	perfRequireOwnLine(t, budget, []perfHotWord{
		{"globalLimiter", unsafe.Offsetof(s.globalLimiter), unsafe.Sizeof(s.globalLimiter)},
		{"fastDispatch", unsafe.Offsetof(s.fastDispatch), unsafe.Sizeof(s.fastDispatch)},
		{"plainRootFast", unsafe.Offsetof(s.plainRootFast), unsafe.Sizeof(s.plainRootFast)},
	})
	if size := unsafe.Sizeof(ipReqCounter{}); size < CacheLineSize {
		t.Errorf("ipReqCounter is %d bytes, want a full %d-byte line", size, CacheLineSize)
	}
}

func TestPerfMemoryStructSizesReport(t *testing.T) {
	t.Logf("H2Stream %d B, Request %d B, Response %d B, epollConn %d B, epollWorker %d B, Server %d B",
		unsafe.Sizeof(H2Stream{}), unsafe.Sizeof(Request{}), unsafe.Sizeof(Response{}),
		unsafe.Sizeof(epollConn{}), unsafe.Sizeof(epollWorker{}), unsafe.Sizeof(Server{}))
}
