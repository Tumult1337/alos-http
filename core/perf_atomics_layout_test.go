//go:build linux && amd64

package core

import (
	"testing"
	"unsafe"
)

type perfFieldOffset struct {
	name string
	off  uintptr
	size uintptr
}

func perfLogLayout(t *testing.T, typ string, total uintptr, fields []perfFieldOffset) {
	t.Helper()
	t.Logf("%s size=%d lines=%d", typ, total, (total+CacheLineSize-1)/CacheLineSize)
	for _, f := range fields {
		first := f.off / CacheLineSize
		last := (f.off + f.size - 1) / CacheLineSize
		t.Logf("  %-20s off=%5d size=%4d line=%d..%d", f.name, f.off, f.size, first, last)
	}
}

func TestPerfAtomicsLayoutReport(t *testing.T) {
	var s Server
	perfLogLayout(t, "Server", unsafe.Sizeof(s), []perfFieldOffset{
		{"debug", unsafe.Offsetof(s.debug), unsafe.Sizeof(s.debug)},
		{"logRequests", unsafe.Offsetof(s.logRequests), unsafe.Sizeof(s.logRequests)},
		{"config", unsafe.Offsetof(s.config), unsafe.Sizeof(s.config)},
		{"Router", unsafe.Offsetof(s.Router), unsafe.Sizeof(s.Router)},
		{"fallbackTLS", unsafe.Offsetof(s.fallbackTLS), unsafe.Sizeof(s.fallbackTLS)},
		{"proxy", unsafe.Offsetof(s.proxy), unsafe.Sizeof(s.proxy)},
		{"httpRouter", unsafe.Offsetof(s.httpRouter), unsafe.Sizeof(s.httpRouter)},
		{"corsEngine", unsafe.Offsetof(s.corsEngine), unsafe.Sizeof(s.corsEngine)},
		{"rateLimitEngine", unsafe.Offsetof(s.rateLimitEngine), unsafe.Sizeof(s.rateLimitEngine)},
		{"done", unsafe.Offsetof(s.done), unsafe.Sizeof(s.done)},
		{"activeConns", unsafe.Offsetof(s.activeConns), unsafe.Sizeof(s.activeConns)},
		{"shuttingDown", unsafe.Offsetof(s.shuttingDown), unsafe.Sizeof(s.shuttingDown)},
		{"drainDone", unsafe.Offsetof(s.drainDone), unsafe.Sizeof(s.drainDone)},
		{"globalLimiter", unsafe.Offsetof(s.globalLimiter), unsafe.Sizeof(s.globalLimiter)},
		{"activeReqs", unsafe.Offsetof(s.activeReqs), unsafe.Sizeof(s.activeReqs)},
		{"inFlightBodyBytes", unsafe.Offsetof(s.inFlightBodyBytes), unsafe.Sizeof(s.inFlightBodyBytes)},
		{"fastDispatch", unsafe.Offsetof(s.fastDispatch), unsafe.Sizeof(s.fastDispatch)},
		{"altSvc", unsafe.Offsetof(s.altSvc), unsafe.Sizeof(s.altSvc)},
		{"trustedProxies", unsafe.Offsetof(s.trustedProxies), unsafe.Sizeof(s.trustedProxies)},
		{"perIPLimiter", unsafe.Offsetof(s.perIPLimiter), unsafe.Sizeof(s.perIPLimiter)},
		{"perIPConnLimiter", unsafe.Offsetof(s.perIPConnLimiter), unsafe.Sizeof(s.perIPConnLimiter)},
		{"limits", unsafe.Offsetof(s.limits), unsafe.Sizeof(s.limits)},
		{"limitsGen", unsafe.Offsetof(s.limitsGen), unsafe.Sizeof(s.limitsGen)},
		{"trackedConnMu", unsafe.Offsetof(s.trackedConnMu), unsafe.Sizeof(s.trackedConnMu)},
		{"onRequestHooks", unsafe.Offsetof(s.onRequestHooks), unsafe.Sizeof(s.onRequestHooks)},
		{"onResponseHooks", unsafe.Offsetof(s.onResponseHooks), unsafe.Sizeof(s.onResponseHooks)},
		{"srvKeepAlive", unsafe.Offsetof(s.srvKeepAlive), unsafe.Sizeof(s.srvKeepAlive)},
	})
	t.Logf("Config.MaxConcurrentReqs off=%d Config.MaxInFlightBodyBytes off=%d (inside Server.config)",
		unsafe.Offsetof(s.config)+unsafe.Offsetof(s.config.MaxConcurrentReqs),
		unsafe.Offsetof(s.config)+unsafe.Offsetof(s.config.MaxInFlightBodyBytes))

	var w epollWorker
	perfLogLayout(t, "epollWorker", unsafe.Sizeof(w), []perfFieldOffset{
		{"server", unsafe.Offsetof(w.server), unsafe.Sizeof(w.server)},
		{"bytesIn", unsafe.Offsetof(w.bytesIn), unsafe.Sizeof(w.bytesIn)},
		{"bytesOut", unsafe.Offsetof(w.bytesOut), unsafe.Sizeof(w.bytesOut)},
		{"spawned", unsafe.Offsetof(w.spawned), unsafe.Sizeof(w.spawned)},
		{"conns", unsafe.Offsetof(w.conns), unsafe.Sizeof(w.conns)},
		{"pool", unsafe.Offsetof(w.pool), unsafe.Sizeof(w.pool)},
		{"events", unsafe.Offsetof(w.events), unsafe.Sizeof(w.events)},
		{"taskCh", unsafe.Offsetof(w.taskCh), unsafe.Sizeof(w.taskCh)},
		{"handlers", unsafe.Offsetof(w.handlers), unsafe.Sizeof(w.handlers)},
		{"taskPending", unsafe.Offsetof(w.taskPending), unsafe.Sizeof(w.taskPending)},
		{"h1Done", unsafe.Offsetof(w.h1Done), unsafe.Sizeof(w.h1Done)},
		{"takeoverUnpins", unsafe.Offsetof(w.takeoverUnpins), unsafe.Sizeof(w.takeoverUnpins)},
		{"parked", unsafe.Offsetof(w.parked), unsafe.Sizeof(w.parked)},
		{"wakeBuf", unsafe.Offsetof(w.wakeBuf), unsafe.Sizeof(w.wakeBuf)},
		{"flushList", unsafe.Offsetof(w.flushList), unsafe.Sizeof(w.flushList)},
		{"readTO", unsafe.Offsetof(w.readTO), unsafe.Sizeof(w.readTO)},
		{"maxHeaderSize", unsafe.Offsetof(w.maxHeaderSize), unsafe.Sizeof(w.maxHeaderSize)},
		{"limitsGen", unsafe.Offsetof(w.limitsGen), unsafe.Sizeof(w.limitsGen)},
		{"maxPendingWrite", unsafe.Offsetof(w.maxPendingWrite), unsafe.Sizeof(w.maxPendingWrite)},
		{"be", unsafe.Offsetof(w.be), unsafe.Sizeof(w.be)},
	})

	var hp handlerPool
	perfLogLayout(t, "handlerPool", unsafe.Sizeof(hp), []perfFieldOffset{
		{"tasks", unsafe.Offsetof(hp.tasks), unsafe.Sizeof(hp.tasks)},
		{"workers", unsafe.Offsetof(hp.workers), unsafe.Sizeof(hp.workers)},
		{"limit", unsafe.Offsetof(hp.limit), unsafe.Sizeof(hp.limit)},
	})

	t.Logf("ipReqCounter size=%d (heap size class packs %d counters per cache line)",
		unsafe.Sizeof(ipReqCounter{}), CacheLineSize/unsafe.Sizeof(ipReqCounter{}))
	t.Logf("cancelSlot size=%d reqCancel size=%d", unsafe.Sizeof(cancelSlot{}), unsafe.Sizeof(reqCancel{}))
	t.Logf("hpackFieldCache bytes=%d lines=%d", unsafe.Sizeof(hpackFieldCache), unsafe.Sizeof(hpackFieldCache)/CacheLineSize)
	t.Logf("ServerStats size=%d", unsafe.Sizeof(ServerStats{}))
}

func TestPerfAtomicsStatsCountersOwnCacheLines(t *testing.T) {
	var s ServerStats
	offs := []perfFieldOffset{
		{"ActiveConns", unsafe.Offsetof(s.ActiveConns), unsafe.Sizeof(s.ActiveConns)},
		{"TotalConns", unsafe.Offsetof(s.TotalConns), unsafe.Sizeof(s.TotalConns)},
		{"H2Conns", unsafe.Offsetof(s.H2Conns), unsafe.Sizeof(s.H2Conns)},
		{"H1Conns", unsafe.Offsetof(s.H1Conns), unsafe.Sizeof(s.H1Conns)},
		{"TotalReqs", unsafe.Offsetof(s.TotalReqs), unsafe.Sizeof(s.TotalReqs)},
		{"BytesIn", unsafe.Offsetof(s.BytesIn), unsafe.Sizeof(s.BytesIn)},
		{"BytesOut", unsafe.Offsetof(s.BytesOut), unsafe.Sizeof(s.BytesOut)},
		{"RawReqs", unsafe.Offsetof(s.RawReqs), unsafe.Sizeof(s.RawReqs)},
		{"BlockedReqs", unsafe.Offsetof(s.BlockedReqs), unsafe.Sizeof(s.BlockedReqs)},
		{"H1Rejected", unsafe.Offsetof(s.H1Rejected), unsafe.Sizeof(s.H1Rejected)},
		{"H3Conns", unsafe.Offsetof(s.H3Conns), unsafe.Sizeof(s.H3Conns)},
		{"rawPerSec", unsafe.Offsetof(s.rawPerSec), unsafe.Sizeof(s.rawPerSec)},
		{"blkPerSec", unsafe.Offsetof(s.blkPerSec), unsafe.Sizeof(s.blkPerSec)},
	}
	seen := map[uintptr]string{}
	for _, f := range offs {
		if f.off%8 != 0 {
			t.Fatalf("%s at offset %d is not 8-byte aligned", f.name, f.off)
		}
		line := f.off / CacheLineSize
		if other, dup := seen[line]; dup {
			t.Fatalf("%s shares cache line %d with %s", f.name, line, other)
		}
		seen[line] = f.name
	}
}
