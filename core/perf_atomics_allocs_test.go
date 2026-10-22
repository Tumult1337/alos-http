//go:build linux && amd64

package core

import (
	"sync/atomic"
	"testing"

	"github.com/guno1928/turbo"
)

const perfAllocRuns = 1000

func perfRequireZeroAllocs(t *testing.T, name string, fn func()) {
	t.Helper()
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	fn()
	if n := testing.AllocsPerRun(perfAllocRuns, fn); n > 0 {
		t.Fatalf("%s: %.2f allocs/op, want 0", name, n)
	}
}

func TestPerfAtomicsZeroAllocStatsCounters(t *testing.T) {
	perfRequireZeroAllocs(t, "request counters", func() {
		Stats.TotalReqs.Add(1)
		Stats.RawReqs.Add(1)
	})
	perfRequireZeroAllocs(t, "statsBlocked", statsBlocked)
	perfRequireZeroAllocs(t, "statsRawBlocked", statsRawBlocked)
	perfRequireZeroAllocs(t, "Snapshot", func() { _ = Stats.Snapshot() })
	perfRequireZeroAllocs(t, "ReqsPerSec", func() { _ = Stats.ReqsPerSec() + Stats.BlockedPerSec() })
	w := &epollWorker{}
	perfRequireZeroAllocs(t, "flushStatsCounters", func() {
		w.bytesIn += 10
		w.bytesOut += 20
		w.flushStatsCounters()
	})
}

func TestPerfAtomicsZeroAllocServerBudgets(t *testing.T) {
	s := perfAtomicsServer()
	perfRequireZeroAllocs(t, "request slot disabled", func() {
		if s.tryAcquireRequestSlot() {
			s.releaseRequestSlot()
		}
	})
	s.config.MaxConcurrentReqs = 1 << 40
	perfRequireZeroAllocs(t, "request slot enabled", func() {
		if s.tryAcquireRequestSlot() {
			s.releaseRequestSlot()
		}
	})
	perfRequireZeroAllocs(t, "body budget", func() {
		if s.tryReserveBodyBytes(1024) {
			s.releaseBodyBytes(1024)
		}
	})
	var connReserved atomic.Int64
	perfRequireZeroAllocs(t, "conn body budget", func() {
		if s.tryReserveConnBodyBytes(&connReserved, 1024) {
			s.releaseConnBodyBytes(&connReserved, 1024)
		}
	})
	perfRequireZeroAllocs(t, "conn tracking", func() {
		if s.tryTrackConn() {
			s.releaseTrackedConn()
		}
	})
	w := &epollWorker{server: s}
	perfRequireZeroAllocs(t, "refreshLimits", w.refreshLimits)
	perfRequireZeroAllocs(t, "hot config reads", func() { perfSinkBool = perfReadHotConfig(s) })
}

func TestPerfAtomicsZeroAllocPerIPLimiterHit(t *testing.T) {
	l := newPerIPRequestLimiter()
	defer l.Stop()
	const ip = "203.0.113.7"
	perfRequireZeroAllocs(t, "per-IP acquire/release", func() {
		if l.acquire(ip, 64) {
			l.release(ip)
		}
	})
}

func TestPerfAtomicsZeroAllocCompletionStack(t *testing.T) {
	w := &epollWorker{}
	c := &epollConn{}
	perfRequireZeroAllocs(t, "pushH1Done", func() {
		w.pushH1Done(c)
		head := w.h1Done.Swap(nil)
		head.h1DoneNext = nil
		w.taskPending.Store(false)
	})
}

func TestPerfAtomicsZeroAllocPools(t *testing.T) {
	perfRequireZeroAllocs(t, "io buf", func() { releaseIOBuf(acquireIOBuf()) })
	perfRequireZeroAllocs(t, "epoll read buf", func() { releaseEpollReadBuf(acquireEpollReadBuf()) })
	perfRequireZeroAllocs(t, "conn read buf", func() {
		releasePooledBuf(&connReadBufPool, acquirePooledBuf(&connReadBufPool), connBufPoolMaxCap)
	})
	perfRequireZeroAllocs(t, "conn write buf", func() {
		releasePooledBuf(&connWriteBufPool, acquirePooledBuf(&connWriteBufPool), connBufPoolMaxCap)
	})
	perfRequireZeroAllocs(t, "request pool", func() { releaseRequestToPool(RequestPool.Get().(*Request)) })
	perfRequireZeroAllocs(t, "response pool", func() { releaseResponseToPool(ResponsePool.Get().(*Response)) })
}

func TestPerfAtomicsZeroAllocSharedReadPaths(t *testing.T) {
	cs := perfCertStore()
	perfRequireZeroAllocs(t, "cert lookup lowercase", func() {
		if cs.Lookup("api.example.com") == nil {
			t.Fatal("nil cert entry")
		}
	})
	perfRequireZeroAllocs(t, "cert lookup default", func() { _ = cs.Lookup("") })
	e := &HpackEncoder{Buf: make([]byte, 0, 64)}
	perfRequireZeroAllocs(t, "hpack field cache hit", func() {
		e.Buf = e.Buf[:0]
		e.encodeStaticFieldCached(hpackStaticContentLength, "13")
	})
	now := turbo.Unix()
	perfRequireZeroAllocs(t, "httpDate hit", func() { perfSinkStr = httpDate(now) })
	perfRequireZeroAllocs(t, "CoarseNanotime", func() { perfSinkInt = CoarseNanotime() })
	perfRequireZeroAllocs(t, "lowerHeaderName common", func() { perfSinkStr = lowerHeaderName([]byte("Content-Type")) })
	var req Request
	perfRequireZeroAllocs(t, "finishContext no slot", req.finishContext)
	var slot cancelSlot
	perfRequireZeroAllocs(t, "cancelSlot attach+finish unused", func() {
		slot.attach(&req)
		req.finishContext()
	})
}
