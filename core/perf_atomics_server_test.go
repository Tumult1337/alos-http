//go:build linux && amd64

package core

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/alosmap"
	"github.com/guno1928/turbo"
)

var (
	perfSinkBool  bool
	perfSinkInt   int64
	perfSinkStr   string
	perfSinkBytes []byte

	perfParallelSink atomic.Int64
)

func perfKeepParallel(hit bool, sum int64, s string) {
	if hit {
		sum++
	}
	perfParallelSink.Add(sum + int64(len(s)))
}

type perfServerHotPadded struct {
	_                 [CacheLineSize]byte
	activeConns       atomic.Int64
	_                 [CacheLineSize - 8]byte
	inFlightBodyBytes atomic.Int64
	_                 [CacheLineSize - 8]byte
	shuttingDown      atomic.Bool
	fastDispatch      atomic.Bool
	plainRootFast     atomic.Pointer[plainRootFastResponse]
	h2RootFast        atomic.Pointer[h2RootFastResponse]
	altSvc            atomic.Pointer[altSvcHeader]
	limits            atomic.Pointer[Limits]
	_                 [CacheLineSize]byte
}

func perfReadHotConfig(s *Server) bool {
	return s.shuttingDown.Load() || s.fastDispatch.Load() || s.h2RootFast.Load() != nil ||
		s.plainRootFast.Load() != nil || s.altSvc.Load() != nil
}

func perfReadHotConfigPadded(p *perfServerHotPadded) bool {
	return p.shuttingDown.Load() || p.fastDispatch.Load() || p.h2RootFast.Load() != nil ||
		p.plainRootFast.Load() != nil || p.altSvc.Load() != nil
}

func BenchmarkPerfAtomicsServerFalseSharing(b *testing.B) {
	const reserve = 1024
	b.Run("read_only_hot_config", func(b *testing.B) {
		b.ReportAllocs()
		s := perfAtomicsServer()
		b.RunParallel(func(pb *testing.PB) {
			hit := false
			for pb.Next() {
				hit = perfReadHotConfig(s) || hit
			}
			perfKeepParallel(hit, 0, "")
		})
	})
	b.Run("real_layout_body_budget_plus_reads", func(b *testing.B) {
		b.ReportAllocs()
		s := perfAtomicsServer()
		b.RunParallel(func(pb *testing.PB) {
			hit := false
			for pb.Next() {
				hit = perfReadHotConfig(s) || hit
				if !s.tryReserveBodyBytes(reserve) {
					b.Error("budget refused")
					return
				}
				hit = perfReadHotConfig(s) || hit
				s.releaseBodyBytes(reserve)
			}
			perfKeepParallel(hit, 0, "")
		})
	})
	b.Run("padded_body_budget_plus_reads", func(b *testing.B) {
		b.ReportAllocs()
		p := &perfServerHotPadded{}
		budget := &perfBodyBudgetPadded{limit: 64 << 20}
		b.RunParallel(func(pb *testing.PB) {
			hit := false
			for pb.Next() {
				hit = perfReadHotConfigPadded(p) || hit
				if !budget.reserveCAS(reserve) {
					b.Error("budget refused")
					return
				}
				hit = perfReadHotConfigPadded(p) || hit
				budget.used.Add(-reserve)
			}
			perfKeepParallel(hit, 0, "")
		})
	})
	b.Run("real_layout_conn_churn_plus_reads", func(b *testing.B) {
		b.ReportAllocs()
		s := perfAtomicsServer()
		b.RunParallel(func(pb *testing.PB) {
			hit := false
			for pb.Next() {
				s.activeConns.Add(1)
				hit = perfReadHotConfig(s) || hit
				s.releaseTrackedConn()
				hit = perfReadHotConfig(s) || hit
			}
			perfKeepParallel(hit, 0, "")
		})
	})
	b.Run("padded_conn_churn_plus_reads", func(b *testing.B) {
		b.ReportAllocs()
		p := &perfServerHotPadded{}
		b.RunParallel(func(pb *testing.PB) {
			hit := false
			for pb.Next() {
				p.activeConns.Add(1)
				hit = perfReadHotConfigPadded(p) || hit
				p.activeConns.Add(-1)
				hit = perfReadHotConfigPadded(p) || hit
			}
			perfKeepParallel(hit, 0, "")
		})
	})
}

func BenchmarkPerfAtomicsSnapshotRead(b *testing.B) {
	limits := &Limits{MaxBodySize: 4 << 20, MaxHeaderSize: 8192}
	b.Run("atomic_pointer_current", func(b *testing.B) {
		b.ReportAllocs()
		s := perfAtomicsServer()
		s.limits.Store(limits)
		b.RunParallel(func(pb *testing.PB) {
			var sum int64
			for pb.Next() {
				sum += s.limits.Load().MaxBodySize
			}
			perfKeepParallel(false, sum, "")
		})
	})
	b.Run("atomic_value_type_assert", func(b *testing.B) {
		b.ReportAllocs()
		var v atomic.Value
		v.Store(limits)
		b.RunParallel(func(pb *testing.PB) {
			var sum int64
			for pb.Next() {
				sum += v.Load().(*Limits).MaxBodySize
			}
			perfKeepParallel(false, sum, "")
		})
	})
	b.Run("rwmutex_read", func(b *testing.B) {
		b.ReportAllocs()
		var mu sync.RWMutex
		cur := limits
		b.RunParallel(func(pb *testing.PB) {
			var sum int64
			for pb.Next() {
				mu.RLock()
				sum += cur.MaxBodySize
				mu.RUnlock()
			}
			perfKeepParallel(false, sum, "")
		})
	})
	b.Run("mutex_read", func(b *testing.B) {
		b.ReportAllocs()
		var mu sync.Mutex
		cur := limits
		b.RunParallel(func(pb *testing.PB) {
			var sum int64
			for pb.Next() {
				mu.Lock()
				sum += cur.MaxBodySize
				mu.Unlock()
			}
			perfKeepParallel(false, sum, "")
		})
	})
	b.Run("worker_cached_gen_check_current", func(b *testing.B) {
		b.ReportAllocs()
		s := perfAtomicsServer()
		s.limits.Store(limits)
		b.RunParallel(func(pb *testing.PB) {
			w := &epollWorker{server: s}
			w.refreshLimits()
			var sum int64
			for pb.Next() {
				w.refreshLimits()
				sum += w.maxBodySize
			}
			perfKeepParallel(false, sum, "")
		})
	})
}

func perfIPList(n int) []string {
	ips := make([]string, n)
	for i := range ips {
		ips[i] = "10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256)
	}
	return ips
}

type perfPaddedIPCounter struct {
	n atomic.Int64
	_ [CacheLineSize - 8]byte
}

type perfPaddedIPLimiter struct {
	m *alosmap.TypedMap[string, *perfPaddedIPCounter]
}

func (l *perfPaddedIPLimiter) hold(ip string, limit int64) (*perfPaddedIPCounter, bool) {
	c, ok := l.m.Load(ip)
	if !ok {
		c, _ = l.m.LoadOrStore(ip, &perfPaddedIPCounter{})
	}
	for {
		cur := c.n.Load()
		if cur >= limit {
			return nil, false
		}
		if c.n.CompareAndSwap(cur, cur+1) {
			return c, true
		}
	}
}

func BenchmarkPerfAtomicsPerIPLimiter(b *testing.B) {
	const limit = 1 << 30
	const goroutineIPs = 64
	ips := perfIPList(goroutineIPs)
	b.Run("current_same_ip_all_loops", func(b *testing.B) {
		b.ReportAllocs()
		l := newPerIPRequestLimiter()
		defer l.Stop()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if !l.acquire(ips[0], limit) {
					b.Error("refused")
					return
				}
				l.release(ips[0])
			}
		})
	})
	b.Run("current_ip_per_loop_adjacent_counters", func(b *testing.B) {
		b.ReportAllocs()
		l := newPerIPRequestLimiter()
		defer l.Stop()
		for _, ip := range ips {
			l.acquire(ip, limit)
			l.release(ip)
		}
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			ip := ips[int(next.Add(1)-1)%goroutineIPs]
			for pb.Next() {
				if !l.acquire(ip, limit) {
					b.Error("refused")
					return
				}
				l.release(ip)
			}
		})
	})
	b.Run("alt_padded_counter_ip_per_loop", func(b *testing.B) {
		b.ReportAllocs()
		l := &perfPaddedIPLimiter{m: alosmap.NewTyped[string, *perfPaddedIPCounter]().Prealloc(256)}
		for _, ip := range ips {
			l.hold(ip, limit)
		}
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			ip := ips[int(next.Add(1)-1)%goroutineIPs]
			for pb.Next() {
				c, ok := l.hold(ip, limit)
				if !ok {
					b.Error("refused")
					return
				}
				c.n.Add(-1)
			}
		})
	})
	b.Run("alt_held_counter_release_without_reload", func(b *testing.B) {
		b.ReportAllocs()
		l := newPerIPRequestLimiter()
		defer l.Stop()
		for _, ip := range ips {
			l.acquire(ip, limit)
			l.release(ip)
		}
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			ip := ips[int(next.Add(1)-1)%goroutineIPs]
			for pb.Next() {
				c, ok := l.hold(ip, limit)
				if !ok {
					b.Error("refused")
					return
				}
				if c != nil {
					c.release()
				}
			}
		})
	})
}

func perfCertStore() *CertStore {
	cs := NewCertStore()
	for _, d := range []string{"example.com", "api.example.com", "static.example.com"} {
		cs.AddCert(&CertEntry{Domain: d})
	}
	return cs
}

func BenchmarkPerfAtomicsCertLookup(b *testing.B) {
	cases := []struct{ name, sni string }{
		{"lower_hit", "api.example.com"},
		{"mixed_case_hit", "API.Example.com"},
		{"miss_default", "unknown.example.org"},
		{"empty_sni_default", ""},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			cs := perfCertStore()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if cs.Lookup(tc.sni) == nil {
						b.Error("nil entry")
						return
					}
				}
			})
		})
	}
}

func perfHpackCollidingValues() (string, string) {
	base := "13"
	want := hpackFieldCacheSlot(hpackStaticContentLength, base)
	for i := 14; i < 1_000_000; i++ {
		v := strconv.Itoa(i)
		if hpackFieldCacheSlot(hpackStaticContentLength, v) == want {
			return base, v
		}
	}
	return base, base
}

func BenchmarkPerfAtomicsHpackFieldCache(b *testing.B) {
	b.Run("hit_shared_global_cache", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			e := &HpackEncoder{Buf: make([]byte, 0, 64)}
			for pb.Next() {
				e.Buf = e.Buf[:0]
				e.encodeStaticFieldCached(hpackStaticContentLength, "13")
			}
		})
	})
	b.Run("thrash_two_values_same_slot", func(b *testing.B) {
		b.ReportAllocs()
		v1, v2 := perfHpackCollidingValues()
		if v1 == v2 {
			b.Skip("no colliding value found")
		}
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			v := v1
			if next.Add(1)%2 == 0 {
				v = v2
			}
			e := &HpackEncoder{Buf: make([]byte, 0, 64)}
			for pb.Next() {
				e.Buf = e.Buf[:0]
				e.encodeStaticFieldCached(hpackStaticContentLength, v)
			}
		})
	})
	b.Run("uncached_encode_baseline", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			e := &HpackEncoder{Buf: make([]byte, 0, 64)}
			for pb.Next() {
				e.Buf = e.Buf[:0]
				e.EncodeInt(0x00, 4, uint64(hpackStaticContentLength))
				e.EncodeString("13")
			}
		})
	})
}

func BenchmarkPerfAtomicsHTTPDate(b *testing.B) {
	b.Run("hit", func(b *testing.B) {
		b.ReportAllocs()
		now := turbo.Unix()
		httpDate(now)
		b.RunParallel(func(pb *testing.PB) {
			var s string
			for pb.Next() {
				s = httpDate(now)
			}
			perfKeepParallel(false, 0, s)
		})
	})
	b.Run("two_seconds_alternating", func(b *testing.B) {
		b.ReportAllocs()
		now := turbo.Unix()
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			u := now + int64(next.Add(1)%2)
			var s string
			for pb.Next() {
				s = httpDate(u)
			}
			perfKeepParallel(false, 0, s)
		})
	})
}

func BenchmarkPerfAtomicsCoarseClock(b *testing.B) {
	b.Run("CoarseNanotime_current", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			var sum int64
			for pb.Next() {
				sum += CoarseNanotime()
			}
			perfKeepParallel(false, sum, "")
		})
	})
	b.Run("turbo_UnixNano_alt", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			var sum int64
			for pb.Next() {
				sum += turbo.UnixNano()
			}
			perfKeepParallel(false, sum, "")
		})
	})
}

func BenchmarkPerfAtomicsRateLimitCheck(b *testing.B) {
	newEngine := func() *RateLimitEngine {
		rl := NewRateLimitEngine()
		rl.AddRule(RateLimitRule{Path: "/mw", MaxReqs: 1_000_000_000, Window: time.Minute})
		return rl
	}
	b.Run("same_ip_all_loops", func(b *testing.B) {
		b.ReportAllocs()
		rl := newEngine()
		defer rl.Stop()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if ok, _, _ := rl.Check("198.51.100.9", "/mw"); !ok {
					b.Error("refused")
					return
				}
			}
		})
	})
	b.Run("ip_per_loop", func(b *testing.B) {
		b.ReportAllocs()
		rl := newEngine()
		defer rl.Stop()
		ips := perfIPList(64)
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			ip := ips[int(next.Add(1)-1)%len(ips)]
			for pb.Next() {
				if ok, _, _ := rl.Check(ip, "/mw"); !ok {
					b.Error("refused")
					return
				}
			}
		})
	})
	b.Run("unmatched_path", func(b *testing.B) {
		b.ReportAllocs()
		rl := newEngine()
		defer rl.Stop()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if ok, _, _ := rl.Check("198.51.100.9", "/other"); !ok {
					b.Error("refused")
					return
				}
			}
		})
	})
}

type perfPaddedBackend struct {
	healthy        atomic.Bool
	ejectedUntilNs atomic.Int64
	_              [CacheLineSize - 16]byte
	activeConns    atomic.Int64
	_              [CacheLineSize - 8]byte
}

func (b *perfPaddedBackend) available(now int64) bool {
	return b.healthy.Load() && b.ejectedUntilNs.Load() <= now
}

func BenchmarkPerfAtomicsProxyBackend(b *testing.B) {
	b.Run("current_rr_pick_activeconns", func(b *testing.B) {
		b.ReportAllocs()
		be := &backend{Addr: "127.0.0.1:9000", Weight: 1}
		be.Healthy.Store(true)
		backends := []*backend{be}
		rr := &roundRobinBalancer{}
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				idx := rr.pick(backends, "", turbo.UnixNano())
				if idx < 0 {
					b.Error("no backend")
					return
				}
				backends[idx].ActiveConns.Add(1)
				backends[idx].ActiveConns.Add(-1)
			}
		})
	})
	b.Run("alt_padded_backend_per_loop_rr", func(b *testing.B) {
		b.ReportAllocs()
		backends := []*perfPaddedBackend{{}}
		backends[0].healthy.Store(true)
		b.RunParallel(func(pb *testing.PB) {
			var rr uint64
			for pb.Next() {
				now := turbo.UnixNano()
				idx := -1
				for i := 0; i < len(backends); i++ {
					cand := int((rr + uint64(i)) % uint64(len(backends)))
					if backends[cand].available(now) {
						idx = cand
						break
					}
				}
				rr++
				if idx < 0 {
					b.Error("no backend")
					return
				}
				backends[idx].activeConns.Add(1)
				backends[idx].activeConns.Add(-1)
			}
		})
	})
	b.Run("current_rr_pick_only", func(b *testing.B) {
		b.ReportAllocs()
		be := &backend{Addr: "127.0.0.1:9000", Weight: 1}
		be.Healthy.Store(true)
		backends := []*backend{be}
		rr := &roundRobinBalancer{}
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if rr.pick(backends, "", turbo.UnixNano()) < 0 {
					b.Error("no backend")
					return
				}
			}
		})
	})
}

func BenchmarkPerfAtomicsRateLimitMiddleware(b *testing.B) {
	run := func(b *testing.B, addrFor func(int) string) {
		b.ReportAllocs()
		stop := make(chan struct{})
		defer close(stop)
		mw := RateLimitMiddleware(RateLimitMiddlewareConfig{MaxRequests: 1_000_000_000, Window: time.Second, StopCh: stop})
		h := mw(func(r *Request, _ *Response) { r.ParamCount = 1 })
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			req := &Request{RemoteAddr: addrFor(int(next.Add(1) - 1))}
			resp := &Response{}
			n := 0
			for pb.Next() {
				h(req, resp)
				n++
			}
			if n > 0 && req.ParamCount != 1 {
				b.Error("handler never ran")
			}
		})
	}
	b.Run("same_ip_all_loops", func(b *testing.B) {
		run(b, func(int) string { return "127.0.0.1:40000" })
	})
	b.Run("ip_per_loop", func(b *testing.B) {
		ips := perfIPList(64)
		run(b, func(i int) string { return ips[i%len(ips)] + ":40000" })
	})
}
