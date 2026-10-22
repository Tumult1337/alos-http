//go:build linux && amd64

package core

import (
	"sync/atomic"
	"testing"
)

const (
	perfAtomicsShardSlots   = 256
	perfAtomicsLoopPassReqs = 32
)

type perfPaddedU64 struct {
	v atomic.Uint64
	_ [CacheLineSize - 8]byte
}

type perfPaddedI64 struct {
	v atomic.Int64
	_ [CacheLineSize - 8]byte
}

type perfLoopReqCounters struct {
	totalReqs uint64
	rawReqs   uint64
	pending   int
	_         [CacheLineSize - 24]byte
}

func (c *perfLoopReqCounters) flush() {
	if c.totalReqs != 0 {
		Stats.TotalReqs.Add(c.totalReqs)
		c.totalReqs = 0
	}
	if c.rawReqs != 0 {
		Stats.RawReqs.Add(c.rawReqs)
		c.rawReqs = 0
	}
	c.pending = 0
}

func perfNextShard(next *atomic.Int32) int {
	return int(next.Add(1)-1) % perfAtomicsShardSlots
}

func BenchmarkPerfAtomicsReqCounters(b *testing.B) {
	b.Run("current_two_global_atomics", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				Stats.TotalReqs.Add(1)
				Stats.RawReqs.Add(1)
			}
		})
	})
	b.Run("per_loop_plain_flush_per_pass", func(b *testing.B) {
		b.ReportAllocs()
		var shards [perfAtomicsShardSlots]perfLoopReqCounters
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			c := &shards[perfNextShard(&next)]
			for pb.Next() {
				c.totalReqs++
				c.rawReqs++
				c.pending++
				if c.pending == perfAtomicsLoopPassReqs {
					c.flush()
				}
			}
			c.flush()
		})
	})
	b.Run("sharded_padded_atomic", func(b *testing.B) {
		b.ReportAllocs()
		var total, raw [perfAtomicsShardSlots]perfPaddedU64
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			i := perfNextShard(&next)
			t, r := &total[i].v, &raw[i].v
			for pb.Next() {
				t.Add(1)
				r.Add(1)
			}
		})
	})
	b.Run("sharded_unpadded_atomic", func(b *testing.B) {
		b.ReportAllocs()
		var total, raw [perfAtomicsShardSlots]atomic.Uint64
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			i := perfNextShard(&next)
			t, r := &total[i], &raw[i]
			for pb.Next() {
				t.Add(1)
				r.Add(1)
			}
		})
	})
	b.Run("owned_plain_padded", func(b *testing.B) {
		b.ReportAllocs()
		var shards [perfAtomicsShardSlots]perfLoopReqCounters
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			c := &shards[perfNextShard(&next)]
			for pb.Next() {
				c.totalReqs++
				c.rawReqs++
			}
		})
	})
}

func BenchmarkPerfAtomicsByteCounters(b *testing.B) {
	b.Run("current_worker_flush_per_pass", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			w := &epollWorker{}
			n := 0
			for pb.Next() {
				w.bytesIn += 96
				w.bytesOut += 160
				n++
				if n == perfAtomicsLoopPassReqs {
					w.flushStatsCounters()
					n = 0
				}
			}
			w.flushStatsCounters()
		})
	})
	b.Run("direct_global_atomic_per_op", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				Stats.BytesIn.Add(96)
				Stats.BytesOut.Add(160)
			}
		})
	})
}

func perfAtomicsServer() *Server {
	s := &Server{done: make(chan struct{}), drainDone: make(chan struct{})}
	s.config.MaxInFlightBodyBytes = 64 << 20
	limits := Limits{MaxBodySize: 4 << 20, MaxHeaderSize: 8192}
	s.limits.Store(&limits)
	return s
}

func BenchmarkPerfAtomicsConnAccounting(b *testing.B) {
	b.Run("current_accept_close", func(b *testing.B) {
		b.ReportAllocs()
		s := perfAtomicsServer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				active := s.activeConns.Add(1)
				Stats.ActiveConns.Add(1)
				if lim := s.limits.Load().MaxConns; lim > 0 && active > lim {
					b.Error("unexpected MaxConns refusal")
					return
				}
				Stats.TotalConns.Add(1)
				s.releaseTrackedConn()
				Stats.ActiveConns.Add(-1)
			}
		})
	})
	b.Run("alt_server_only_counter", func(b *testing.B) {
		b.ReportAllocs()
		s := perfAtomicsServer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				active := s.activeConns.Add(1)
				if lim := s.limits.Load().MaxConns; lim > 0 && active > lim {
					b.Error("unexpected MaxConns refusal")
					return
				}
				s.releaseTrackedConn()
			}
		})
	})
}

func BenchmarkPerfAtomicsRequestSlot(b *testing.B) {
	b.Run("disabled_default", func(b *testing.B) {
		b.ReportAllocs()
		s := perfAtomicsServer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if !s.tryAcquireRequestSlot() {
					b.Error("slot refused")
					return
				}
				s.releaseRequestSlot()
			}
		})
	})
	b.Run("enabled_global_atomic", func(b *testing.B) {
		b.ReportAllocs()
		s := perfAtomicsServer()
		s.config.MaxConcurrentReqs = 1 << 40
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if !s.tryAcquireRequestSlot() {
					b.Error("slot refused")
					return
				}
				s.releaseRequestSlot()
			}
		})
	})
}

type perfBodyBudgetPadded struct {
	_     [CacheLineSize]byte
	used  atomic.Int64
	_     [CacheLineSize - 8]byte
	limit int64
}

func (p *perfBodyBudgetPadded) reserveAdd(n int64) bool {
	if p.used.Add(n) > p.limit {
		p.used.Add(-n)
		return false
	}
	return true
}

func (p *perfBodyBudgetPadded) reserveCAS(n int64) bool {
	for {
		used := p.used.Load()
		if n > p.limit-used {
			return false
		}
		if p.used.CompareAndSwap(used, used+n) {
			return true
		}
	}
}

func BenchmarkPerfAtomicsBodyBudget(b *testing.B) {
	const reserve = 1024
	b.Run("current_cas_reserve_release", func(b *testing.B) {
		b.ReportAllocs()
		s := perfAtomicsServer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if !s.tryReserveBodyBytes(reserve) {
					b.Error("budget refused")
					return
				}
				s.releaseBodyBytes(reserve)
			}
		})
	})
	b.Run("current_h2_conn_reserve_release", func(b *testing.B) {
		b.ReportAllocs()
		s := perfAtomicsServer()
		b.RunParallel(func(pb *testing.PB) {
			var connReserved atomic.Int64
			for pb.Next() {
				if !s.tryReserveConnBodyBytes(&connReserved, reserve) {
					b.Error("budget refused")
					return
				}
				s.releaseConnBodyBytes(&connReserved, reserve)
			}
		})
	})
	b.Run("alt_padded_cas", func(b *testing.B) {
		b.ReportAllocs()
		p := &perfBodyBudgetPadded{limit: 64 << 20}
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if !p.reserveCAS(reserve) {
					b.Error("budget refused")
					return
				}
				p.used.Add(-reserve)
			}
		})
	})
	b.Run("alt_padded_add_then_check", func(b *testing.B) {
		b.ReportAllocs()
		p := &perfBodyBudgetPadded{limit: 64 << 20}
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if !p.reserveAdd(reserve) {
					b.Error("budget refused")
					return
				}
				p.used.Add(-reserve)
			}
		})
	})
}
