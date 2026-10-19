package core

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func rateExpiryBenchKeys() []string {
	keys := make([]string, 256)
	for i := range keys {
		keys[i] = fmt.Sprintf("192.0.2.%d", i)
	}
	return keys
}

func BenchmarkRateLimitExpiryEngine(b *testing.B) {
	for _, mode := range []string{"SequentialAllowed", "HotAllowed", "HotBlocked", "SpreadAllowed"} {
		b.Run(mode, func(b *testing.B) {
			engine := NewRateLimitEngine()
			b.Cleanup(engine.Stop)
			limit := int64(1 << 62)
			if mode == "HotBlocked" {
				limit = 1
			}
			engine.SetRules([]RateLimitRule{{Path: "/bench", MaxReqs: limit, Window: time.Hour, BlockFor: rateLimitBlockFor}})
			keys := rateExpiryBenchKeys()
			if mode != "SpreadAllowed" {
				keys = keys[:1]
			}
			for _, key := range keys {
				engine.Check(key, "/bench")
			}
			if mode == "HotBlocked" {
				engine.Check(keys[0], "/bench")
			}
			want := mode != "HotBlocked"
			var wrong atomic.Bool
			var workers atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			if mode == "SequentialAllowed" {
				for b.Loop() {
					allowed, _, _ := engine.Check(keys[0], "/bench")
					if allowed != want {
						wrong.Store(true)
					}
				}
			} else {
				b.RunParallel(func(pb *testing.PB) {
					index := int(workers.Add(1)) % len(keys)
					for pb.Next() {
						allowed, _, _ := engine.Check(keys[index], "/bench")
						if allowed != want {
							wrong.Store(true)
						}
						index = (index + 1) % len(keys)
					}
				})
			}
			b.StopTimer()
			if wrong.Load() {
				b.Fatal("benchmark changed admission branch")
			}
		})
	}
}

func BenchmarkRateLimitExpiryMiddleware(b *testing.B) {
	for _, mode := range []string{"SequentialAllowed", "HotAllowed", "HotBlocked", "SpreadAllowed"} {
		b.Run(mode, func(b *testing.B) {
			stop := make(chan struct{})
			b.Cleanup(func() { close(stop) })
			limit := int64(1 << 62)
			if mode == "HotBlocked" {
				limit = 1
			}
			handler := RateLimitMiddleware(RateLimitMiddlewareConfig{MaxRequests: limit, Window: time.Hour, StopCh: stop})(func(_ *Request, resp *Response) { resp.Status(200) })
			keys := rateExpiryBenchKeys()
			if mode != "SpreadAllowed" {
				keys = keys[:1]
			}
			remotes := make([]string, len(keys))
			for i, key := range keys {
				remotes[i] = key + ":1234"
				handler(&Request{RemoteAddr: remotes[i], Path: "/bench"}, &Response{})
			}
			if mode == "HotBlocked" {
				handler(&Request{RemoteAddr: remotes[0], Path: "/bench"}, &Response{})
			}
			want := 200
			if mode == "HotBlocked" {
				want = 429
			}
			var wrong atomic.Bool
			var workers atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			if mode == "SequentialAllowed" {
				req := &Request{RemoteAddr: remotes[0], Path: "/bench"}
				resp := &Response{}
				for b.Loop() {
					resp.Reset()
					handler(req, resp)
					if resp.StatusCode != want {
						wrong.Store(true)
					}
				}
			} else {
				b.RunParallel(func(pb *testing.PB) {
					index := int(workers.Add(1)) % len(remotes)
					req := &Request{Path: "/bench"}
					resp := &Response{}
					for pb.Next() {
						req.RemoteAddr = remotes[index]
						resp.Reset()
						handler(req, resp)
						if resp.StatusCode != want {
							wrong.Store(true)
						}
						index = (index + 1) % len(remotes)
					}
				})
			}
			b.StopTimer()
			if wrong.Load() {
				b.Fatal("benchmark changed admission branch")
			}
		})
	}
}

func BenchmarkRateLimitExpiryControl(b *testing.B) {
	var state atomic.Uint64
	now, window := int64(5*time.Hour), int64(time.Hour)
	b.ReportAllocs()
	for b.Loop() {
		rlBumpCount(&state, now, window)
	}
}
