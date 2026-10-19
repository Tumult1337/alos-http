//go:build linux && amd64

package core

import (
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	appFixBucketBurst        = 65536
	appFixBucketReturnWithin = 150 * time.Millisecond
	appFixDocExampleMbps     = 100 << 20
	appFixElapsedSteps       = 50
	appFixElapsedStep        = 10*time.Millisecond + 7*time.Microsecond
)

func appFixDrainedBucket(t *testing.T, rate, burst int64) *TokenBucket {
	t.Helper()
	tb := NewTokenBucket(rate, burst)
	if !tb.Allow(burst) {
		t.Fatalf("a fresh bucket refused its full burst of %d", burst)
	}
	return tb
}

func appFixRefillAfter(tb *TokenBucket, elapsed time.Duration) int64 {
	tb.tokens.Store(0)
	tb.lastTime.Store(CoarseNanotime() - int64(elapsed))
	tb.refill()
	return tb.tokens.Load()
}

func TestAppFixTokenBucketLargeRateRefillsWithoutOverflow(t *testing.T) {
	tb := appFixDrainedBucket(t, appFixDocExampleMbps*125000, appFixBucketBurst)
	for step := 1; step <= appFixElapsedSteps; step++ {
		elapsed := time.Duration(step) * appFixElapsedStep
		if got := appFixRefillAfter(tb, elapsed); got != appFixBucketBurst {
			t.Fatalf("after %v idle a %d B/s bucket holds %d tokens, want the full burst %d", elapsed, tb.rate, got, appFixBucketBurst)
		}
	}
}

func TestAppFixTokenBucketLongIdleAtHighRateFillsToBurst(t *testing.T) {
	const hugeBurst = 1 << 62
	tb := appFixDrainedBucket(t, 1<<62, hugeBurst)
	if got := appFixRefillAfter(tb, 90*time.Second); got != hugeBurst {
		t.Fatalf("after a long idle the bucket holds %d tokens, want %d", got, int64(hugeBurst))
	}
}

func TestAppFixTokenBucketFractionalRefillIsExact(t *testing.T) {
	const rate = 1000
	tb := appFixDrainedBucket(t, rate, 10*rate)
	got := appFixRefillAfter(tb, 500*time.Millisecond)
	if got < rate/2 || got > rate/2+rate/100 {
		t.Fatalf("500ms at %d tokens/s refilled %d tokens, want about %d", rate, got, rate/2)
	}
}

func TestAppFixBandwidthRatesAreCappedNotOverflowed(t *testing.T) {
	cfg := BandwidthConfig{MaxUploadRate: 1 << 62, MaxDownloadRate: appFixDocExampleMbps, BurstSize: 1 << 62}
	want := int64(maxBandwidthMbps) * bytesPerMbps
	conn, global := NewConnectionLimiter(cfg), NewGlobalLimiter(cfg)
	for name, tb := range map[string]*TokenBucket{"conn upload": conn.Upload, "conn download": conn.Download, "global upload": global.Upload, "global download": global.Download} {
		if tb.rate != want || tb.burst != want {
			t.Errorf("%s bucket rate %d burst %d, want both capped at %d (%d Mbps)", name, tb.rate, tb.burst, want, maxBandwidthMbps)
		}
	}
}

func appFixReturnsPromptly(t *testing.T, what string, call func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		call()
		close(done)
	}()
	select {
	case <-done:
	case <-turbo.After(appFixBucketReturnWithin):
		t.Fatalf("%s did not return within %v", what, appFixBucketReturnWithin)
	}
}

func TestAppFixTokenBucketZeroBurstDoesNotSpin(t *testing.T) {
	tb := NewTokenBucket(1000, 0)
	appFixReturnsPromptly(t, "NewTokenBucket(1000, 0).Wait(1)", func() { tb.Wait(1) })
	appFixReturnsPromptly(t, "NewTokenBucket(1000, 0).WaitWithDeadline(1, ...)", func() {
		tb.WaitWithDeadline(1, time.Unix(0, turbo.UnixNano()+int64(appFixBucketReturnWithin/2)))
	})
	if !tb.Allow(1) {
		t.Fatal("a bucket built with burst 0 refused a single token")
	}
}

func TestAppFixTokenBucketNonPositiveRateIsUnlimited(t *testing.T) {
	for _, rate := range []int64{0, -5} {
		tb := NewTokenBucket(rate, 10)
		appFixReturnsPromptly(t, "Wait on a rate<=0 bucket", func() { tb.Wait(1 << 30) })
		if !tb.Allow(1 << 30) {
			t.Fatalf("rate %d bucket refused tokens, want it unthrottled", rate)
		}
		if !tb.WaitWithDeadline(1<<30, time.Unix(0, turbo.UnixNano())) {
			t.Fatalf("rate %d bucket failed WaitWithDeadline, want it unthrottled", rate)
		}
	}
	var zero TokenBucket
	appFixReturnsPromptly(t, "Wait on a zero-value TokenBucket", func() { zero.Wait(1) })
}

func BenchmarkAppFixTokenBucketAllow(b *testing.B) {
	tb := NewTokenBucket(1<<40, 1<<30)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tb.Allow(1024)
	}
}

func BenchmarkAppFixTokenBucketRefill(b *testing.B) {
	tb := NewTokenBucket(1_000_000_000, 1<<30)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tb.tokens.Store(0)
		tb.lastTime.Store(CoarseNanotime() - 1_500_000)
		tb.refill()
	}
}

func TestAppFixSendFileRateOptionsAreCapped(t *testing.T) {
	want := int64(maxBandwidthMbps) * bytesPerMbps
	var single, burst sendFileConfig
	WithRateLimit(1 << 62)(&single)
	WithRateLimitBurst(1<<62, 1<<62)(&burst)
	if single.rateLimit != want || single.burstSize != want || burst.rateLimit != want || burst.burstSize != want {
		t.Fatalf("rate/burst WithRateLimit %d/%d, WithRateLimitBurst %d/%d, want all capped at %d", single.rateLimit, single.burstSize, burst.rateLimit, burst.burstSize, want)
	}
	var floor sendFileConfig
	WithRateLimitBurst(0, 0)(&floor)
	if floor.rateLimit != bytesPerMbps || floor.burstSize != bytesPerMbps {
		t.Fatalf("WithRateLimitBurst(0, 0) gave %d/%d, want the 1 Mbps floor %d", floor.rateLimit, floor.burstSize, bytesPerMbps)
	}
}
