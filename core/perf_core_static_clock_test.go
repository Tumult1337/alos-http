//go:build linux && amd64

package core

import (
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const perfCoreStaticSettleSkew = time.Hour

func perfCoreSettleStaticFiles(tb testing.TB) {
	tb.Helper()
	prev := staticCacheClock
	staticCacheClock = func() int64 { return turbo.UnixNano() + int64(perfCoreStaticSettleSkew) }
	tb.Cleanup(func() { staticCacheClock = prev })
}
