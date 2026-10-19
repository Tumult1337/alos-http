//go:build linux && amd64

package core

const (
	sweepIntervalNano    = int64(250 * 1e6)
	minSweepIntervalNano = int64(10 * 1e6)
	sweepsPerTimeout     = 4
	nanosPerMilli        = int64(1e6)
)

func (l *beLoop) sweepEvery() int64 {
	if l.sweepEveryNano == 0 {
		return sweepIntervalNano
	}
	return l.sweepEveryNano
}

func (l *beLoop) tightenSweep(ex *Exchange, now int64) {
	shortest := ex.deadline - now
	if r := ex.readTimeoutNano; r > 0 && r < shortest {
		shortest = r
	}
	every := min(max(shortest/sweepsPerTimeout, minSweepIntervalNano), sweepIntervalNano)
	if every < l.sweepEvery() {
		l.sweepEveryNano = every
	}
}

func (l *beLoop) maybeSweep(now int64) {
	if l.liveConns == 0 {
		return
	}
	if now-l.lastSweep < l.sweepEvery() {
		return
	}
	l.lastSweep = now
	l.sweepBackends(now)
}

func (l *beLoop) nextTimeoutMs() int {
	if l.liveConns == 0 {
		return maxEpollWaitMs
	}
	remaining := l.lastSweep + l.sweepEvery() - l.nowNano()
	if remaining <= 0 {
		return 0
	}
	return int((remaining + nanosPerMilli - 1) / nanosPerMilli)
}
