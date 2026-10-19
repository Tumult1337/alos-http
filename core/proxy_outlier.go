//go:build linux && amd64

package core

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/turbo"
)

const (
	defaultOutlierConsecutiveFailures = 5
	defaultOutlierBaseEject           = 30 * time.Second
	defaultOutlierMaxEject            = 5 * time.Minute
	defaultOutlierMaxEjectPercent     = 50
	outlierFailureStatus              = 500
)

type OutlierConfig struct {
	Disabled            bool
	ConsecutiveFailures int
	BaseEject           time.Duration
	MaxEject            time.Duration
	MaxEjectPercent     int
}

func (oc *OutlierConfig) normalize() {
	if oc.ConsecutiveFailures <= 0 {
		oc.ConsecutiveFailures = defaultOutlierConsecutiveFailures
	}
	if oc.BaseEject <= 0 {
		oc.BaseEject = defaultOutlierBaseEject
	}
	if oc.MaxEject <= 0 {
		oc.MaxEject = defaultOutlierMaxEject
	}
	oc.MaxEject = max(oc.MaxEject, oc.BaseEject)
	if oc.MaxEjectPercent <= 0 {
		oc.MaxEjectPercent = defaultOutlierMaxEjectPercent
	}
	oc.MaxEjectPercent = min(oc.MaxEjectPercent, 100)
}

type outlierState struct {
	consecFails    atomic.Int32
	ejectedUntilNs atomic.Int64
	ejectCount     int32
}

func (b *backend) ejected(now int64) bool { return b.outlier.ejectedUntilNs.Load() > now }

func (b *backend) available(now int64) bool { return b.Healthy.Load() && !b.ejected(now) }

type outlierDetector struct {
	cfg      OutlierConfig
	backends []*backend
	now      func() int64
	mu       sync.Mutex
}

func newOutlierDetector(cfg OutlierConfig, backends []*backend) *outlierDetector {
	return &outlierDetector{cfg: cfg, backends: backends, now: turbo.UnixNano}
}

func (d *outlierDetector) recordStatus(b *backend, status int) {
	if status >= outlierFailureStatus {
		d.recordFailure(b)
		return
	}
	d.recordSuccess(b)
}

func (d *outlierDetector) recordSuccess(b *backend) {
	if b.outlier.consecFails.Load() != 0 {
		b.outlier.consecFails.Store(0)
	}
}

func (d *outlierDetector) recordFailure(b *backend) {
	if d.cfg.Disabled {
		return
	}
	if int(b.outlier.consecFails.Add(1)) >= d.cfg.ConsecutiveFailures {
		d.eject(b)
	}
}

func (d *outlierDetector) eject(b *backend) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	st := &b.outlier
	if b.ejected(now) || int(st.consecFails.Load()) < d.cfg.ConsecutiveFailures || !d.mayEjectAnother(now) {
		return
	}
	if until := st.ejectedUntilNs.Load(); until != 0 && now-until >= int64(d.cfg.MaxEject) {
		st.ejectCount = 0
	}
	st.consecFails.Store(0)
	st.ejectedUntilNs.Store(now + int64(d.ejectDuration(st.ejectCount)))
	st.ejectCount++
}

func (d *outlierDetector) ejectDuration(priorEjections int32) time.Duration {
	dur := d.cfg.BaseEject
	for i := int32(0); i < priorEjections && dur < d.cfg.MaxEject; i++ {
		dur *= 2
	}
	return min(dur, d.cfg.MaxEject)
}

func (d *outlierDetector) mayEjectAnother(now int64) bool {
	ejected := 1
	for _, b := range d.backends {
		if b.ejected(now) {
			ejected++
		}
	}
	return ejected*100 <= d.cfg.MaxEjectPercent*len(d.backends)
}
