//go:build linux && amd64

package core

import (
	"fmt"
	"runtime"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	perfH2HeapMetric     = "/memory/classes/heap/objects:bytes"
	perfH2GCMetric       = "/gc/cycles/total:gc-cycles"
	perfH2HeapSampleTick = 2 * time.Millisecond
	perfH2ManyConns      = 8
	perfH2BytesPerMB     = 1 << 20
	perfH2PerThousand    = 1000
)

func perfH2ReadMetric(tb testing.TB, name string) uint64 {
	sample := []metrics.Sample{{Name: name}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		tb.Fatalf("runtime metric %s unavailable", name)
	}
	return sample[0].Value.Uint64()
}

type perfH2HeapPeak struct {
	stop chan struct{}
	done chan struct{}
	peak atomic.Uint64
}

func startPerfH2HeapPeak(tb testing.TB) *perfH2HeapPeak {
	p := &perfH2HeapPeak{stop: make(chan struct{}), done: make(chan struct{})}
	p.peak.Store(perfH2ReadMetric(tb, perfH2HeapMetric))
	go func() {
		defer close(p.done)
		sample := []metrics.Sample{{Name: perfH2HeapMetric}}
		for {
			select {
			case <-p.stop:
				return
			default:
			}
			metrics.Read(sample)
			if v := sample[0].Value.Uint64(); v > p.peak.Load() {
				p.peak.Store(v)
			}
			turbo.Sleep(perfH2HeapSampleTick)
		}
	}()
	return p
}

func (p *perfH2HeapPeak) finish() uint64 {
	close(p.stop)
	<-p.done
	return p.peak.Load()
}

type perfH2FailureLatch struct {
	mu  sync.Mutex
	msg string
}

func (l *perfH2FailureLatch) fail(format string, args ...any) {
	l.mu.Lock()
	if l.msg == "" {
		l.msg = fmt.Sprintf(format, args...)
	}
	l.mu.Unlock()
	runtime.Goexit()
}

func benchPerfH2Concurrent(b *testing.B, useTLS bool, wl perfH2Workload, conns, streams int) {
	addr := perfH2SharedServer(b, useTLS)
	var latch perfH2FailureLatch
	clients := make([]*perfH2Client, conns)
	for i := range clients {
		clients[i] = perfH2Ready(b, addr, useTLS, wl, streams)
		clients[i].fail = latch.fail
	}
	runtime.GC()
	gcBefore := perfH2ReadMetric(b, perfH2GCMetric)
	heap := startPerfH2HeapPeak(b)
	var issued atomic.Int64
	var wg sync.WaitGroup
	b.SetBytes(int64(wl.respLen))
	b.ReportAllocs()
	b.ResetTimer()
	for _, cl := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				start := int(issued.Add(int64(streams))) - streams
				if start >= b.N {
					return
				}
				cl.roundTrip(min(streams, b.N-start))
			}
		}()
	}
	wg.Wait()
	b.StopTimer()
	peak := heap.finish()
	if latch.msg != "" {
		b.Fatal(latch.msg)
	}
	inflight := conns * streams
	b.ReportMetric(float64(peak)/perfH2BytesPerMB, "peak-heap-MB")
	b.ReportMetric(float64(peak)/float64(inflight), "peak-heap-B/inflight-stream")
	b.ReportMetric(float64(perfH2ReadMetric(b, perfH2GCMetric)-gcBefore)*perfH2PerThousand/float64(b.N), "gc/1k-req")
}

func benchPerfH2LargeMatrix(b *testing.B, useTLS bool, wl perfH2Workload) {
	for _, conns := range []int{1, perfH2ManyConns} {
		for _, streams := range []int{1, perfH2Streams} {
			b.Run(fmt.Sprintf("conns=%d/streams=%d", conns, streams), func(b *testing.B) {
				benchPerfH2Concurrent(b, useTLS, wl, conns, streams)
			})
		}
	}
}

func BenchmarkPerfH2cLargeW5a64K(b *testing.B)   { benchPerfH2LargeMatrix(b, false, perfH2W5a) }
func BenchmarkPerfH2cLargeW5b1M(b *testing.B)    { benchPerfH2LargeMatrix(b, false, perfH2W5b) }
func BenchmarkPerfH2TLSLargeW5a64K(b *testing.B) { benchPerfH2LargeMatrix(b, true, perfH2W5a) }
func BenchmarkPerfH2TLSLargeW5b1M(b *testing.B)  { benchPerfH2LargeMatrix(b, true, perfH2W5b) }
