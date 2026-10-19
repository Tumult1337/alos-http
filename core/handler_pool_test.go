//go:build linux && amd64

package core

import (
	"sync"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	poolTestCeiling      = 2 * time.Second
	poolTestPollInterval = 2 * time.Millisecond
	deepStackDepth       = 14
)

func waitForPool(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := turbo.Deadline(poolTestCeiling)
	for !cond() {
		if turbo.Until(deadline) <= 0 {
			t.Fatalf("timed out waiting for %s", what)
		}
		turbo.Sleep(poolTestPollInterval)
	}
}

func handOffToIdleWorker(t testing.TB, p *handlerPool, task func()) {
	t.Helper()
	waitForPool(t, "an idle worker", func() bool {
		select {
		case p.tasks <- task:
			return true
		default:
			return false
		}
	})
}

func TestHandlerPoolReusesAnIdleWorker(t *testing.T) {
	p := newHandlerPool(handlerPoolWorkersPerLoop)
	defer p.close()
	done := make(chan struct{})
	p.run(func() { done <- struct{}{} })
	<-done
	for range 100 {
		handOffToIdleWorker(t, p, func() { done <- struct{}{} })
		<-done
		if n := p.workers.Load(); n != 1 {
			t.Fatalf("sequential tasks used %d workers, want 1", n)
		}
	}
}

func TestHandlerPoolOverflowsPastItsLimit(t *testing.T) {
	const limit, tasks = 2, 10
	p := newHandlerPool(limit)
	defer p.close()
	release := make(chan struct{})
	var started, finished sync.WaitGroup
	started.Add(tasks)
	finished.Add(tasks)
	for range tasks {
		p.run(func() {
			started.Done()
			<-release
			finished.Done()
		})
	}
	started.Wait()
	if n := p.workers.Load(); n != limit {
		t.Fatalf("pool holds %d workers, want its limit %d", n, limit)
	}
	close(release)
	finished.Wait()
}

func TestHandlerPoolCloseStopsIdleWorkers(t *testing.T) {
	p := newHandlerPool(handlerPoolWorkersPerLoop)
	var finished sync.WaitGroup
	finished.Add(3)
	for range 3 {
		p.run(func() { finished.Done() })
	}
	finished.Wait()
	p.close()
	waitForPool(t, "workers to exit", func() bool { return p.workers.Load() == 0 })
}

//go:noinline
func burnStack(depth int) byte {
	var pad [512]byte
	pad[depth%len(pad)] = byte(depth)
	if depth == 0 {
		return pad[0]
	}
	return burnStack(depth-1) + pad[(depth*7)%len(pad)]
}

func BenchmarkDeepHandler(b *testing.B) {
	done := make(chan struct{})
	task := func() {
		burnStack(deepStackDepth)
		done <- struct{}{}
	}
	b.Run("goroutine-per-task", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			go task()
			<-done
		}
	})
	b.Run("pooled", func(b *testing.B) {
		p := newHandlerPool(handlerPoolWorkersPerLoop)
		defer p.close()
		b.ReportAllocs()
		for b.Loop() {
			p.run(task)
			<-done
		}
	})
}
