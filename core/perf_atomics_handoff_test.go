//go:build linux && amd64

package core

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

const perfHandoffConnsPerProducer = 32

type perfH1DoneHarness struct {
	w    *epollWorker
	busy map[*epollConn]*atomic.Bool
	stop chan struct{}
	done chan struct{}
}

func newPerfH1DoneHarness(producers int) (*perfH1DoneHarness, [][]*epollConn) {
	h := &perfH1DoneHarness{
		w:    &epollWorker{},
		busy: make(map[*epollConn]*atomic.Bool),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	rings := make([][]*epollConn, producers)
	for p := range rings {
		rings[p] = make([]*epollConn, perfHandoffConnsPerProducer)
		for i := range rings[p] {
			c := &epollConn{}
			rings[p][i] = c
			h.busy[c] = new(atomic.Bool)
		}
	}
	return h, rings
}

func (h *perfH1DoneHarness) drainOnce() int {
	h.w.taskPending.Store(false)
	n := 0
	for c := h.w.h1Done.Swap(nil); c != nil; {
		next := c.h1DoneNext
		c.h1DoneNext = nil
		h.busy[c].Store(false)
		c = next
		n++
	}
	return n
}

func (h *perfH1DoneHarness) consume() {
	defer close(h.done)
	for {
		select {
		case <-h.stop:
			h.drainOnce()
			return
		default:
		}
		if h.drainOnce() == 0 {
			runtime.Gosched()
		}
	}
}

func (h *perfH1DoneHarness) produce(ring []*epollConn, i int) {
	c := ring[i%len(ring)]
	flag := h.busy[c]
	for flag.Load() {
		runtime.Gosched()
	}
	flag.Store(true)
	h.w.pushH1Done(c)
}

func BenchmarkPerfAtomicsCompletionHandoff(b *testing.B) {
	b.Run("h1_pushH1Done_lockfree_stack", func(b *testing.B) {
		b.ReportAllocs()
		producers := runtime.GOMAXPROCS(0) * 4
		h, rings := newPerfH1DoneHarness(producers)
		go h.consume()
		var next atomic.Int32
		b.RunParallel(func(pb *testing.PB) {
			ring := rings[int(next.Add(1)-1)%producers]
			i := 0
			for pb.Next() {
				h.produce(ring, i)
				i++
			}
		})
		close(h.stop)
		<-h.done
	})
	b.Run("h2_postTask_closure_channel", func(b *testing.B) {
		b.ReportAllocs()
		w := &epollWorker{taskCh: make(chan func(*epollWorker), epollTaskQueueSize)}
		var ran atomic.Int64
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case fn := <-w.taskCh:
					fn(w)
				case <-stop:
					for {
						select {
						case fn := <-w.taskCh:
							fn(w)
						default:
							return
						}
					}
				}
			}
		}()
		b.RunParallel(func(pb *testing.PB) {
			cc := &epollConn{}
			stream := &H2Stream{}
			var counter uint32
			for pb.Next() {
				counter++
				gen := counter
				sid := counter * 2
				w.postTask(func(w *epollWorker) {
					if cc != nil && stream != nil && sid != gen+1 {
						ran.Add(1)
					}
				})
			}
		})
		close(stop)
		<-done
	})
}

func BenchmarkPerfAtomicsHandlerPoolRun(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		p := newHandlerPool(handlerPoolWorkersPerLoop)
		var wg sync.WaitGroup
		task := func() { wg.Done() }
		for pb.Next() {
			wg.Add(1)
			p.run(task)
		}
		wg.Wait()
		p.close()
	})
}
