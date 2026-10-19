//go:build linux && amd64

package core

import "sync/atomic"

const handlerPoolWorkersPerLoop = 256

type handlerPool struct {
	tasks   chan func()
	workers atomic.Int32
	limit   int32
}

func newHandlerPool(limit int) *handlerPool {
	return &handlerPool{tasks: make(chan func()), limit: int32(limit)}
}

func (p *handlerPool) run(task func()) {
	select {
	case p.tasks <- task:
		return
	default:
	}
	if p.workers.Add(1) > p.limit {
		p.workers.Add(-1)
		go task()
		return
	}
	go p.serve(task)
}

func (p *handlerPool) serve(task func()) {
	defer p.workers.Add(-1)
	for {
		task()
		next, ok := <-p.tasks
		if !ok {
			return
		}
		task = next
	}
}

func (p *handlerPool) close() {
	close(p.tasks)
}
