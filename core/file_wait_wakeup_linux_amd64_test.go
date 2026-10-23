//go:build linux && amd64

package core

import (
	"testing"
	"time"
)

const fileWaitTestSize = 4096

func fileWaitTestWorker() *epollWorker {
	return &epollWorker{taskCh: make(chan func(*epollWorker), 4)}
}

func awaitWarmTask(t *testing.T, w *epollWorker, finish func()) {
	t.Helper()
	select {
	case <-w.taskCh:
		finish()
	case <-time.After(2 * time.Second):
		t.Fatal("the file waiter slept although the pump had already requested a warm-up")
	}
}

func TestH1FileWaiterWarmsWhenNeedIOIsAlreadySet(t *testing.T) {
	f, _ := preadTestFile(t, fileWaitTestSize)
	w := fileWaitTestWorker()
	sw := newEpollH1StreamWriter().(*epollH1StreamWriter)
	sw.w = w
	sw.fileFD, sw.fileLeft, sw.fileNeedIO = int(f.Fd()), fileWaitTestSize, true
	done := make(chan struct{})
	go func() {
		sw.mu.Lock()
		sw.waitFileLocked()
		sw.mu.Unlock()
		close(done)
	}()
	awaitWarmTask(t, w, func() {
		sw.mu.Lock()
		sw.fileLeft = 0
		sw.space.Broadcast()
		sw.mu.Unlock()
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the file waiter did not finish")
	}
}

func TestH2FileWaiterWarmsWhenNeedIOIsAlreadySet(t *testing.T) {
	f, _ := preadTestFile(t, fileWaitTestSize)
	w := fileWaitTestWorker()
	sw := newEpollH2StreamWriter().(*epollH2StreamWriter)
	sw.w = w
	sw.file.fd, sw.file.left, sw.file.needIO = int(f.Fd()), fileWaitTestSize, true
	done := make(chan struct{})
	go func() {
		sw.mu.Lock()
		_ = sw.waitFileLocked()
		sw.mu.Unlock()
		close(done)
	}()
	awaitWarmTask(t, w, func() {
		sw.mu.Lock()
		sw.file.left = 0
		sw.space.Broadcast()
		sw.mu.Unlock()
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the file waiter did not finish")
	}
}
