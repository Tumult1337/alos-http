//go:build linux && amd64

package core

import (
	"testing"
	"time"

	"github.com/guno1928/turbo"
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

func TestH2FileWaiterReportsStallThatFiredDuringWarmUp(t *testing.T) {
	f, _ := preadTestFile(t, fileWaitTestSize)
	w := &epollWorker{taskCh: make(chan func(*epollWorker))}
	sw := newEpollH2StreamWriter().(*epollH2StreamWriter)
	sw.w = w
	sw.file.fd, sw.file.left, sw.file.needIO = int(f.Fd()), fileWaitTestSize, true
	result := make(chan error, 1)
	go func() {
		sw.mu.Lock()
		result <- sw.waitFileLocked()
		sw.mu.Unlock()
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		sw.mu.Lock()
		warmed := !sw.file.needIO
		if warmed {
			sw.file.stallFired = true
			sw.file.armedAt = turbo.Now() - int64(h2StreamStallTimeout)
		}
		sw.mu.Unlock()
		if warmed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the waiter never finished the warm-up")
		}
		time.Sleep(time.Millisecond)
	}
	<-w.taskCh
	select {
	case err := <-result:
		if err != errH2StreamStalled {
			t.Fatalf("err %v, want errH2StreamStalled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter slept although the stall timer had already fired")
	}
}
