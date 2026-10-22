//go:build linux && amd64

package core

import (
	"io"
	"os"
	"slices"
	"unsafe"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const h2FileMaxFrames = 64

type h2FileSend struct {
	fd         int
	off        int64
	left       int64
	stall      *turbo.Timer
	stallFired bool
	needIO     bool
	armedAt    int64
}

func (f *h2FileSend) clear() {
	f.fd, f.off, f.left = 0, 0, 0
	f.stallFired, f.needIO, f.armedAt = false, false, 0
}

func (sw *epollH2StreamWriter) sendFileRange(file *os.File, start, length int64, limiter *TokenBucket) (bool, error) {
	if limiter != nil || !sw.headerCalled || sw.suppressBody {
		return false, nil
	}
	if length <= 0 {
		return true, nil
	}
	if sw.maxWrite > 0 {
		sw.written += length
		if sw.written > sw.maxWrite {
			return true, ErrBodyTooLarge
		}
	}
	fd := int(file.Fd())
	sw.mu.Lock()
	if sw.err != nil || sw.ended {
		err := sw.err
		sw.mu.Unlock()
		if err == nil {
			err = ErrStreamClosed
		}
		return true, err
	}
	sw.file.fd, sw.file.off, sw.file.left = fd, start, length
	queue := sw.claimPumpLocked()
	sw.mu.Unlock()
	if queue {
		sw.w.postTask(sw.pumpFn)
	}
	sw.mu.Lock()
	err := sw.waitFileLocked()
	sw.file.left = 0
	sw.mu.Unlock()
	return true, err
}

func (sw *epollH2StreamWriter) waitFileLocked() error {
	if sw.err != nil || sw.file.left == 0 {
		return sw.err
	}
	sw.armFileStallLocked()
	mark := sw.file.off
	for sw.err == nil && sw.file.left > 0 {
		sw.space.Wait()
		if sw.file.needIO {
			sw.warmFileLocked()
		}
		if !sw.file.stallFired {
			continue
		}
		sw.file.stallFired = false
		if turbo.Now()-sw.file.armedAt < int64(h2StreamStallTimeout)/2 {
			continue
		}
		if sw.file.off == mark {
			sw.err = errH2StreamStalled
			sw.sendRST = true
			break
		}
		mark = sw.file.off
		sw.armFileStallLocked()
	}
	sw.file.stall.Stop()
	return sw.err
}

func (sw *epollH2StreamWriter) armFileStallLocked() {
	sw.file.stallFired = false
	sw.file.armedAt = turbo.Now()
	if sw.file.stall == nil {
		sw.file.stall = turbo.AfterFunc(h2StreamStallTimeout, sw.fileStallFired)
		return
	}
	sw.file.stall.Reset(h2StreamStallTimeout)
}

func (sw *epollH2StreamWriter) warmFileLocked() {
	fd, off, n := sw.file.fd, sw.file.off, min(sw.file.left, h2StreamSocketHighMark)
	sw.mu.Unlock()
	err := warmFileRange(fd, off, n)
	sw.mu.Lock()
	sw.file.needIO = false
	if err != nil {
		if sw.err == nil {
			sw.err, sw.sendRST, sw.file.left = err, true, 0
		}
		return
	}
	queue := sw.claimPumpLocked()
	sw.mu.Unlock()
	if queue {
		sw.w.postTask(sw.pumpFn)
	}
	sw.mu.Lock()
}

func (sw *epollH2StreamWriter) fileStallFired() {
	sw.mu.Lock()
	sw.file.stallFired = true
	sw.space.Broadcast()
	sw.mu.Unlock()
}

func (c *epollConn) h2PumpFile(dst []byte, sw *epollH2StreamWriter, room, frameLimit int) []byte {
	st := &c.h2
	avail := min(sw.stream.Window.Load(), st.connWindow, sw.file.left, int64(room), int64(frameLimit)*h2FileMaxFrames)
	if avail <= 0 || sw.file.needIO {
		return dst
	}
	frames := int((avail + int64(frameLimit) - 1) / int64(frameLimit))
	extra := int(avail) + frames*h2FrameHeaderLen
	base := len(dst)
	dst = slices.Grow(growIOBuf(dst, extra), extra)
	d := &c.worker.h2Direct
	iov := d.iov[:0]
	for left := int(avail); left > 0; {
		n := min(left, frameLimit)
		dst = appendH2FrameHeader(dst, H2FrameData, 0, sw.streamID, n)
		hole := dst[len(dst) : len(dst)+n]
		v := unix.Iovec{Base: &hole[0]}
		v.SetLen(n)
		iov = append(iov, v)
		dst = dst[:len(dst)+n]
		left -= n
	}
	got, err := preadvFull(sw.file.fd, iov, sw.file.off)
	clear(iov)
	d.iov = iov[:0]
	if err == unix.EAGAIN || (err == nil && got > 0 && int64(got) < avail) {
		sw.file.needIO = true
		return dst[:base]
	}
	if err != nil || int64(got) != avail {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		sw.err, sw.sendRST, sw.file.left = err, true, 0
		return dst[:base]
	}
	sw.file.off += avail
	sw.file.left -= avail
	st.connWindow -= avail
	sw.stream.Window.Add(-avail)
	return dst
}

func preadvFull(fd int, iov []unix.Iovec, off int64) (int, error) {
	total := 0
	for len(iov) > 0 {
		n, err := preadvFlags(fd, iov, off, unix.RWF_NOWAIT)
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
		total += n
		off += int64(n)
		for len(iov) > 0 && n >= int(iov[0].Len) {
			n -= int(iov[0].Len)
			iov = iov[1:]
		}
		if n > 0 {
			iov[0].Base = (*byte)(unsafe.Add(unsafe.Pointer(iov[0].Base), n))
			iov[0].SetLen(int(iov[0].Len) - n)
		}
	}
	return total, nil
}
