//go:build linux && amd64

package core

import (
	"io"
	"os"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	h1SendFileMaxCall = 1 << 30
	h1SealFileChunk   = 4 * (MaxRecordPayload - 1)
	fileWarmMax       = 256 << 10
)

func (sw *epollH1StreamWriter) admitBody(n int64) error {
	if sw.maxWrite > 0 {
		sw.written += n
		if sw.written > sw.maxWrite {
			sw.mustClose = true
			return ErrBodyTooLarge
		}
	}
	if sw.contentLength != h1NoContentLength && sw.bodyBytes+n > sw.contentLength {
		sw.mustClose = true
		return ErrBodyTooLarge
	}
	sw.bodyBytes += n
	return nil
}

func sendsFilePlainH1(req *Request) bool {
	c, ok := req.swFactory.(*epollConn)
	if !ok || c.tls || req.h2Stream != nil || c.connLimiter != nil {
		return false
	}
	global := c.worker.server.globalLimiter
	return global == nil || global.Download == nil
}

func (sw *epollH1StreamWriter) sendsFile(limiter *TokenBucket) bool {
	return limiter == nil && sw.limiter == nil && (sw.global == nil || sw.global.Download == nil) &&
		sw.headerCalled && !sw.suppressBody && !sw.chunked
}

func (sw *epollH1StreamWriter) sendFileRange(file *os.File, start, length int64, limiter *TokenBucket) (bool, error) {
	if !sw.sendsFile(limiter) {
		return false, nil
	}
	if length <= 0 {
		return true, nil
	}
	if err := sw.admitBody(length); err != nil {
		return true, err
	}
	fd := int(file.Fd())
	sw.mu.Lock()
	sw.fileFD, sw.fileOff, sw.fileLeft = fd, start, length
	queue := sw.claimPumpLocked()
	sw.mu.Unlock()
	if queue {
		sw.w.postTask(sw.pumpFn)
	}
	sw.mu.Lock()
	sw.waitFileLocked()
	err := sw.err
	sw.fileLeft = 0
	sw.mu.Unlock()
	return true, err
}

func (sw *epollH1StreamWriter) waitFileLocked() {
	for sw.err == nil && sw.fileLeft > 0 {
		if sw.fileNeedIO {
			sw.warmFileLocked()
			continue
		}
		sw.space.Wait()
	}
}

func (sw *epollH1StreamWriter) sendFileDetached(h *staticFD, start, length int64) {
	if !sw.sendsFile(nil) || length <= 0 || sw.admitBody(length) != nil {
		h.release()
		return
	}
	sw.mu.Lock()
	sw.fileRef = h
	if sw.err == nil && !sw.ended {
		sw.fileFD, sw.fileOff, sw.fileLeft = h.fd, start, length
	}
	queue := sw.claimPumpLocked()
	sw.mu.Unlock()
	if queue {
		sw.w.postTask(sw.pumpFn)
	}
}

func (c *epollConn) h1PumpFile(sw *epollH1StreamWriter) {
	sw.fileBlocked = false
	if sw.fileLeft == 0 || sw.bufferedLocked() > 0 || sw.fileNeedIO {
		return
	}
	if c.tls {
		c.h1SealFile(sw)
		return
	}
	if c.writeSent < len(c.writeBuf) && (len(c.bodyOut) > 0 || sw.fileLeft > h1OutSocketHighMark || !c.h1SendHeadMore()) {
		return
	}
	progressed := false
	for sw.fileLeft > 0 {
		n, err := unix.Sendfile(c.fd, sw.fileFD, &sw.fileOff, int(min(sw.fileLeft, h1SendFileMaxCall)))
		if n > 0 {
			sw.fileLeft -= int64(n)
			c.worker.bytesOut += uint64(n)
			progressed = true
			continue
		}
		switch err {
		case unix.EINTR:
			continue
		case unix.EAGAIN:
			sw.fileBlocked, sw.fileProgress = true, progressed
			return
		case nil:
			err = io.ErrUnexpectedEOF
		}
		sw.failFile(err)
		return
	}
}

func (c *epollConn) h1SendHeadMore() bool {
	if c.lingering || c.outArmed {
		return false
	}
	for c.writeSent < len(c.writeBuf) {
		p := c.writeBuf[c.writeSent:]
		r, _, errno := unix.RawSyscall6(unix.SYS_SENDTO, uintptr(c.fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT|unix.MSG_MORE, 0, 0)
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 || r == 0 {
			return false
		}
		c.worker.bytesOut += uint64(r)
		c.writeSent += int(r)
	}
	c.writeBuf, c.writeSent = c.writeBuf[:0], 0
	return true
}

var h1SealFileColdReads atomic.Uint64

func (c *epollConn) h1SealFile(sw *epollH1StreamWriter) {
	room := c.h1OutRoom()
	if room <= 0 {
		return
	}
	bp := FileReadBufPool.Get().(*[]byte)
	buf := (*bp)[:min(len(*bp), h1SealFileChunk)]
	for room > 0 && sw.fileLeft > 0 {
		chunk := buf[:min(int64(len(buf)), int64(room), sw.fileLeft)]
		iov := [1]unix.Iovec{{Base: &chunk[0]}}
		iov[0].SetLen(len(chunk))
		n, err := preadvAll(sw.fileFD, iov[:], sw.fileOff, unix.RWF_NOWAIT)
		if n > 0 {
			c.writeBuf = c.sealTLSAppData(c.writeBuf, buf[:n])
			sw.fileOff += int64(n)
			sw.fileLeft -= int64(n)
			room -= n
		}
		if err == unix.EAGAIN {
			h1SealFileColdReads.Add(1)
			sw.fileNeedIO = true
			break
		}
		if err != nil {
			sw.failFile(err)
			break
		}
	}
	FileReadBufPool.Put(bp)
}

func (sw *epollH1StreamWriter) warmFileLocked() {
	fd, off, n := sw.fileFD, sw.fileOff, min(sw.fileLeft, fileWarmMax)
	sw.mu.Unlock()
	err := warmFileRange(fd, off, n)
	sw.mu.Lock()
	sw.fileNeedIO = false
	if err != nil {
		if sw.err == nil {
			sw.failFile(err)
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

func preadvAll(fd int, iov []unix.Iovec, off int64, flags int) (int, error) {
	total := 0
	for {
		for len(iov) > 0 && iov[0].Len == 0 {
			iov = iov[1:]
		}
		if len(iov) == 0 {
			return total, nil
		}
		n, err := preadvFlags(fd, iov, off, flags)
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrUnexpectedEOF
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
}

func preadvFlags(fd int, iov []unix.Iovec, off int64, flags int) (int, error) {
	for {
		r, _, errno := unix.Syscall6(unix.SYS_PREADV2, uintptr(fd), uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)), uintptr(off), 0, uintptr(flags))
		switch errno {
		case 0:
			return int(r), nil
		case unix.EINTR:
			continue
		case unix.EOPNOTSUPP, unix.EINVAL:
			if flags != 0 {
				flags = 0
				continue
			}
		}
		return 0, errno
	}
}

func warmFileRange(fd int, off, n int64) error {
	bp := FileReadBufPool.Get().(*[]byte)
	defer FileReadBufPool.Put(bp)
	buf := *bp
	for n > 0 {
		chunk := buf[:min(int64(len(buf)), n)]
		iov := [1]unix.Iovec{{Base: &chunk[0]}}
		iov[0].SetLen(len(chunk))
		got, err := preadvAll(fd, iov[:], off, 0)
		if err != nil {
			return err
		}
		off += int64(got)
		n -= int64(got)
	}
	return nil
}

func (sw *epollH1StreamWriter) failFile(err error) {
	sw.err, sw.mustClose, sw.fileLeft = err, true, 0
}

func (c *epollConn) h1FileBlocked(w *epollWorker) bool {
	sw := c.h1Stream
	if sw == nil || !sw.fileBlocked {
		return false
	}
	if sw.fileProgress && c.outArmed {
		c.deadline = w.wsOutDeadline(c)
	}
	sw.fileProgress = false
	w.armOut(c)
	return true
}
