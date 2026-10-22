//go:build linux && amd64

package core

import (
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const nativeSendFileChunk = 64 << 10

var nativeSendFileHook func(wrote int64)

func trySendFileFastPath(sw StreamWriter, file *os.File, start, length int64, limiter *TokenBucket) (bool, error) {
	if epollWriter, ok := sw.(*epollH1StreamWriter); ok {
		return epollWriter.sendFileRange(file, start, length, limiter)
	}
	if h2Writer, ok := sw.(*epollH2StreamWriter); ok {
		return h2Writer.sendFileRange(file, start, length, limiter)
	}
	writer, ok := sw.(*PlainH1StreamWriter)
	if !ok || !writer.headersSent || writer.chunked || writer.suppressBody {
		return false, nil
	}
	return writer.tryWriteFileNative(file, start, length, limiter)
}

func (w *PlainH1StreamWriter) tryWriteFileNative(file *os.File, start, length int64, limiter *TokenBucket) (bool, error) {
	if length <= 0 {
		return true, nil
	}

	outFD, deadline, unlock, ok, err := nativeSendFileTarget(w.conn)
	if err != nil {
		return true, err
	}
	if !ok {
		return false, nil
	}
	defer unlock()

	inFD := int(file.Fd())
	if inFD < 0 {
		return true, net.ErrClosed
	}
	return true, sendFileFD(outFD, inFD, start, length, deadline, w.limiter, w.global, limiter)
}

func nativeSendFileTarget(conn net.Conn) (int, time.Time, func(), bool, error) {
	if conn == nil {
		return 0, time.Time{}, func() {}, true, net.ErrClosed
	}
	rawProvider, ok := conn.(syscall.Conn)
	if !ok {
		return 0, time.Time{}, func() {}, false, nil
	}
	rawConn, err := rawProvider.SyscallConn()
	if err != nil {
		return 0, time.Time{}, func() {}, true, err
	}
	outFD := -1
	controlErr := rawConn.Control(func(fd uintptr) {
		outFD = int(fd)
	})
	if controlErr != nil {
		return 0, time.Time{}, func() {}, true, controlErr
	}
	if outFD < 0 {
		return 0, time.Time{}, func() {}, false, nil
	}
	return outFD, time.Time{}, func() {}, true, nil
}

func sendFileFD(outFD int, inFD int, start, length int64, deadline time.Time, connLimiter *ConnectionLimiter, global *GlobalLimiter, limiter *TokenBucket) error {
	offset := start
	remaining := length
	for remaining > 0 {
		chunk := remaining
		if chunk > nativeSendFileChunk {
			chunk = nativeSendFileChunk
		}

		n, err := unix.Sendfile(outFD, inFD, &offset, int(chunk))
		if n > 0 {
			wrote := int64(n)
			Stats.BytesOut.Add(uint64(n))
			if nativeSendFileHook != nil {
				nativeSendFileHook(wrote)
			}
			if connLimiter != nil {
				connLimiter.ThrottleDownload(wrote)
			}
			if global != nil && global.Download != nil {
				global.Download.Wait(wrote)
			}
			if limiter != nil {
				limiter.Wait(wrote)
			}
			remaining -= wrote
			continue
		}

		if err == nil {
			return io.ErrUnexpectedEOF
		}
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			if waitErr := waitSendFileWritable(outFD, deadline); waitErr != nil {
				return waitErr
			}
			continue
		}
		return err
	}
	return nil
}

func waitSendFileWritable(fd int, deadline time.Time) error {
	pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	for {
		timeout := -1
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return errNetDeadlineExceeded
			}
			timeout = int((remaining + time.Millisecond - 1) / time.Millisecond)
			if timeout < 1 {
				timeout = 1
			}
		}

		n, err := unix.Poll(pollFDs, timeout)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return errNetDeadlineExceeded
		}
		revents := pollFDs[0].Revents
		if revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return syscall.EPIPE
		}
		if revents&unix.POLLOUT != 0 {
			return nil
		}
	}
}
