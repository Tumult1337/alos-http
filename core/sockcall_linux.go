//go:build linux && amd64

package core

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func socketRecv(fd int, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r, _, e := unix.RawSyscall6(unix.SYS_RECVFROM, uintptr(fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), 0, 0, 0)
	if e != 0 {
		return -1, e
	}
	return int(r), nil
}

func socketSend(fd int, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r, _, e := unix.RawSyscall6(unix.SYS_SENDTO, uintptr(fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT, 0, 0)
	if e != 0 {
		return -1, e
	}
	return int(r), nil
}

func socketAccept(lfd int, sa *unix.RawSockaddrAny, saLen *uint32) (int, error) {
	*saLen = unix.SizeofSockaddrAny
	r, _, e := unix.RawSyscall6(unix.SYS_ACCEPT4, uintptr(lfd), uintptr(unsafe.Pointer(sa)), uintptr(unsafe.Pointer(saLen)), unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0, 0)
	if e != 0 {
		return -1, e
	}
	return int(r), nil
}

func socketSendmsg(fd int, msg *unix.Msghdr) (int, error) {
	r, _, e := unix.RawSyscall6(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(msg)), unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT, 0, 0, 0)
	if e != 0 {
		return -1, e
	}
	return int(r), nil
}

func iovecOf(seg []byte) unix.Iovec {
	v := unix.Iovec{Base: &seg[0]}
	v.SetLen(len(seg))
	return v
}

func appendIovec(iov []unix.Iovec, seg []byte) []unix.Iovec {
	if len(seg) == 0 {
		return iov
	}
	return append(iov, iovecOf(seg))
}

func socketSendIovecs(fd int, iov []unix.Iovec) (int, error) {
	if len(iov) == 0 {
		return 0, nil
	}
	var msg unix.Msghdr
	msg.Iov = &iov[0]
	msg.SetIovlen(len(iov))
	n, err := socketSendmsg(fd, &msg)
	for err == unix.EINTR {
		n, err = socketSendmsg(fd, &msg)
	}
	clear(iov)
	return n, err
}
