//go:build linux && amd64

package core

import (
	"net/netip"

	"golang.org/x/sys/unix"
)

func upstreamSockaddr(addr netip.Addr, port uint16) (int, unix.Sockaddr) {
	if addr.Is4() {
		return unix.AF_INET, &unix.SockaddrInet4{Port: int(port), Addr: addr.As4()}
	}
	return unix.AF_INET6, &unix.SockaddrInet6{Port: int(port), Addr: addr.As16()}
}

func dialNonBlocking(addr netip.Addr, port uint16) (int, error) {
	family, sa := upstreamSockaddr(addr, port)
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return -1, err
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	err = unix.Connect(fd, sa)
	if err != nil && err != unix.EINPROGRESS {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func socketError(fd int) error {
	v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return err
	}
	if v != 0 {
		return unix.Errno(v)
	}
	return nil
}
