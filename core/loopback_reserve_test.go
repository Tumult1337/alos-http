//go:build linux && amd64

package core

import (
	"fmt"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func reserveLoopbackPort() (string, func() error, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return "", nil, fmt.Errorf("reservation socket: %w", err)
	}
	release := func() error { return unix.Close(fd) }
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		_ = release()
		return "", nil, fmt.Errorf("reservation SO_REUSEADDR: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		_ = release()
		return "", nil, fmt.Errorf("reservation SO_REUSEPORT: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		_ = release()
		return "", nil, fmt.Errorf("reservation bind: %w", err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		_ = release()
		return "", nil, fmt.Errorf("reservation getsockname: %w", err)
	}
	inet4, ok := bound.(*unix.SockaddrInet4)
	if !ok {
		_ = release()
		return "", nil, fmt.Errorf("reservation bound to %T", bound)
	}
	return netip.AddrPortFrom(netip.AddrFrom4(inet4.Addr), uint16(inet4.Port)).String(), release, nil
}

func freeLoopbackAddr(t testing.TB) string {
	t.Helper()
	addr, release, err := reserveLoopbackPort()
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	t.Cleanup(func() {
		if err := release(); err != nil {
			t.Errorf("release loopback port %s: %v", addr, err)
		}
	})
	return addr
}
