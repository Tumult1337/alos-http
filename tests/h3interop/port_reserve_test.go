package h3interop

import (
	"net/netip"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func reserveH3Port(t *testing.T) (string, func()) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("reservation socket: %v", err)
	}
	var once sync.Once
	release := func() { once.Do(func() { _ = syscall.Close(fd) }) }
	t.Cleanup(release)
	if err := syscall.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		t.Fatalf("reservation SO_REUSEPORT: %v", err)
	}
	loopback := [4]byte{127, 0, 0, 1}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: loopback}); err != nil {
		t.Fatalf("reservation bind: %v", err)
	}
	bound, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatalf("reservation getsockname: %v", err)
	}
	inet4, ok := bound.(*syscall.SockaddrInet4)
	if !ok {
		t.Fatalf("reservation bound to %T", bound)
	}
	return netip.AddrPortFrom(netip.AddrFrom4(loopback), uint16(inet4.Port)).String(), release
}
