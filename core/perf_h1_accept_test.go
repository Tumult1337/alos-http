//go:build linux && amd64

package core

import (
	"context"
	"net"
	"strconv"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func perfH1AcceptedFd(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	return fd
}

func perfH1FdOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err != unix.EBADF
}

func TestPerfH1AcceptAfterShutdownDrainedIsRefused(t *testing.T) {
	srv := New(Config{Addr: freeLoopbackAddr(t), HTTPAddr: "-", MaxConnsPerIP: -1})
	ctx, cancel := context.WithTimeout(context.Background(), harnessIOTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown with no connections: %v", err)
	}
	w := &epollWorker{server: srv}
	fd := perfH1AcceptedFd(t)
	admitted := w.admitAccepted(fd, srv.limits.Load())
	if admitted {
		_ = unix.Close(fd)
		srv.releaseTrackedConn()
		t.Fatalf("a connection accepted after Shutdown had already drained was admitted (activeConns=%d): it would be served after Shutdown returned", srv.activeConns.Load()+1)
	}
	if n := srv.activeConns.Load(); n != 0 {
		t.Fatalf("activeConns=%d after refusing the late connection, want 0", n)
	}
	if perfH1FdOpen(fd) {
		_ = unix.Close(fd)
		t.Fatalf("the refused connection's fd was left open")
	}
}

func TestPerfH1RemoteAddrMatchesNetFormatting(t *testing.T) {
	cases := []struct {
		ip   [4]byte
		port int
	}{{[4]byte{127, 0, 0, 1}, 18080}, {[4]byte{0, 0, 0, 0}, 0}, {[4]byte{255, 255, 255, 255}, 65535}, {[4]byte{10, 1, 200, 9}, 443}}
	for _, tc := range cases {
		var rsa unix.RawSockaddrAny
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(&rsa))
		sa4.Family = unix.AF_INET
		sa4.Addr = tc.ip
		port := (*[2]byte)(unsafe.Pointer(&sa4.Port))
		port[0], port[1] = byte(tc.port>>8), byte(tc.port)
		want := net.IP(tc.ip[:]).String() + ":" + strconv.Itoa(tc.port)
		if got := epollRemoteAddr(&rsa); got != want {
			t.Fatalf("epollRemoteAddr = %q, want %q", got, want)
		}
	}
	var v6 unix.RawSockaddrAny
	v6.Addr.Family = unix.AF_INET6
	if got := epollRemoteAddr(&v6); got != "" {
		t.Fatalf("non-IPv4 address formatted as %q, want empty", got)
	}
}

func TestPerfH1AcceptedSocketsGetConnSockopts(t *testing.T) {
	addr := freeLoopbackAddr(t)
	lfd, err := epollListen(addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer unix.Close(lfd)
	client, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	w := &epollWorker{}
	var nfd int
	waitFor(t, harnessIOTimeout, func() bool {
		nfd, err = socketAccept(lfd, &w.acceptAddr, &w.acceptAddrLen)
		return err == nil
	})
	defer unix.Close(nfd)
	w.configureAccepted(nfd)
	if !connSockoptsApplied(nfd) {
		t.Fatalf("accepted socket lacks TCP_NODELAY or TCP_NOTSENT_LOWAT=%d", epollNotSentLowat)
	}
	t.Logf("listener options inherited by accepted sockets: %v", w.sockoptInherit == sockoptInheritYes)

	raw := perfH1AcceptedFd(t)
	defer unix.Close(raw)
	fresh := &epollWorker{}
	fresh.configureAccepted(raw)
	if fresh.sockoptInherit != sockoptInheritNo || !connSockoptsApplied(raw) {
		t.Fatalf("a socket without inherited options was not configured (state %d)", fresh.sockoptInherit)
	}
	other := perfH1AcceptedFd(t)
	defer unix.Close(other)
	fresh.configureAccepted(other)
	if !connSockoptsApplied(other) {
		t.Fatalf("after a failed inheritance probe later sockets must still be configured")
	}
}

func TestPerfH1AcceptAdmitsUntilMaxConns(t *testing.T) {
	srv := New(Config{Addr: freeLoopbackAddr(t), HTTPAddr: "-", MaxConnsPerIP: -1, MaxConns: 1})
	w := &epollWorker{server: srv}
	first := perfH1AcceptedFd(t)
	if !w.admitAccepted(first, srv.limits.Load()) {
		t.Fatalf("first connection refused under MaxConns=1")
	}
	defer func() {
		_ = unix.Close(first)
		srv.releaseTrackedConn()
		Stats.ActiveConns.Add(-1)
	}()
	second := perfH1AcceptedFd(t)
	if w.admitAccepted(second, srv.limits.Load()) {
		_ = unix.Close(second)
		t.Fatalf("second connection admitted above MaxConns=1")
	}
	if n := srv.activeConns.Load(); n != 1 {
		t.Fatalf("activeConns=%d, want 1", n)
	}
	if perfH1FdOpen(second) {
		_ = unix.Close(second)
		t.Fatalf("the refused connection's fd was left open")
	}
}
