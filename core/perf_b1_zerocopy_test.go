//go:build linux && amd64

package core

import (
	"testing"

	"golang.org/x/sys/unix"
)

func b1LoopbackPair(b *testing.B) (int, int) {
	b.Helper()
	lfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer unix.Close(lfd)
	if err := unix.Bind(lfd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		b.Fatal(err)
	}
	if err := unix.Listen(lfd, 1); err != nil {
		b.Fatal(err)
	}
	sa, err := unix.Getsockname(lfd)
	if err != nil {
		b.Fatal(err)
	}
	cfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		b.Fatal(err)
	}
	if err := unix.Connect(cfd, sa); err != nil {
		b.Fatal(err)
	}
	sfd, _, err := unix.Accept4(lfd, unix.SOCK_CLOEXEC)
	if err != nil {
		b.Fatal(err)
	}
	return sfd, cfd
}

func b1DrainErrQueue(fd int, oob []byte) int {
	n := 0
	for {
		_, _, _, _, err := unix.Recvmsg(fd, nil, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if err != nil {
			return n
		}
		n++
	}
}

func benchB1LoopbackSend(b *testing.B, size int, zerocopy bool) {
	sfd, cfd := b1LoopbackPair(b)
	defer unix.Close(sfd)
	defer unix.Close(cfd)
	if zerocopy {
		if err := unix.SetsockoptInt(sfd, unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1); err != nil {
			b.Skipf("SO_ZEROCOPY: %v", err)
		}
	}
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	total := int64(size) * int64(b.N)
	done := make(chan int64)
	go func() {
		buf := make([]byte, 256<<10)
		var got int64
		for got < total {
			n, err := unix.Read(cfd, buf)
			if n <= 0 || err != nil {
				break
			}
			got += int64(n)
		}
		done <- got
	}()
	flags := unix.MSG_NOSIGNAL
	if zerocopy {
		flags |= unix.MSG_ZEROCOPY
	}
	oob := make([]byte, 128)
	notes := 0
	b.SetBytes(int64(size))
	b.ResetTimer()
	for range b.N {
		for off := 0; off < size; {
			n, err := unix.SendmsgN(sfd, payload[off:], nil, nil, flags)
			if err == unix.ENOBUFS {
				notes += b1DrainErrQueue(sfd, oob)
				continue
			}
			if err != nil {
				b.Fatal(err)
			}
			off += n
		}
		if zerocopy {
			notes += b1DrainErrQueue(sfd, oob)
		}
	}
	if got := <-done; got != total {
		b.Fatalf("received %d of %d bytes", got, total)
	}
	b.ReportMetric(float64(notes)/float64(b.N), "notes/op")
}

func BenchmarkB1LoopbackSendCopy64K(b *testing.B)     { benchB1LoopbackSend(b, 64<<10, false) }
func BenchmarkB1LoopbackSendZeroCopy64K(b *testing.B) { benchB1LoopbackSend(b, 64<<10, true) }
func BenchmarkB1LoopbackSendCopy1M(b *testing.B)      { benchB1LoopbackSend(b, 1<<20, false) }
func BenchmarkB1LoopbackSendZeroCopy1M(b *testing.B)  { benchB1LoopbackSend(b, 1<<20, true) }
