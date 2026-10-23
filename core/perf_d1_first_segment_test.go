//go:build linux && amd64

package core

import (
	"bytes"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func d1WithAcceptedTCPFd(t *testing.T, fn func(fd int)) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	rc, err := server.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Control(func(fd uintptr) { fn(int(fd)) }); err != nil {
		t.Fatal(err)
	}
}

func d1LargeBodyConn(fd, headLen, bodyLen int) *epollConn {
	return &epollConn{
		fd:       fd,
		writeBuf: bytes.Repeat([]byte{'h'}, headLen),
		h1Body:   bytes.Repeat([]byte{'b'}, bodyLen),
	}
}

func d1DrainHandOff(c *epollConn) {
	c.writeSent = len(c.writeBuf)
	c.bodyOut = nil
}

func TestD1FirstLargeBodyWriteSpansJustOverOneSegment(t *testing.T) {
	d1WithAcceptedTCPFd(t, func(fd int) {
		mss, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG)
		if err != nil || mss <= 0 || mss > h1FirstSegmentMaxMSS {
			t.Skipf("loopback mss %d (err %v) is outside the split range", mss, err)
		}
		const headLen, bodyLen = 157, 64 << 10
		c := d1LargeBodyConn(fd, headLen, bodyLen)
		c.h1HandOffBody()
		if got := headLen + len(c.bodyOut); got != mss+h1FirstWriteOverMSS {
			t.Fatalf("first write carries %d bytes, want mss+%d = %d", got, h1FirstWriteOverMSS, mss+h1FirstWriteOverMSS)
		}
		first := len(c.bodyOut)
		d1DrainHandOff(c)
		c.h1HandOffBody()
		if len(c.bodyOut) != bodyLen-first || c.h1BodyOff != bodyLen {
			t.Fatalf("second write carries %d bytes at offset %d, want the remaining %d", len(c.bodyOut), c.h1BodyOff, bodyLen-first)
		}
		d1DrainHandOff(c)
		c.writeBuf = bytes.Repeat([]byte{'h'}, headLen)
		c.writeSent = 0
		c.h1Body, c.h1BodyOff = bytes.Repeat([]byte{'b'}, bodyLen), 0
		c.h1HandOffBody()
		if len(c.bodyOut) != bodyLen {
			t.Fatalf("a later large body was split into %d bytes, want one %d byte write", len(c.bodyOut), bodyLen)
		}
	})
}

func TestD1FirstLargeBodyNotSplitWhenHeadFillsSegment(t *testing.T) {
	d1WithAcceptedTCPFd(t, func(fd int) {
		mss, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG)
		if err != nil || mss <= 0 || mss > h1FirstSegmentMaxMSS {
			t.Skipf("loopback mss %d (err %v) is outside the split range", mss, err)
		}
		c := d1LargeBodyConn(fd, mss+h1FirstWriteOverMSS, 64<<10)
		c.h1HandOffBody()
		if len(c.bodyOut) != 64<<10 {
			t.Fatalf("body split into %d bytes although the pending head already fills the first write", len(c.bodyOut))
		}
	})
}

func TestD1FirstLargeBodyNotSplitOnNonTCPSocket(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	c := d1LargeBodyConn(fds[0], 157, 64<<10)
	c.h1HandOffBody()
	if len(c.bodyOut) != 64<<10 || !c.h1FirstSegSent {
		t.Fatalf("non-TCP socket: body handed off as %d bytes (first-seg flag %v), want the whole body once", len(c.bodyOut), c.h1FirstSegSent)
	}
}
