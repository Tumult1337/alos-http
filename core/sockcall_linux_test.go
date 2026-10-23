//go:build linux && amd64

package core

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"
)

func socketPairForSend(t *testing.T) (int, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fds[0]); unix.Close(fds[1]) })
	return fds[0], fds[1]
}

func drainSocket(t *testing.T, fd int) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestWsSendFrameEmptyPayloadSendsHeaderOnly(t *testing.T) {
	tx, rx := socketPairForSend(t)
	header := []byte{0x82, 0x00}
	n, err := wsSendFrame(tx, header, nil)
	if err != nil || n != len(header) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := drainSocket(t, rx); !bytes.Equal(got, header) {
		t.Fatalf("got %x", got)
	}
}

func TestWsSendFrameSendsHeaderAndPayload(t *testing.T) {
	tx, rx := socketPairForSend(t)
	n, err := wsSendFrame(tx, []byte{0x82, 0x03}, []byte("abc"))
	if err != nil || n != 5 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := drainSocket(t, rx); !bytes.Equal(got, []byte{0x82, 0x03, 'a', 'b', 'c'}) {
		t.Fatalf("got %x", got)
	}
}

func TestSendWithBodyEmptyBodySendsHead(t *testing.T) {
	tx, rx := socketPairForSend(t)
	var w epollWorker
	c := &epollConn{fd: tx, writeBuf: []byte("head")}
	n, err := w.sendWithBody(c)
	if err != nil || n != 4 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := drainSocket(t, rx); string(got) != "head" {
		t.Fatalf("got %q", got)
	}
}

func TestH2DirectScratchSendAllEmptySegmentsSendsNothing(t *testing.T) {
	tx, _ := socketPairForSend(t)
	var d h2DirectScratch
	if n := d.send(tx, [][]byte{nil, {}}); n != 0 {
		t.Fatalf("n=%d", n)
	}
}

func TestH2DirectScratchSendSkipsEmptySegments(t *testing.T) {
	tx, rx := socketPairForSend(t)
	var d h2DirectScratch
	if n := d.send(tx, [][]byte{[]byte("ab"), nil, []byte("cd")}); n != 4 {
		t.Fatalf("n=%d", n)
	}
	if got := drainSocket(t, rx); string(got) != "abcd" {
		t.Fatalf("got %q", got)
	}
}

func TestWsSendFrameDoesNotAllocate(t *testing.T) {
	tx, rx := socketPairForSend(t)
	payload := make([]byte, 64)
	sink := make([]byte, 128)
	allocs := testing.AllocsPerRun(100, func() {
		var hdr [wsMaxFrameHeaderLen]byte
		h := wsAppendFrameHeader(hdr[:0], 0x82, len(payload))
		if _, err := wsSendFrame(tx, h, payload); err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Read(rx, sink); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("allocs=%v", allocs)
	}
}

func TestSocketSendIovecsClearsIovecSlots(t *testing.T) {
	tx, rx := socketPairForSend(t)
	iov := appendIovec(appendIovec(make([]unix.Iovec, 0, 2), []byte("ab")), []byte("cd"))
	n, err := socketSendIovecs(tx, iov)
	if err != nil || n != 4 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := drainSocket(t, rx); string(got) != "abcd" {
		t.Fatalf("got %q", got)
	}
	for i, slot := range iov {
		if slot.Base != nil || slot.Len != 0 {
			t.Fatalf("slot %d still holds a pointer: %+v", i, slot)
		}
	}
}
