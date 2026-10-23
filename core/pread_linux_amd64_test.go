//go:build linux && amd64

package core

import (
	"bytes"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func preadTestFile(t *testing.T, size int) (*os.File, []byte) {
	t.Helper()
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i*7 + 3)
	}
	f, err := os.CreateTemp(t.TempDir(), "pread")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}
	return f, content
}

func preadTestIovecs(bufs ...[]byte) []unix.Iovec {
	iov := make([]unix.Iovec, len(bufs))
	for i, b := range bufs {
		if len(b) > 0 {
			iov[i].Base = &b[0]
		}
		iov[i].SetLen(len(b))
	}
	return iov
}

func TestPreadvAllFillsEverySegment(t *testing.T) {
	f, content := preadTestFile(t, 8192)
	first, second := make([]byte, 3000), make([]byte, 5000)
	got, err := preadvAll(int(f.Fd()), preadTestIovecs(first, second), 100, unix.RWF_NOWAIT)
	if err != nil || got != 8000 {
		t.Fatalf("got=%d err=%v", got, err)
	}
	if !bytes.Equal(append(first, second...), content[100:8100]) {
		t.Fatal("content mismatch")
	}
}

func TestPreadvAllTruncatedAfterSizeSnapshotReportsShortCount(t *testing.T) {
	f, _ := preadTestFile(t, 8192)
	if err := f.Truncate(5000); err != nil {
		t.Fatal(err)
	}
	got, err := preadvAll(int(f.Fd()), preadTestIovecs(make([]byte, 4096), make([]byte, 4096)), 0, unix.RWF_NOWAIT)
	if got != 5000 || err != io.ErrUnexpectedEOF {
		t.Fatalf("got=%d err=%v", got, err)
	}
}

func TestPreadvAllZeroLengthReadTerminates(t *testing.T) {
	f, _ := preadTestFile(t, 4096)
	if err := f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	got, err := preadvAll(int(f.Fd()), preadTestIovecs(make([]byte, 4096)), 0, unix.RWF_NOWAIT)
	if got != 0 || err != io.ErrUnexpectedEOF {
		t.Fatalf("got=%d err=%v", got, err)
	}
}

func TestPreadvAllSkipsEmptySegments(t *testing.T) {
	f, content := preadTestFile(t, 64)
	buf := make([]byte, 64)
	got, err := preadvAll(int(f.Fd()), preadTestIovecs(nil, buf, nil), 0, 0)
	if err != nil || got != 64 || !bytes.Equal(buf, content) {
		t.Fatalf("got=%d err=%v", got, err)
	}
	got, err = preadvAll(int(f.Fd()), nil, 0, 0)
	if err != nil || got != 0 {
		t.Fatalf("empty: got=%d err=%v", got, err)
	}
	got, err = preadvAll(int(f.Fd()), preadTestIovecs(nil), 0, 0)
	if err != nil || got != 0 {
		t.Fatalf("only empty segment: got=%d err=%v", got, err)
	}
}

func TestPreadFullTruncatedAfterSizeSnapshotFails(t *testing.T) {
	f, content := preadTestFile(t, 8192)
	data, ok := preadFull(int(f.Fd()), 8192)
	if !ok || !bytes.Equal(data, content) {
		t.Fatal("full read failed")
	}
	if err := f.Truncate(5000); err != nil {
		t.Fatal(err)
	}
	if data, ok := preadFull(int(f.Fd()), 8192); ok || data != nil {
		t.Fatalf("ok=%v len=%d", ok, len(data))
	}
}

func TestWarmFileRangeTruncatedAfterSizeSnapshotFails(t *testing.T) {
	f, _ := preadTestFile(t, 8192)
	if err := warmFileRange(int(f.Fd()), 0, 8192); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(5000); err != nil {
		t.Fatal(err)
	}
	if err := warmFileRange(int(f.Fd()), 0, 8192); err != io.ErrUnexpectedEOF {
		t.Fatalf("err=%v", err)
	}
}
