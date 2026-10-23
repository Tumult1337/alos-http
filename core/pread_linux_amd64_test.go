//go:build linux && amd64

package core

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

func TestPreadFullZeroSizeReturnsEmpty(t *testing.T) {
	f, _ := preadTestFile(t, 0)
	data, ok := preadFull(int(f.Fd()), 0)
	if !ok || len(data) != 0 {
		t.Fatalf("ok=%v len=%d", ok, len(data))
	}
}

func TestStaticEmptyFileServedOverH1TLSAndH2(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	for _, tc := range []struct {
		name  string
		tls   bool
		alpn  string
		proto int
	}{
		{"h1-tls", true, "http/1.1", 1},
		{"h2-tls", true, "h2", 2},
		{"h2c", false, "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			perfCoreWriteStatic(t, filepath.Join(root, "empty.txt"), nil)
			ts := newTestServer(t, testServerOptions{TLS: tc.tls, Domain: perfCoreH2FileDomain, Routes: func(r *Router) {
				r.GET("/s/*filepath", Static("/s", StaticConfig{Root: root}))
			}})
			var cl *http.Client
			switch {
			case tc.tls:
				cl = ts.client(t, tc.alpn)
			default:
				cl = h2cClient()
				t.Cleanup(cl.CloseIdleConnections)
			}
			for i := 0; i < 3; i++ {
				resp, body, err := perfCoreH2FileGet(cl, ts.url("/s/empty.txt"), "")
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				if resp.StatusCode != 200 || resp.ProtoMajor != tc.proto || len(body) != 0 || resp.Header.Get("Content-Length") != "0" {
					t.Fatalf("request %d: status %d proto %d len %d cl %q", i, resp.StatusCode, resp.ProtoMajor, len(body), resp.Header.Get("Content-Length"))
				}
			}
		})
	}
}

func diskTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/var/tmp", "alos-cold-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestH1TLSSealFileColdCacheDeliversIntactBody(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	root := diskTempDir(t)
	content := serveContentPattern(perfCoreH2FileSize)
	path := filepath.Join(root, "big.bin")
	perfCoreWriteStatic(t, path, content)
	ts := newTestServer(t, testServerOptions{TLS: true, Domain: perfCoreH2FileDomain, Routes: func(r *Router) {
		r.GET("/s/*filepath", Static("/s", StaticConfig{Root: root, CacheMaxFileSize: staticCacheEvictingFileSize}))
	}})
	cl := ts.client(t, "http/1.1")
	for round := 0; round < 3; round++ {
		perfCoreDropPageCache(t, path)
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		probe := make([]byte, 4096)
		_, probeErr := preadvAll(int(f.Fd()), preadTestIovecs(probe), 0, unix.RWF_NOWAIT)
		f.Close()
		if probeErr != unix.EAGAIN {
			t.Skipf("filesystem under /var/tmp serves RWF_NOWAIT reads from a dropped cache: %v", probeErr)
		}
		resp, body, err := perfCoreH2FileGet(cl, ts.url("/s/big.bin"), "")
		if err != nil || resp.StatusCode != 200 || resp.ProtoMajor != 1 || !bytes.Equal(body, content) {
			t.Fatalf("round %d: err %v len %d equal=%v", round, err, len(body), bytes.Equal(body, content))
		}
	}
}
