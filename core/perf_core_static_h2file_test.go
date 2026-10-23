//go:build linux && amd64

package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	perfCoreH2FileSize     = 4<<20 + 333
	perfCoreH2FileParallel = 6
	perfCoreH2FileDomain   = "stream.test"
)

func perfCoreH2FileServer(t *testing.T, useTLS bool, size int) (*testServer, []byte, string) {
	t.Helper()
	perfCoreSettleStaticFiles(t)
	root := t.TempDir()
	content := serveContentPattern(size)
	path := filepath.Join(root, "big.bin")
	perfCoreWriteStatic(t, path, content)
	ts := newTestServer(t, testServerOptions{TLS: useTLS, Domain: perfCoreH2FileDomain, Routes: func(r *Router) {
		h := Static("/s", StaticConfig{Root: root, CacheMaxFileSize: staticCacheEvictingFileSize})
		r.GET("/s/*filepath", h)
		r.HEAD("/s/*filepath", h)
	}})
	return ts, content, path
}

func perfCoreH2FileClient(t *testing.T, ts *testServer) *http.Client {
	if ts.tls {
		return ts.client(t, "h2")
	}
	cl := h2cClient()
	t.Cleanup(cl.CloseIdleConnections)
	return cl
}

func perfCoreH2FileGet(cl *http.Client, url, rangeSpec string) (*http.Response, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	if rangeSpec != "" {
		req.Header.Set("Range", rangeSpec)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body, err
}

func TestPerfCoreStaticH2LargeFile(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run("tls="+strconv.FormatBool(useTLS), func(t *testing.T) {
			ts, content, _ := perfCoreH2FileServer(t, useTLS, perfCoreH2FileSize)
			cl := perfCoreH2FileClient(t, ts)
			url := ts.url("/s/big.bin")
			var wg sync.WaitGroup
			errs := make(chan error, perfCoreH2FileParallel)
			for i := 0; i < perfCoreH2FileParallel; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					resp, body, err := perfCoreH2FileGet(cl, url, "")
					switch {
					case err != nil:
						errs <- err
					case resp.ProtoMajor != 2 || resp.StatusCode != 200 || !bytes.Equal(body, content):
						errs <- fmt.Errorf("proto %d status %d len %d equal=%v", resp.ProtoMajor, resp.StatusCode, len(body), bytes.Equal(body, content))
					case resp.Header.Get("Content-Length") != strconv.Itoa(len(content)):
						errs <- fmt.Errorf("content-length %q", resp.Header.Get("Content-Length"))
					}
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatal(err)
			}
			resp, body, err := perfCoreH2FileGet(cl, url, "bytes=70000-1500000")
			if err != nil || resp.StatusCode != 206 || !bytes.Equal(body, content[70000:1500001]) {
				t.Fatalf("range: err %v status %d len %d", err, resp.StatusCode, len(body))
			}
			resp, body, err = perfCoreH2FileGet(cl, url, "bytes=-5")
			if err != nil || resp.StatusCode != 206 || !bytes.Equal(body, content[len(content)-5:]) {
				t.Fatalf("suffix range: err %v status %d %q", err, resp.StatusCode, body)
			}
			head, err := cl.Head(url)
			if err != nil {
				t.Fatal(err)
			}
			headBody, _ := io.ReadAll(head.Body)
			head.Body.Close()
			if head.StatusCode != 200 || len(headBody) != 0 || head.Header.Get("Content-Length") != strconv.Itoa(len(content)) {
				t.Fatalf("head: %d len %d cl %q", head.StatusCode, len(headBody), head.Header.Get("Content-Length"))
			}
		})
	}
}

func TestPerfCoreStaticH2FileHonoursTheWindow(t *testing.T) {
	ts, content, _ := perfCoreH2FileServer(t, true, perfCoreH2FileSize)
	r := dialRawH2(t, ts.addr, h2SpecWindow)
	r.get(1, "/s/big.bin")
	var got bytes.Buffer
	n, ended := r.readStream(1, h2SpecWindow, &got)
	if n != h2SpecWindow || ended {
		t.Fatalf("first window delivered %d bytes (ended=%v), want exactly %d", n, ended, h2SpecWindow)
	}
	if f, err := r.next(streamQuietPeriod); err == nil || !isTimeout(err) {
		t.Fatalf("server sent %+v past an exhausted window (err=%v)", f, err)
	}
	r.windowUpdate(0, perfCoreH2FileSize)
	r.windowUpdate(1, perfCoreH2FileSize)
	rest, ended := r.readStreamToEnd(1, perfCoreH2FileSize-h2SpecWindow, &got)
	if n+rest != perfCoreH2FileSize || !ended || !bytes.Equal(got.Bytes(), content) {
		t.Fatalf("total %d ended=%v equal=%v", n+rest, ended, bytes.Equal(got.Bytes(), content))
	}
}

func perfCoreH2WaitReset(t *testing.T, r *rawH2Conn, stream uint32) uint32 {
	t.Helper()
	deadline := time.Now().Add(streamTestTimeout)
	for time.Now().Before(deadline) {
		f, err := r.next(streamTestTimeout)
		if err != nil {
			t.Fatal(err)
		}
		if f.typ == H2FrameRSTStream && f.stream == stream {
			return binary.BigEndian.Uint32(f.payload)
		}
	}
	t.Fatalf("stream %d was never reset", stream)
	return 0
}

func perfCoreH2FollowUp(t *testing.T, r *rawH2Conn, stream uint32, content []byte) {
	t.Helper()
	r.windowUpdate(0, 64<<20)
	r.get(stream, "/s/big.bin")
	r.windowUpdate(stream, perfCoreH2FileSize)
	var got bytes.Buffer
	n, ended := r.readStreamToEnd(stream, len(content), &got)
	if n != len(content) || !ended || !bytes.Equal(got.Bytes(), content) {
		t.Fatalf("follow-up stream %d: %d bytes ended=%v equal=%v", stream, n, ended, bytes.Equal(got.Bytes(), content))
	}
}

func TestPerfCoreStaticH2FileStallIsReset(t *testing.T) {
	old := h2StreamStallTimeout
	h2StreamStallTimeout = streamQuietPeriod
	t.Cleanup(func() { h2StreamStallTimeout = old })
	ts, content, _ := perfCoreH2FileServer(t, true, perfCoreH2FileSize)
	r := dialRawH2(t, ts.addr, h2SpecWindow)
	r.get(1, "/s/big.bin")
	if code := perfCoreH2WaitReset(t, r, 1); code != H2ErrCancel {
		t.Fatalf("stall reset code %d, want CANCEL", code)
	}
	perfCoreH2FollowUp(t, r, 3, content)
}

func TestPerfCoreStaticH2FileClientReset(t *testing.T) {
	ts, content, _ := perfCoreH2FileServer(t, true, perfCoreH2FileSize)
	r := dialRawH2(t, ts.addr, h2SpecWindow)
	r.get(1, "/s/big.bin")
	if _, ended := r.readStream(1, 1, io.Discard); ended {
		t.Fatal("stream ended after one window")
	}
	var code [4]byte
	binary.BigEndian.PutUint32(code[:], H2ErrCancel)
	r.write(H2FrameRSTStream, 0, 1, code[:])
	r.windowUpdate(0, perfCoreH2FileSize)
	perfCoreH2FollowUp(t, r, 3, content)
}

func TestPerfCoreStaticH2FileTruncatedMidBody(t *testing.T) {
	ts, content, path := perfCoreH2FileServer(t, true, perfCoreH2FileSize)
	r := dialRawH2(t, ts.addr, h2SpecWindow)
	r.get(1, "/s/big.bin")
	if n, ended := r.readStream(1, h2SpecWindow, io.Discard); n != h2SpecWindow || ended {
		t.Fatalf("first window %d ended=%v", n, ended)
	}
	if err := os.Truncate(path, int64(len(content)/2)); err != nil {
		t.Fatal(err)
	}
	r.windowUpdate(0, perfCoreH2FileSize)
	r.windowUpdate(1, perfCoreH2FileSize)
	if code := perfCoreH2WaitReset(t, r, 1); code != H2ErrCancel {
		t.Fatalf("truncated file reset code %d, want CANCEL", code)
	}
	perfCoreH2FollowUp(t, r, 3, content[:len(content)/2])
}

func perfCoreDropPageCache(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED); err != nil {
		t.Fatal(err)
	}
}

func TestPerfCoreStaticColdFilePumps(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run("tls="+strconv.FormatBool(useTLS), func(t *testing.T) {
			ts, content, path := perfCoreH2FileServer(t, useTLS, perfCoreH2FileSize)
			clients := map[string]*http.Client{"h2": perfCoreH2FileClient(t, ts)}
			if useTLS {
				clients["http/1.1"] = ts.client(t, "http/1.1")
			}
			for name, cl := range clients {
				perfCoreDropPageCache(t, path)
				resp, body, err := perfCoreH2FileGet(cl, ts.url("/s/big.bin"), "")
				if err != nil || resp.StatusCode != 200 || !bytes.Equal(body, content) {
					t.Fatalf("tls=%v %s cold file: err %v len %d equal=%v", useTLS, name, err, len(body), bytes.Equal(body, content))
				}
			}
		})
	}
}
