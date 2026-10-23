//go:build linux && amd64

package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const (
	perfCoreStaticFileName = "file-64k.bin"
	perfCoreStaticFileSize = 64 << 10
	perfCoreStaticPrefix   = "/static"
)

type perfCoreCopySW struct {
	pending []byte
	status  int
	header  bool
	closed  bool
}

func (w *perfCoreCopySW) WriteHeader(statusCode int, headers [][2]string, contentType string) error {
	w.status = statusCode
	w.header = true
	return nil
}

func (w *perfCoreCopySW) WriteChunk(data []byte) error {
	w.pending = append(w.pending, data...)
	return nil
}

func (w *perfCoreCopySW) Flush() error { return nil }

func (w *perfCoreCopySW) Close() error {
	w.closed = true
	return nil
}

func (w *perfCoreCopySW) reset() {
	w.pending = w.pending[:0]
	w.status = 0
	w.header = false
	w.closed = false
}

type perfCoreSWFactory struct{ sw *perfCoreCopySW }

func (f *perfCoreSWFactory) newStreamWriter(req *Request) StreamWriter { return f.sw }

func perfCoreStaticRoot(tb testing.TB) (string, []byte) {
	tb.Helper()
	root := filepath.Join(tb.TempDir(), "harness", "static")
	if err := os.MkdirAll(root, 0o755); err != nil {
		tb.Fatal(err)
	}
	data := bytes.Repeat([]byte("0123456789abcdef"), perfCoreStaticFileSize/16)
	if err := os.WriteFile(filepath.Join(root, perfCoreStaticFileName), data, 0o644); err != nil {
		tb.Fatal(err)
	}
	return root, data
}

type perfCoreStaticRig struct {
	handler HandlerFunc
	req     *Request
	resp    *Response
	sw      *perfCoreCopySW
}

func newPerfCoreStaticRig(root string, streamed bool) *perfCoreStaticRig {
	rig := &perfCoreStaticRig{
		handler: Static(perfCoreStaticPrefix, StaticConfig{Root: root}),
		req:     &Request{Method: "GET", Path: perfCoreStaticPrefix + "/" + perfCoreStaticFileName, Proto: "HTTP/1.1", Headers: make([][2]string, 0, 8)},
		resp:    perfCoreResp(),
		sw:      &perfCoreCopySW{pending: make([]byte, 0, perfCoreStaticFileSize+1024)},
	}
	if streamed {
		rig.req.server = &Server{}
		rig.req.swFactory = &perfCoreSWFactory{sw: rig.sw}
	}
	return rig
}

func (rig *perfCoreStaticRig) serve() {
	rig.resp.Reset()
	rig.resp.lazyReq = rig.req
	rig.req.StreamWriter = nil
	rig.sw.reset()
	rig.handler(rig.req, rig.resp)
}

func TestPerfCoreStaticServesFile(t *testing.T) {
	root, data := perfCoreStaticRoot(t)
	streamed := newPerfCoreStaticRig(root, true)
	streamed.serve()
	if !streamed.resp.IsStreamed() || streamed.sw.status != 200 || !streamed.sw.closed || !bytes.Equal(streamed.sw.pending, data) {
		t.Fatalf("streamed static: streamed=%v status=%d closed=%v len=%d", streamed.resp.IsStreamed(), streamed.sw.status, streamed.sw.closed, len(streamed.sw.pending))
	}
	buffered := newPerfCoreStaticRig(root, false)
	buffered.serve()
	if buffered.resp.StatusCode != 200 || !bytes.Equal(buffered.resp.GetBody(), data) {
		t.Fatalf("buffered static: status=%d len=%d", buffered.resp.StatusCode, buffered.resp.BodyLen())
	}
}

func BenchmarkPerfCoreW6Static(b *testing.B) {
	root, _ := perfCoreStaticRoot(b)
	b.Run("streamed_sw_64K", func(b *testing.B) {
		rig := newPerfCoreStaticRig(root, true)
		b.SetBytes(perfCoreStaticFileSize)
		b.ReportAllocs()
		for b.Loop() {
			rig.serve()
		}
		if rig.sw.status != 200 || len(rig.sw.pending) != perfCoreStaticFileSize {
			b.Fatalf("status %d len %d", rig.sw.status, len(rig.sw.pending))
		}
	})
	b.Run("buffered_no_sw_64K", func(b *testing.B) {
		rig := newPerfCoreStaticRig(root, false)
		b.SetBytes(perfCoreStaticFileSize)
		b.ReportAllocs()
		for b.Loop() {
			rig.serve()
		}
		if rig.resp.StatusCode != 200 {
			b.Fatalf("status %d", rig.resp.StatusCode)
		}
	})
	b.Run("step_sanitize", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			perfCoreSinkString, _ = sanitizeStaticPath("/" + perfCoreStaticFileName)
		}
	})
	full := filepath.Join(root, perfCoreStaticFileName)
	b.Run("step_join_abs", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			p, _ := filepath.Abs(filepath.Join(root, perfCoreStaticFileName))
			perfCoreSinkString = p
		}
	})
	sr := newStaticRoot(root)
	b.Run("step_contains_evalsymlinks", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if sr.contains(full) != 0 {
				b.Fatal("not contained")
			}
		}
	})
	b.Run("step_stat", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := os.Stat(full); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("step_open_fstat_close", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			f, err := os.Open(full)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := f.Stat(); err != nil {
				b.Fatal(err)
			}
			f.Close()
		}
	})
	fi, err := os.Stat(full)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("step_fileValidators", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			perfCoreSinkString = fileValidators(fi).etag
		}
	})
	b.Run("step_detectMIME", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			perfCoreSinkString = detectMIME(full)
		}
	})
}
