//go:build linux && amd64

package core

import (
	"bytes"
	"compress/gzip"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

const (
	perfCorePangram    = "The quick brown fox jumps over the lazy dog. "
	perfCoreText16Size = 16384
)

func perfCoreText16K() string {
	var b strings.Builder
	for b.Len() < perfCoreText16Size {
		b.WriteString(perfCorePangram)
	}
	return b.String()[:perfCoreText16Size]
}

func perfCoreCompressReq(accept string) *Request {
	req := &Request{Method: "GET", Path: "/text16k", Proto: "HTTP/1.1", Headers: make([][2]string, 0, 8)}
	req.Headers = append(req.Headers, [2]string{"Host", "bench.local"}, [2]string{"Accept-Encoding", accept})
	return req
}

func perfCoreCompressHandler(cfg CompressConfig, text string) HandlerFunc {
	return Chain(func(req *Request, resp *Response) { resp.String(text) }, Compress(cfg))
}

func perfCoreDecode(t *testing.T, enc string, body []byte) []byte {
	t.Helper()
	var r io.Reader
	switch enc {
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r = gr
	case "br":
		r = brotli.NewReader(bytes.NewReader(body))
	default:
		return body
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPerfCoreW7CompressRoundTrip(t *testing.T) {
	text := perfCoreText16K()
	h := perfCoreCompressHandler(CompressConfig{}, text)
	for _, enc := range []string{"gzip", "br"} {
		req := perfCoreCompressReq(enc)
		resp := perfCoreResp()
		h(req, resp)
		if !responseHasHeader(resp.Headers, "content-encoding") {
			t.Fatalf("%s: no Content-Encoding", enc)
		}
		if got := perfCoreDecode(t, enc, resp.GetBody()); string(got) != text {
			t.Fatalf("%s: round trip mismatch (%d bytes)", enc, len(got))
		}
	}
}

func BenchmarkPerfCoreW7Compress(b *testing.B) {
	text := perfCoreText16K()
	for _, tc := range []struct {
		name   string
		accept string
		cfg    CompressConfig
	}{
		{"gzip_default", "gzip", CompressConfig{}},
		{"br_default_L4", "br", CompressConfig{}},
		{"gzip_L1", "gzip", CompressConfig{Level: 1}},
		{"br_L1", "br", CompressConfig{BrotliLevel: 1}},
		{"browser_accept_picks_br", "gzip, deflate, br, zstd", CompressConfig{}},
		{"identity_vary_only", "identity", CompressConfig{}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			h := perfCoreCompressHandler(tc.cfg, text)
			req := perfCoreCompressReq(tc.accept)
			resp := perfCoreResp()
			b.SetBytes(perfCoreText16Size)
			b.ReportAllocs()
			for b.Loop() {
				req.headerCacheMask = 0
				resp.resetFastH1()
				h(req, resp)
			}
			b.ReportMetric(float64(resp.BodyLen()), "out-bytes")
		})
	}
}

func BenchmarkPerfCoreW7GzipLevels(b *testing.B) {
	body := []byte(perfCoreText16K())
	for level := 1; level <= 9; level++ {
		b.Run("gzip_L"+strconv.Itoa(level), func(b *testing.B) {
			bp := LargeBufPool.Get().(*[]byte)
			out := (*bp)[:0]
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				out = appendCompressed(out[:0], body, encodingGzip, level)
			}
			b.ReportMetric(float64(len(out)), "out-bytes")
			*bp = out
			putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
		})
	}
	for _, level := range []int{1, 2, 4, 5, 6} {
		b.Run("br_L"+strconv.Itoa(level), func(b *testing.B) {
			out := make([]byte, 0, 32<<10)
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				out = appendCompressed(out[:0], body, encodingBrotli, level)
			}
			b.ReportMetric(float64(len(out)), "out-bytes")
		})
	}
}

func TestPerfCoreW7IdentityZeroAlloc(t *testing.T) {
	text := perfCoreText16K()
	h := perfCoreCompressHandler(CompressConfig{}, text)
	req := perfCoreCompressReq("identity")
	resp := perfCoreResp()
	allocs := testing.AllocsPerRun(200, func() {
		req.headerCacheMask = 0
		resp.resetFastH1()
		h(req, resp)
	})
	if allocs != 0 {
		t.Fatalf("Compress with no acceptable encoding allocates %.1f/op, want 0", allocs)
	}
}
