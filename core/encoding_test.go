//go:build linux && amd64

package core

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

var compressibleTestBody = []byte(strings.Repeat(`{"id":12345,"name":"widget","tags":["a","b","c"],"price":19.99},`, 64))

func TestNegotiateEncoding(t *testing.T) {
	cases := []struct {
		accept  string
		offered encodingSet
		want    encodingType
	}{
		{"", offerAllEncodings, encodingNone},
		{"identity", offerAllEncodings, encodingNone},
		{"gzip", offerAllEncodings, encodingGzip},
		{"GZIP", offerAllEncodings, encodingGzip},
		{"x-gzip", offerAllEncodings, encodingGzip},
		{"deflate", offerAllEncodings, encodingDeflate},
		{"br", offerAllEncodings, encodingBrotli},
		{"gzip, deflate, br", offerAllEncodings, encodingBrotli},
		{"gzip, deflate, br, zstd", offerAllEncodings, encodingBrotli},
		{"deflate, gzip", offerAllEncodings, encodingGzip},
		{"br;q=0, gzip", offerAllEncodings, encodingGzip},
		{"br;q=0.0, gzip", offerAllEncodings, encodingGzip},
		{"br;q=0.000, gzip", offerAllEncodings, encodingGzip},
		{"gzip;q=0.0", offerAllEncodings, encodingNone},
		{"br;q=0.5, gzip;q=0.8", offerAllEncodings, encodingGzip},
		{"br;q=0.8, gzip;q=0.5", offerAllEncodings, encodingBrotli},
		{"br;q=0.001, gzip;q=0", offerAllEncodings, encodingBrotli},
		{"br; q=0.9 , gzip ; q=0.9", offerAllEncodings, encodingBrotli},
		{"br;Q=1.000", offerAllEncodings, encodingBrotli},
		{"*", offerAllEncodings, encodingBrotli},
		{"*;q=0", offerAllEncodings, encodingNone},
		{"*;q=0.5, br;q=0", offerAllEncodings, encodingGzip},
		{"gzip;q=0.2, *;q=0.5", offerAllEncodings, encodingBrotli},
		{"br;q=1.5, gzip", offerAllEncodings, encodingGzip},
		{"br;q=1.001, gzip", offerAllEncodings, encodingGzip},
		{"br;q=0.0001, gzip", offerAllEncodings, encodingGzip},
		{"br;q=abc, gzip", offerAllEncodings, encodingGzip},
		{"br;q=, gzip", offerAllEncodings, encodingGzip},
		{"br;q=.5, gzip", offerAllEncodings, encodingGzip},
		{"br;level=5, gzip;q=0.5", offerAllEncodings, encodingBrotli},
		{"br", offerGzip, encodingNone},
		{"br, gzip", offerGzip, encodingGzip},
		{"br, gzip", offerGzip | offerBrotli, encodingBrotli},
		{"gzip", 0, encodingNone},
		{";;,,q=", offerAllEncodings, encodingNone},
		{"gzipx, xgzip, brr", offerAllEncodings, encodingNone},
	}
	for _, c := range cases {
		if got := negotiateEncoding(c.accept, c.offered); got != c.want {
			t.Errorf("negotiateEncoding(%q, %03b) = %d, want %d", c.accept, c.offered, got, c.want)
		}
	}
}

func TestParseQValue(t *testing.T) {
	cases := map[string]int16{
		"0": 0, "1": 1000, "0.": 0, "1.": 1000, "0.5": 500, "0.05": 50, "0.005": 5, "0.123": 123,
		"1.0": 1000, "1.000": 1000, "1.001": 0, "1.5": 0, "2": 0, "0.1234": 0, "": 0, "-1": 0, "0,5": 0, " 1": 0,
	}
	for in, want := range cases {
		if got := parseQValue(in); got != want {
			t.Errorf("parseQValue(%q) = %d, want %d", in, got, want)
		}
	}
}

var referenceQValue = regexp.MustCompile(`^(0(\.[0-9]{0,3})?|1(\.0{0,3})?)$`)

func referenceNegotiate(accept string, offered encodingSet) encodingType {
	if accept == "" {
		return encodingNone
	}
	weights := map[string]int{}
	for _, element := range strings.Split(accept, ",") {
		parts := strings.Split(element, ";")
		coding := asciiLowerTest(strings.Trim(parts[0], " \t\r\n"))
		if coding == "x-gzip" {
			coding = "gzip"
		}
		weight := 1000
		for _, p := range parts[1:] {
			p = strings.Trim(p, " \t\r\n")
			if len(p) >= 2 && (p[0] == 'q' || p[0] == 'Q') && p[1] == '=' {
				weight = 0
				if v := p[2:]; referenceQValue.MatchString(v) {
					f, _ := strconv.ParseFloat(strings.TrimSuffix(v, "."), 64)
					weight = int(f*1000 + 0.5)
				}
				break
			}
		}
		weights[coding] = weight
	}
	best, bestWeight := encodingNone, 0
	for _, c := range []struct {
		enc  encodingType
		name string
	}{{encodingBrotli, "br"}, {encodingGzip, "gzip"}, {encodingDeflate, "deflate"}} {
		if offered&(1<<c.enc) == 0 {
			continue
		}
		w, ok := weights[c.name]
		if !ok {
			w, ok = weights["*"]
		}
		if ok && w > bestWeight {
			best, bestWeight = c.enc, w
		}
	}
	return best
}

func asciiLowerTest(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func FuzzAcceptEncoding(f *testing.F) {
	for _, s := range []string{"gzip", "br;q=1.0, gzip;q=0.8, *;q=0.1", "gzip;q=0", "identity", ";;,,q=", "GZIP ; Q=0.5", "x-gzip;q=0.999", "*;q=0.5, br;q=0"} {
		f.Add(s, uint8(offerAllEncodings))
	}
	f.Fuzz(func(t *testing.T, accept string, offered uint8) {
		set := encodingSet(offered) & offerAllEncodings
		if got, want := negotiateEncoding(accept, set), referenceNegotiate(accept, set); got != want {
			t.Fatalf("negotiateEncoding(%q, %03b) = %d, reference %d", accept, set, got, want)
		}
	})
}

func decodeContent(t *testing.T, encoding string, body []byte) []byte {
	t.Helper()
	var r io.Reader
	switch encoding {
	case "br":
		r = brotli.NewReader(bytes.NewReader(body))
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r = gr
	case "deflate":
		r = flate.NewReader(bytes.NewReader(body))
	case "":
		return body
	default:
		t.Fatalf("unexpected encoding %q", encoding)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decode %s: %v", encoding, err)
	}
	return out
}

func varyFieldLines(resp *Response) int {
	n := 0
	for _, h := range resp.Headers {
		if EqualFoldASCII(h[0], "vary") {
			n++
		}
	}
	return n
}

func runCompress(cfg CompressConfig, accept string, body []byte, extraHeaders ...[2]string) *Response {
	req := newTestReq()
	if accept != "" {
		req.Headers = append(req.Headers, [2]string{"accept-encoding", accept})
	}
	resp := newTestResp()
	Compress(cfg)(func(req *Request, resp *Response) {
		resp.Status(200).JSON(body)
		resp.Headers = append(resp.Headers, extraHeaders...)
	})(req, resp)
	return resp
}

func TestBrotliCompressMiddleware(t *testing.T) {
	cases := []struct {
		accept  string
		wantEnc string
	}{
		{"br", "br"},
		{"gzip, deflate, br", "br"},
		{"br;q=0, gzip", "gzip"},
		{"deflate", "deflate"},
		{"identity", ""},
		{"", ""},
	}
	for _, c := range cases {
		resp := runCompress(CompressConfig{}, c.accept, compressibleTestBody)
		gotEnc := hdr(resp, "content-encoding")
		if gotEnc != c.wantEnc {
			t.Errorf("Accept-Encoding %q: Content-Encoding %q, want %q", c.accept, gotEnc, c.wantEnc)
			continue
		}
		if varyFieldLines(resp) != 1 || hdr(resp, "vary") != "Accept-Encoding" {
			t.Errorf("Accept-Encoding %q: Vary %q in %d field lines", c.accept, hdr(resp, "vary"), varyFieldLines(resp))
		}
		if got := decodeContent(t, gotEnc, resp.body); !bytes.Equal(got, compressibleTestBody) {
			t.Errorf("Accept-Encoding %q: decoded body differs (%d bytes)", c.accept, len(got))
		}
		if c.wantEnc != "" && len(resp.body) >= len(compressibleTestBody) {
			t.Errorf("Accept-Encoding %q: %d compressed bytes for %d", c.accept, len(resp.body), len(compressibleTestBody))
		}
	}
}

func TestBrotliCompressLevels(t *testing.T) {
	var sizes []int
	for _, level := range []int{1, 4, 11} {
		resp := runCompress(CompressConfig{BrotliLevel: level}, "br", compressibleTestBody)
		if !bytes.Equal(decodeContent(t, "br", resp.body), compressibleTestBody) {
			t.Fatalf("level %d: round trip failed", level)
		}
		sizes = append(sizes, len(resp.body))
	}
	if sizes[2] > sizes[0] {
		t.Errorf("level 11 output (%d) larger than level 1 (%d)", sizes[2], sizes[0])
	}
	for _, level := range []int{-1, 0, 12, 1 << 20} {
		if got := normalizeBrotliLevel(level); got != defaultBrotliLevel {
			t.Errorf("normalizeBrotliLevel(%d) = %d", level, got)
		}
	}
}

func TestBrotliVaryNotDuplicated(t *testing.T) {
	resp := runCompress(CompressConfig{}, "br", compressibleTestBody, [2]string{"Vary", "Origin, accept-encoding"})
	if varyFieldLines(resp) != 1 || hdr(resp, "content-encoding") != "br" {
		t.Fatalf("%d Vary lines, Content-Encoding %q", varyFieldLines(resp), hdr(resp, "content-encoding"))
	}
	resp = runCompress(CompressConfig{}, "br", compressibleTestBody, [2]string{"Vary", "Origin"})
	if varyFieldLines(resp) != 2 {
		t.Fatalf("Vary: Origin alone should gain Accept-Encoding, got %d lines", varyFieldLines(resp))
	}
}

func TestBrotliSkipsSmallAndEncoded(t *testing.T) {
	resp := runCompress(CompressConfig{}, "br", []byte(`{"tiny":true}`))
	if hdr(resp, "content-encoding") != "" || varyFieldLines(resp) != 0 {
		t.Fatalf("small body: Content-Encoding %q, %d Vary lines", hdr(resp, "content-encoding"), varyFieldLines(resp))
	}
	resp = runCompress(CompressConfig{}, "br", compressibleTestBody, [2]string{"Content-Encoding", "gzip"})
	if hdr(resp, "content-encoding") != "gzip" || !bytes.Equal(resp.body, compressibleTestBody) {
		t.Fatal("an already-encoded response was re-encoded")
	}
}

func bytesPerCompressedResponse(accept string) uint64 {
	const (
		runs    = 200
		warmups = 8
	)
	req := newTestReq()
	req.Headers = append(req.Headers, [2]string{"accept-encoding", accept})
	resp := newTestResp()
	handler := Compress(CompressConfig{})(func(req *Request, resp *Response) { resp.Status(200).JSON(compressibleTestBody) })
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	for range warmups {
		resp.Reset()
		handler(req, resp)
	}
	prevGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prevGC)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		resp.Reset()
		handler(req, resp)
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / runs
}

func TestBrotliPooledAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector drops sync.Pool entries at random, so pooled allocation counts do not apply")
	}
	br, gz := bytesPerCompressedResponse("br"), bytesPerCompressedResponse("gzip")
	if br > gz {
		t.Fatalf("brotli allocates %d B per response, gzip %d B", br, gz)
	}
}

func BenchmarkCompressEncodings(b *testing.B) {
	for _, accept := range []string{"br", "gzip", "deflate"} {
		b.Run(accept, func(b *testing.B) {
			req := newTestReq()
			req.Headers = append(req.Headers, [2]string{"accept-encoding", accept})
			resp := newTestResp()
			handler := Compress(CompressConfig{})(func(req *Request, resp *Response) { resp.Status(200).JSON(compressibleTestBody) })
			b.SetBytes(int64(len(compressibleTestBody)))
			b.ReportAllocs()
			for b.Loop() {
				resp.Reset()
				handler(req, resp)
			}
		})
	}
}

func BenchmarkNegotiateEncoding(b *testing.B) {
	for b.Loop() {
		_ = negotiateEncoding("gzip, deflate, br, zstd", offerAllEncodings)
	}
}

func TestBrotliResponseCache(t *testing.T) {
	calls := 0
	handler := Cache(CacheConfig{TTL: time.Minute, Gzip: true, Brotli: true})(func(req *Request, resp *Response) {
		calls++
		resp.Status(200).JSON(compressibleTestBody)
	})
	serve := func(accept string) *Response {
		req := newTestReq()
		req.Path = "/cached"
		if accept != "" {
			req.Headers = append(req.Headers, [2]string{"accept-encoding", accept})
		}
		resp := newTestResp()
		handler(req, resp)
		return resp
	}
	for i, c := range []struct{ accept, want string }{
		{"gzip, br", "br"},
		{"gzip, br", "br"},
		{"gzip", "gzip"},
		{"br;q=0.5, gzip;q=0.8", "gzip"},
		{"deflate", ""},
		{"", ""},
	} {
		resp := serve(c.accept)
		if got := hdr(resp, "content-encoding"); got != c.want {
			t.Errorf("request %d (%q): Content-Encoding %q, want %q", i, c.accept, got, c.want)
		}
		if hdr(resp, "vary") != "Accept-Encoding" || varyFieldLines(resp) != 1 {
			t.Errorf("request %d (%q): Vary %q", i, c.accept, hdr(resp, "vary"))
		}
		if !bytes.Equal(decodeContent(t, c.want, resp.GetBody()), compressibleTestBody) {
			t.Errorf("request %d (%q): body does not decode to the original", i, c.accept)
		}
	}
	if calls != 1 {
		t.Fatalf("handler ran %d times, want 1", calls)
	}

	gzipOnly := Cache(CacheConfig{TTL: time.Minute, Gzip: true})(func(req *Request, resp *Response) {
		resp.Status(200).JSON(compressibleTestBody)
	})
	req := newTestReq()
	req.Headers = append(req.Headers, [2]string{"accept-encoding", "br;q=1, gzip;q=0.1"})
	resp := newTestResp()
	gzipOnly(req, resp)
	if hdr(resp, "content-encoding") != "gzip" {
		t.Fatalf("gzip-only cache served %q to a client that prefers br but accepts gzip", hdr(resp, "content-encoding"))
	}
}

func TestProxyCacheHonoursZeroQValue(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{})
	defer pc.Stop()
	pc.PutManual("GET", "h", "/p", 200, nil, "application/json", compressibleTestBody, time.Minute, 0, true, 0)
	for _, c := range []struct{ accept, want string }{
		{"gzip", "gzip"},
		{"gzip;q=0.0", ""},
		{"gzip;q=0.000, deflate", ""},
		{"", ""},
	} {
		req := newTestReq()
		if c.accept != "" {
			req.Headers = append(req.Headers, [2]string{"accept-encoding", c.accept})
		}
		entry, ok := pc.Get("GET", "h", "/p", req)
		if !ok {
			t.Fatal("entry not cached")
		}
		resp := newTestResp()
		pc.ServeCached(entry, req, resp)
		if got := hdr(resp, "content-encoding"); got != c.want {
			t.Errorf("Accept-Encoding %q: Content-Encoding %q, want %q", c.accept, got, c.want)
		}
		if hdr(resp, "vary") != "Accept-Encoding" {
			t.Errorf("Accept-Encoding %q: Vary %q", c.accept, hdr(resp, "vary"))
		}
		if !bytes.Equal(decodeContent(t, c.want, resp.GetBody()), compressibleTestBody) {
			t.Errorf("Accept-Encoding %q: body does not decode", c.accept)
		}
	}
}

func hdr(resp *Response, name string) string {
	v, _ := respHeader(resp, name)
	return v
}

func TestBrotliCacheHitAllocs(t *testing.T) {
	handler := Cache(CacheConfig{TTL: time.Minute, Gzip: true, Brotli: true})(func(req *Request, resp *Response) {
		resp.Status(200).JSON(compressibleTestBody)
	})
	req := &Request{Method: "GET", Host: "alos.gg", Path: "/cached", Headers: [][2]string{{"accept-encoding", "gzip, deflate, br, zstd"}}}
	resp := &Response{}
	handler(req, resp)
	allocs := testing.AllocsPerRun(100, func() {
		resp.resetFastH1()
		handler(req, resp)
	})
	if allocs != 0 || hdr(resp, "content-encoding") != "br" {
		t.Fatalf("%.1f allocations per brotli cache hit, Content-Encoding %q", allocs, hdr(resp, "content-encoding"))
	}
}
