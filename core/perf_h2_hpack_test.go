//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

const (
	perfH2HpackTable       = 4096
	perfH2HpackStreamID    = 7
	perfH2HpackLongValue   = 160
	perfH2HpackHeaderSpare = 512
)

var perfH2HpackWorkloads = []perfH2Workload{perfH2W1, perfH2W3, perfH2W4, perfH2W8}

func newPerfH2Decoder() *HpackDecoder {
	return &HpackDecoder{
		maxTableSize:         perfH2HpackTable,
		protocolMaxSize:      perfH2HpackTable,
		allowExtendedConnect: true,
		maxHeaderListSize:    h2HeaderListLimitFor(DefaultConfig().MaxHeaderSize),
	}
}

func perfH2WarmDecoder(tb testing.TB, wl perfH2Workload, scheme string) (*HpackDecoder, []byte) {
	tb.Helper()
	blocks := perfH2EncodeRequest(wl, scheme)
	d := newPerfH2Decoder()
	if _, _, _, err := d.DecodeRequest(nil, blocks.warm); err != nil {
		tb.Fatalf("%s warm block: %v", wl.name, err)
	}
	return d, blocks.steady
}

func perfH2ExpectedFields(wl perfH2Workload, scheme string) [][2]string {
	var out [][2]string
	for _, f := range perfH2RequestFields(wl, scheme) {
		out = append(out, [2]string{f.name, f.value})
	}
	return out
}

func TestPerfH2RequestEncoderDecodesBothBlocks(t *testing.T) {
	for _, wl := range append(perfH2HpackWorkloads, perfH2W1r, perfH2W5a) {
		blocks := perfH2EncodeRequest(wl, "https")
		d := newPerfH2Decoder()
		want := perfH2ExpectedFields(wl, "https")
		for _, block := range [][]byte{blocks.warm, blocks.steady} {
			got, err := d.DecodeInto(nil, block)
			if err != nil {
				t.Fatalf("%s: decode: %v", wl.name, err)
			}
			if len(got) != len(want) {
				t.Fatalf("%s: decoded %d fields, want %d", wl.name, len(got), len(want))
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("%s: field %d = %q, want %q", wl.name, i, got[i], want[i])
				}
			}
		}
	}
}

func BenchmarkPerfH2HpackDecodeSteadyMemo(b *testing.B) {
	for _, wl := range perfH2HpackWorkloads {
		b.Run(wl.name, func(b *testing.B) {
			d, block := perfH2WarmDecoder(b, wl, "https")
			var headers [][2]string
			b.ReportAllocs()
			b.SetBytes(int64(len(block)))
			for b.Loop() {
				var err error
				headers, _, _, err = d.DecodeRequest(headers[:0], block)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPerfH2HpackDecodeSteadyNoMemo(b *testing.B) {
	for _, wl := range perfH2HpackWorkloads {
		b.Run(wl.name, func(b *testing.B) {
			d, block := perfH2WarmDecoder(b, wl, "https")
			var headers [][2]string
			b.ReportAllocs()
			b.SetBytes(int64(len(block)))
			for b.Loop() {
				var err error
				headers, _, err = d.DecodeIntoRequest(headers[:0], block)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPerfH2HpackDecodeWarmBlock(b *testing.B) {
	for _, wl := range perfH2HpackWorkloads {
		b.Run(wl.name, func(b *testing.B) {
			block := perfH2EncodeRequest(wl, "https").warm
			d := newPerfH2Decoder()
			var headers [][2]string
			b.ReportAllocs()
			b.SetBytes(int64(len(block)))
			for b.Loop() {
				var err error
				headers, _, _, err = d.DecodeRequest(headers[:0], block)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func perfH2RawPathBlock(path string) []byte {
	var enc HpackEncoder
	enc.EncodeInt(0x80, 7, uint64(perfH2StaticPair(":method", "GET")))
	enc.EncodeInt(0x80, 7, uint64(perfH2StaticPair(":scheme", "https")))
	enc.EncodeInt(0x00, 4, uint64(hpackFindStaticName(":path")))
	enc.EncodeInt(0x00, 7, uint64(len(path)))
	enc.Buf = append(enc.Buf, path...)
	enc.EncodeInt(0x00, 4, uint64(hpackFindStaticName(":authority")))
	enc.EncodeInt(0x00, 7, uint64(len(perfH2Authority)))
	enc.Buf = append(enc.Buf, perfH2Authority...)
	return enc.Buf
}

func BenchmarkPerfH2HpackDecodeRawLiteralNoMemo(b *testing.B) {
	block := perfH2RawPathBlock(perfH2W1.path)
	d := newPerfH2Decoder()
	var headers [][2]string
	b.ReportAllocs()
	b.SetBytes(int64(len(block)))
	for b.Loop() {
		var err error
		headers, _, err = d.DecodeIntoRequest(headers[:0], block)
		if err != nil {
			b.Fatal(err)
		}
	}
}

type perfH2RespShape struct {
	name        string
	status      int
	contentType string
	length      int64
	headers     [][2]string
}

var perfH2RespShapes = []perfH2RespShape{
	{name: "W1-text13", status: 200, contentType: "text/plain; charset=utf-8", length: int64(len(perfH2PlaintextBody))},
	{name: "W2-json27", status: 200, contentType: "application/json; charset=utf-8", length: 27},
	{name: "W5a-octet64k", status: 200, contentType: "application/octet-stream", length: perfH2Bytes64k},
	{name: "W9-cors", status: 200, contentType: "text/plain; charset=utf-8", length: 2, headers: [][2]string{
		{"Access-Control-Allow-Origin", "*"},
		{"Vary", "Origin"},
		{"X-RateLimit-Limit", "1000000000"},
		{"X-RateLimit-Remaining", "999999999"},
	}},
	{name: "W7-gzip", status: 200, contentType: "text/plain; charset=utf-8", length: 251, headers: [][2]string{
		{"Content-Encoding", "gzip"},
		{"Vary", "Accept-Encoding"},
	}},
	{name: "long-uncached", status: 200, contentType: "text/html; charset=utf-8", length: 4096, headers: [][2]string{
		{"Set-Cookie", "session=" + strings.Repeat("s", perfH2HpackLongValue) + "; Path=/; HttpOnly; Secure"},
	}},
}

func perfH2EncodeShape(enc *HpackEncoder, s perfH2RespShape) {
	encodeH2ResponseHeaders(enc, s.status, s.contentType, s.length, s.headers, "ALOS")
}

func BenchmarkPerfH2HpackEncodeResponse(b *testing.B) {
	for _, s := range perfH2RespShapes {
		b.Run(s.name, func(b *testing.B) {
			enc := HpackEncoder{Buf: make([]byte, 0, perfH2HpackHeaderSpare)}
			perfH2EncodeShape(&enc, s)
			b.ReportAllocs()
			for b.Loop() {
				enc.Reset(enc.Buf[:0])
				perfH2EncodeShape(&enc, s)
			}
		})
	}
}

func BenchmarkPerfH2HpackEncodeContentLengthSweep(b *testing.B) {
	enc := HpackEncoder{Buf: make([]byte, 0, perfH2HpackHeaderSpare)}
	n := int64(0)
	b.ReportAllocs()
	for b.Loop() {
		enc.Reset(enc.Buf[:0])
		encodeH2ResponseHeaders(&enc, 200, "application/octet-stream", n, nil, "ALOS")
		n++
	}
}

func BenchmarkPerfH2ResponseHeadersFrame(b *testing.B) {
	for _, s := range perfH2RespShapes {
		b.Run(s.name, func(b *testing.B) {
			var resp Response
			resp.Reset()
			resp.Status(s.status)
			resp.ContentType = s.contentType
			resp.body = make([]byte, s.length)
			for _, h := range s.headers {
				resp.SetHeader(h[0], h[1])
			}
			dst := make([]byte, 0, perfH2HpackHeaderSpare)
			dst = appendH2ResponseHeadersFrame(dst, perfH2HpackStreamID, &resp, false, 0)
			b.ReportAllocs()
			for b.Loop() {
				dst = appendH2ResponseHeadersFrame(dst[:0], perfH2HpackStreamID, &resp, false, 0)
			}
		})
	}
}
