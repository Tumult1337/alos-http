//go:build linux && amd64

package core

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/bytedance/sonic/encoder"
)

const (
	perfCoreHello      = "Hello, World!"
	perfCoreBody64K    = 64 << 10
	perfCoreBody1M     = 1 << 20
	perfCoreEchoBodyKB = 1 << 10
)

type perfCoreMessage struct {
	Message string `json:"message"`
}

var perfCoreSinkBytes []byte

func perfCoreResp() *Response {
	return &Response{StatusCode: 200, Headers: make([][2]string, 0, 8), body: make([]byte, 0, 4096)}
}

func perfCoreEncodeInto(resp *Response, v any) error {
	resp.body = resp.body[:0]
	if err := encoder.EncodeInto(&resp.body, v, 0); err != nil {
		resp.body = resp.body[:0]
		return err
	}
	resp.ContentType = "application/json; charset=utf-8"
	resp.bodyString = ""
	resp.bodyIsText = false
	return nil
}

func perfCoreAppendMessageJSON(resp *Response, msg string) {
	buf := append(resp.body[:0], `{"message":`...)
	buf = AppendJSONString(buf, msg)
	buf = append(buf, '}')
	resp.ContentType = "application/json; charset=utf-8"
	resp.body = buf
	resp.bodyString = ""
	resp.bodyIsText = false
}

func BenchmarkPerfCoreW2JSON(b *testing.B) {
	b.Run("JSONMarshal_value", func(b *testing.B) {
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			_ = resp.JSONMarshal(perfCoreMessage{Message: perfCoreHello})
		}
	})
	b.Run("JSONMarshal_pointer", func(b *testing.B) {
		resp := perfCoreResp()
		msg := &perfCoreMessage{Message: perfCoreHello}
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			_ = resp.JSONMarshal(msg)
		}
	})
	b.Run("AcquireJSON_Marshal", func(b *testing.B) {
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			j := AcquireJSON()
			resp.JSON(j.Marshal(perfCoreMessage{Message: perfCoreHello}))
			j.Release()
		}
	})
	b.Run("sonic_EncodeInto_body", func(b *testing.B) {
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			_ = perfCoreEncodeInto(resp, perfCoreMessage{Message: perfCoreHello})
		}
	})
	b.Run("sonic_EncodeInto_body_pointer", func(b *testing.B) {
		resp := perfCoreResp()
		msg := &perfCoreMessage{Message: perfCoreHello}
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			_ = perfCoreEncodeInto(resp, msg)
		}
	})
	b.Run("AppendJSONString_handwritten", func(b *testing.B) {
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			perfCoreAppendMessageJSON(resp, perfCoreHello)
		}
	})
	b.Run("JSONString_prebuilt", func(b *testing.B) {
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			resp.JSONString(`{"message":"Hello, World!"}`)
		}
	})
}

func TestPerfCoreW2EncodingsAgree(t *testing.T) {
	values := []any{
		perfCoreMessage{Message: perfCoreHello},
		&perfCoreMessage{Message: "<script>&\"\\\n\t\x01é"},
		map[string]any{"a": []int{1, 2}},
		map[string]any{"c": nil},
		[]string{"x", "\xff\xfe"},
		struct {
			N float64 `json:"n"`
			S []byte  `json:"s"`
		}{N: 1.5, S: []byte("hi")},
	}
	for i, v := range values {
		want, err := sonic.Marshal(v)
		if err != nil {
			t.Fatalf("value %d: sonic.Marshal: %v", i, err)
		}
		resp := perfCoreResp()
		if err := resp.JSONMarshal(v); err != nil {
			t.Fatalf("value %d: JSONMarshal: %v", i, err)
		}
		if !bytes.Equal(resp.GetBody(), want) {
			t.Fatalf("value %d: JSONMarshal %q, want %q", i, resp.GetBody(), want)
		}
		into := perfCoreResp()
		if err := perfCoreEncodeInto(into, v); err != nil {
			t.Fatalf("value %d: EncodeInto: %v", i, err)
		}
		if !bytes.Equal(into.GetBody(), want) {
			t.Fatalf("value %d: EncodeInto %q differs from sonic.Marshal %q", i, into.GetBody(), want)
		}
	}
	hand := perfCoreResp()
	perfCoreAppendMessageJSON(hand, perfCoreHello)
	if string(hand.GetBody()) != `{"message":"Hello, World!"}` {
		t.Fatalf("handwritten %q", hand.GetBody())
	}
}

func TestPerfCoreJSONStringZeroAlloc(t *testing.T) {
	resp := perfCoreResp()
	allocs := testing.AllocsPerRun(200, func() {
		resp.resetFastH1()
		resp.JSONString(`{"message":"Hello, World!"}`)
	})
	if allocs != 0 {
		t.Fatalf("JSONString allocates %.1f/op, want 0", allocs)
	}
}

func perfCoreEchoRequest() *Request {
	req := &Request{Method: "POST", Path: "/echo", Proto: "HTTP/1.1", Headers: make([][2]string, 0, 8)}
	req.Headers = append(req.Headers,
		[2]string{"Host", "bench.local"},
		[2]string{"Content-Type", "application/octet-stream"},
		[2]string{"Content-Length", strconv.Itoa(perfCoreEchoBodyKB)},
	)
	req.Body = bytes.Repeat([]byte{'p'}, perfCoreEchoBodyKB)
	return req
}

func BenchmarkPerfCoreW4BodyRead(b *testing.B) {
	b.Run("len_Itoa_harness", func(b *testing.B) {
		req := perfCoreEchoRequest()
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			resp.String(strconv.Itoa(len(req.Body)))
		}
	})
	b.Run("len_appendUint_body", func(b *testing.B) {
		req := perfCoreEchoRequest()
		resp := perfCoreResp()
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			resp.body = appendUint(resp.body[:0], int64(len(req.Body)))
			resp.ContentType = "text/plain; charset=utf-8"
		}
	})
	b.Run("content_length_header", func(b *testing.B) {
		req := perfCoreEchoRequest()
		b.ReportAllocs()
		for b.Loop() {
			req.headerCacheMask = 0
			perfCoreSinkString = req.Header("Content-Length")
		}
	})
	b.Run("echo_bytes_copy", func(b *testing.B) {
		req := perfCoreEchoRequest()
		resp := perfCoreResp()
		b.SetBytes(int64(len(req.Body)))
		b.ReportAllocs()
		for b.Loop() {
			resp.resetFastH1()
			resp.Bytes(req.Body)
		}
	})
}

func TestPerfCoreBodyReadZeroAlloc(t *testing.T) {
	req := perfCoreEchoRequest()
	resp := perfCoreResp()
	allocs := testing.AllocsPerRun(200, func() {
		resp.resetFastH1()
		resp.Bytes(req.Body)
		req.headerCacheMask = 0
		perfCoreSinkString = req.Header("Content-Length")
	})
	if allocs != 0 {
		t.Fatalf("1KB body Bytes echo + Content-Length lookup allocates %.1f/op, want 0", allocs)
	}
}

func perfCoreBody(n int) []byte { return bytes.Repeat([]byte{'x'}, n) }

func BenchmarkPerfCoreW5Bytes(b *testing.B) {
	for _, size := range []struct {
		name string
		n    int
	}{{"64K", perfCoreBody64K}, {"1M", perfCoreBody1M}} {
		body := perfCoreBody(size.n)
		b.Run(size.name+"/Bytes", func(b *testing.B) {
			resp := perfCoreResp()
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for b.Loop() {
				resp.resetFastH1()
				resp.Bytes(body)
			}
		})
		b.Run(size.name+"/Bytes_Reset", func(b *testing.B) {
			resp := perfCoreResp()
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for b.Loop() {
				resp.Reset()
				resp.Bytes(body)
			}
		})
		b.Run(size.name+"/String_unsafe_nocopy", func(b *testing.B) {
			resp := perfCoreResp()
			s := UnsafeString(body)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for b.Loop() {
				resp.resetFastH1()
				resp.String(s)
				resp.ContentType = "application/octet-stream"
			}
		})
		b.Run(size.name+"/Bytes_serialize_reused_out", func(b *testing.B) {
			resp := perfCoreResp()
			out := make([]byte, 0, size.n+512)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for b.Loop() {
				resp.resetFastH1()
				resp.Bytes(body)
				out = appendPlainResponseMode(resp, out[:0], true, true)
			}
			perfCoreSinkBytes = out
		})
		b.Run(size.name+"/Bytes_serialize_iobuf_pool", func(b *testing.B) {
			resp := perfCoreResp()
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for b.Loop() {
				resp.resetFastH1()
				resp.Bytes(body)
				out := appendPlainResponseMode(resp, acquireIOBuf(), true, true)
				perfCoreSinkBytes = out
				releaseIOBuf(out)
			}
		})
		b.Run(size.name+"/String_nocopy_serialize_iobuf_pool", func(b *testing.B) {
			resp := perfCoreResp()
			s := UnsafeString(body)
			b.SetBytes(int64(size.n))
			b.ReportAllocs()
			for b.Loop() {
				resp.resetFastH1()
				resp.String(s)
				resp.ContentType = "application/octet-stream"
				out := appendPlainResponseMode(resp, acquireIOBuf(), true, true)
				perfCoreSinkBytes = out
				releaseIOBuf(out)
			}
		})
	}
}

func TestPerfCoreBytes64KSteadyStateZeroAlloc(t *testing.T) {
	body := perfCoreBody(perfCoreBody64K)
	resp := perfCoreResp()
	resp.Bytes(body)
	allocs := testing.AllocsPerRun(50, func() {
		resp.resetFastH1()
		resp.Bytes(body)
	})
	if allocs != 0 {
		t.Fatalf("64KB Bytes after warm-up allocates %.1f/op, want 0", allocs)
	}
}
