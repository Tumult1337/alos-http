//go:build linux && amd64

package core

import (
	"bytes"
	"strings"
	"testing"
)

func h2FixLiteral(name, value string) []byte {
	var enc HpackEncoder
	enc.Buf = append(enc.Buf, 0x00)
	enc.EncodeInt(0x00, 7, uint64(len(name)))
	enc.Buf = append(enc.Buf, name...)
	enc.EncodeInt(0x00, 7, uint64(len(value)))
	enc.Buf = append(enc.Buf, value...)
	return enc.Buf
}

func h2FixIndexedLiteral(name, value string) []byte {
	var enc HpackEncoder
	enc.Buf = append(enc.Buf, 0x40)
	enc.EncodeInt(0x00, 7, uint64(len(name)))
	enc.Buf = append(enc.Buf, name...)
	enc.EncodeInt(0x00, 7, uint64(len(value)))
	enc.Buf = append(enc.Buf, value...)
	return enc.Buf
}

func h2FixBlock(fields ...[2]string) []byte {
	var block []byte
	for _, f := range fields {
		block = append(block, h2FixLiteral(f[0], f[1])...)
	}
	return block
}

func h2FixRequest(method, path string) []byte {
	return h2FixBlock(
		[2]string{":method", method},
		[2]string{":scheme", "http"},
		[2]string{":authority", "a.test"},
		[2]string{":path", path},
	)
}

func h2FixDecode(block []byte) error {
	_, _, _, err := NewHpackDecoder().DecodeRequest(nil, block)
	return err
}

func TestH2FixHPACKRejectsNonOriginFormPath(t *testing.T) {
	for _, tc := range []struct {
		method, path string
	}{
		{"GET", "http://admin.internal/admin/secret"},
		{"GET", "admin"},
		{"GET", "*"},
		{"GET", ""},
	} {
		if err := h2FixDecode(h2FixRequest(tc.method, tc.path)); err != errH2MalformedRequest {
			t.Errorf(":method %q :path %q decoded with err=%v, want a malformed-request stream error", tc.method, tc.path, err)
		}
	}
	if err := h2FixDecode(h2FixRequest("OPTIONS", "*")); err != nil {
		t.Errorf("OPTIONS * rejected: %v", err)
	}
	if err := h2FixDecode(h2FixRequest("GET", "/ok?x=1")); err != nil {
		t.Errorf("origin-form path rejected: %v", err)
	}
	fast := append([]byte{0x82, 0x04}, byte(len("http://x/y")))
	fast = append(append(fast, "http://x/y"...), 0x87)
	if err := h2FixDecode(fast); err != errH2MalformedRequest {
		t.Errorf("fast-path absolute :path decoded with err=%v, want malformed", err)
	}
}

func TestH2FixHPACKRejectsSpaceAndControlsInMethodAndPath(t *testing.T) {
	for _, tc := range []struct {
		method, path string
	}{
		{"GET /admin", "/public"},
		{"GET\t", "/public"},
		{"G\"T", "/public"},
		{"GET", "/x /y"},
		{"GET", "/x\ty"},
		{"GET", "/x\x7fy"},
		{"GET", "/x\x01y"},
	} {
		if err := h2FixDecode(h2FixRequest(tc.method, tc.path)); err == nil {
			t.Errorf(":method %q :path %q was accepted", tc.method, tc.path)
		}
	}
	fast := append([]byte{0x82, 0x04}, byte(len("/x /y")))
	fast = append(append(fast, "/x /y"...), 0x87)
	if err := h2FixDecode(fast); err == nil {
		t.Error("fast-path :path containing SP was accepted")
	}
	for _, m := range []string{"GET", "PATCH", "M-SEARCH", "X_CUSTOM~1"} {
		if err := h2FixDecode(h2FixRequest(m, "/")); err != nil {
			t.Errorf("token method %q rejected: %v", m, err)
		}
	}
}

func TestH2FixHPACKEnforcesHeaderListSize(t *testing.T) {
	dec := NewHpackDecoder()
	seed := append(h2FixRequest("GET", "/seed"), h2FixIndexedLiteral("x-a", strings.Repeat("v", 4000))...)
	if _, _, _, err := dec.DecodeRequest(nil, seed); err != nil {
		t.Fatalf("seed block: %v", err)
	}
	amplified := h2FixRequest("GET", "/amp")
	amplified = append(amplified, bytes.Repeat([]byte{0xbe}, 120)...)
	if _, _, _, err := dec.DecodeRequest(nil, amplified); err == nil {
		t.Fatalf("a %d-byte block decoding to ~%d bytes of fields was accepted (advertised MAX_HEADER_LIST_SIZE %d)", len(amplified), 120*4035, H2MaxHeaderListSize)
	}
	follow := append(h2FixRequest("GET", "/after"), 0xbe)
	headers, _, _, err := dec.DecodeRequest(nil, follow)
	if err != nil {
		t.Fatalf("block after the rejected one failed (decoder table desynchronised): %v", err)
	}
	if last := headers[len(headers)-1]; last[0] != "x-a" {
		t.Fatalf("dynamic index 62 resolved to %q after the rejected block", last[0])
	}
	within := append(h2FixRequest("GET", "/within"), h2FixLiteral("x-b", strings.Repeat("w", H2MaxHeaderListSize/2))...)
	if err := h2FixDecode(within); err != nil {
		t.Fatalf("header list under the advertised limit rejected: %v", err)
	}
}

func BenchmarkH2FixHPACKDecodeNoMemo(b *testing.B) {
	var first, second HpackEncoder
	for _, h := range gateH2BrowserHeaders {
		first.EncodeHeader(h[0], h[1])
		if h[0] == ":path" {
			second.EncodeHeader(h[0], h[1]+"&v=2")
			continue
		}
		second.EncodeHeader(h[0], h[1])
	}
	blocks := [2][]byte{first.Buf, second.Buf}
	dec := NewHpackDecoder()
	headers := make([][2]string, 0, 32)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		out, _, _, err := dec.DecodeRequest(headers[:0], blocks[i&1])
		if err != nil {
			b.Fatal(err)
		}
		headers = out
		i++
	}
}

func BenchmarkH2FixHPACKDecodeDynamic(b *testing.B) {
	dec := NewHpackDecoder()
	var seed []byte
	for _, h := range gateH2BrowserHeaders[4:] {
		seed = append(seed, h2FixIndexedLiteral(h[0], h[1])...)
	}
	if _, err := dec.DecodeInto(nil, seed); err != nil {
		b.Fatal(err)
	}
	dynamicCount := len(gateH2BrowserHeaders) - 4
	var blocks [2][]byte
	for v := range blocks {
		block := []byte{0x82, 0x87}
		block = append(block, h2FixLiteral(":authority", "alos.gg")...)
		block = append(block, h2FixLiteral(":path", "/dashboard/shop?tab=orders&page="+string(rune('1'+v)))...)
		for i := 0; i < dynamicCount-1; i++ {
			block = append(block, 0x80|byte(62+i))
		}
		block = append(block, 0x0f, byte(62+dynamicCount-1-15), 0x01, 'x')
		blocks[v] = block
	}
	headers := make([][2]string, 0, 32)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		out, _, _, err := dec.DecodeRequest(headers[:0], blocks[i&1])
		if err != nil {
			b.Fatal(err)
		}
		headers = out
		i++
	}
}

func h2FixHuffmanLiteral(name, value string) []byte {
	var enc HpackEncoder
	enc.Buf = append(enc.Buf, 0x00)
	enc.EncodeInt(0x00, 7, uint64(len(name)))
	enc.Buf = append(enc.Buf, name...)
	coded := hpackHuffmanAppend(nil, value)
	enc.EncodeInt(0x80, 7, uint64(len(coded)))
	enc.Buf = append(enc.Buf, coded...)
	return enc.Buf
}

func h2FixHuffmanCacheBytes(d *HpackDecoder) int {
	n := 0
	for i := range d.huffmanCache {
		n += cap(d.huffmanCache[i].heap) + len(d.huffmanCache[i].value)
	}
	return n
}

const h2FixHuffmanCacheRetentionMax = 16 << 10

func TestH2FixHuffmanCacheDoesNotRetainLargeLiterals(t *testing.T) {
	dec := NewHpackDecoder()
	for i := range hpackHuffmanDecodeCacheSize {
		value := strings.Repeat(string(rune('a'+i%26)), 26000)
		fields, err := dec.DecodeInto(nil, h2FixHuffmanLiteral("x-big", value))
		if err != nil || len(fields) != 1 || fields[0][1] != value {
			t.Fatalf("block %d: decode failed (err=%v)", i, err)
		}
	}
	if n := h2FixHuffmanCacheBytes(dec); n > h2FixHuffmanCacheRetentionMax {
		t.Fatalf("Huffman decode cache retains %d bytes after %d large literals, want <= %d", n, hpackHuffmanDecodeCacheSize, h2FixHuffmanCacheRetentionMax)
	}
	short := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	block := h2FixHuffmanLiteral("user-agent", short)
	for range 2 {
		fields, err := dec.DecodeInto(nil, block)
		if err != nil || fields[0][1] != short {
			t.Fatalf("user-agent literal decode failed: %v", err)
		}
	}
}

func TestH2FixHuffmanRejectsEmbeddedEOS(t *testing.T) {
	inputs := [][]byte{
		{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x1f, 0xff, 0xff, 0xff, 0xfc, 0x00},
		append(hpackHuffmanAppend(nil, "ab"), 0xff, 0xff, 0xff, 0xff, 0x0f),
	}
	for _, in := range inputs {
		if s, ok := hpackHuffmanDecode(in); ok {
			t.Errorf("hpackHuffmanDecode(%x) accepted EOS: %q", in, s)
		}
		if s, ok := hpackHuffmanDecodeInto(nil, in); ok {
			t.Errorf("hpackHuffmanDecodeInto(%x) accepted EOS: %q", in, s)
		}
	}
	for i := range 4096 {
		var b strings.Builder
		for j := 0; j < i%97; j++ {
			b.WriteByte(byte((i*31 + j*17) % 256))
		}
		want := b.String()
		coded := hpackHuffmanAppend(nil, want)
		if got, ok := hpackHuffmanDecode(coded); !ok || got != want {
			t.Fatalf("round trip of %q failed: ok=%v got %q", want, ok, got)
		}
		if got, ok := hpackHuffmanDecodeInto(nil, coded); !ok || string(got) != want {
			t.Fatalf("round trip (into) of %q failed", want)
		}
	}
}

func BenchmarkH2FixHuffmanDecode(b *testing.B) {
	coded := hpackHuffmanAppend(nil, gateH2BrowserHeaders[8][1])
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := hpackHuffmanDecode(coded); !ok {
			b.Fatal("decode failed")
		}
	}
}
