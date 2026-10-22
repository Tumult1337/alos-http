//go:build linux && amd64

package core

import (
	"testing"
)

func perfB3DecodeBlock(t *testing.T, dec *HpackDecoder, block []byte) [][2]string {
	t.Helper()
	fields, err := dec.DecodeInto(nil, block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return fields
}

func perfB3Field(fields [][2]string, name string) string {
	for _, f := range fields {
		if f[0] == name {
			return f[1]
		}
	}
	return ""
}

func TestPerfB3H2HeadMemoReplaysIdenticalBlock(t *testing.T) {
	var tbl hpackEncTable
	tbl.reset()
	dec := &HpackDecoder{maxTableSize: 4096, protocolMaxSize: 4096, maxHeaderListSize: 1 << 20}
	var blocks [][]byte
	for i := 0; i < 6; i++ {
		enc := HpackEncoder{}
		encodeH2ResponseHeadersIndexed(&enc, &tbl, 200, "text/plain; charset=utf-8", 13, nil, "ALOS")
		blocks = append(blocks, enc.Buf)
		fields := perfB3DecodeBlock(t, dec, enc.Buf)
		if perfB3Field(fields, "content-type") != "text/plain; charset=utf-8" || perfB3Field(fields, "content-length") != "13" ||
			perfB3Field(fields, "server") != "ALOS" || perfB3Field(fields, ":status") != "200" || perfB3Field(fields, "date") == "" {
			t.Fatalf("round %d: fields %q", i, fields)
		}
	}
	last := blocks[len(blocks)-1]
	if string(blocks[len(blocks)-2]) != string(last) {
		t.Fatalf("steady-state blocks differ: %x vs %x", blocks[len(blocks)-2], last)
	}
}

func TestPerfB3H2HeadMemoSeesMutatedValues(t *testing.T) {
	var tbl hpackEncTable
	tbl.reset()
	dec := &HpackDecoder{maxTableSize: 4096, protocolMaxSize: 4096, maxHeaderListSize: 1 << 20}
	ctBuf := []byte("text/plain; charset=utf-8")
	server := []byte("ALOS")
	cases := []struct {
		mutate func()
		status int
		length int64
	}{
		{func() {}, 200, 13},
		{func() {}, 200, 13},
		{func() {}, 200, 13},
		{func() { copy(ctBuf, "text/html;  charset=utf-8") }, 200, 13},
		{func() {}, 200, 13},
		{func() { copy(server, "OTHR") }, 200, 13},
		{func() {}, 404, 13},
		{func() {}, 404, 14},
		{func() {}, 404, 14},
	}
	for i, c := range cases {
		c.mutate()
		enc := HpackEncoder{}
		encodeH2ResponseHeadersIndexed(&enc, &tbl, c.status, UnsafeString(ctBuf), c.length, nil, UnsafeString(server))
		fields := perfB3DecodeBlock(t, dec, enc.Buf)
		if got := perfB3Field(fields, "content-type"); got != string(ctBuf) {
			t.Fatalf("case %d: content-type %q, want %q", i, got, ctBuf)
		}
		if got := perfB3Field(fields, "server"); got != string(server) {
			t.Fatalf("case %d: server %q, want %q", i, got, server)
		}
		if got := perfB3Field(fields, ":status"); got != perfB3Itoa(c.status) {
			t.Fatalf("case %d: status %q", i, got)
		}
		if got := perfB3Field(fields, "content-length"); got != perfB3Itoa(int(c.length)) {
			t.Fatalf("case %d: content-length %q", i, got)
		}
	}
}

func TestPerfB3H2HeadMemoInvalidatedByPeerTableSize(t *testing.T) {
	var tbl hpackEncTable
	tbl.reset()
	dec := &HpackDecoder{maxTableSize: 4096, protocolMaxSize: 4096, maxHeaderListSize: 1 << 20}
	for i := 0; i < 8; i++ {
		switch i {
		case 3:
			tbl.setPeerLimit(64)
			dec.protocolMaxSize = 64
		case 6:
			tbl.setPeerLimit(0)
			dec.protocolMaxSize = 0
		}
		enc := HpackEncoder{}
		encodeH2ResponseHeadersIndexed(&enc, &tbl, 200, "application/json; charset=utf-8", 27, nil, "ALOS")
		fields := perfB3DecodeBlock(t, dec, enc.Buf)
		if perfB3Field(fields, "content-type") != "application/json; charset=utf-8" || perfB3Field(fields, "date") == "" {
			t.Fatalf("round %d: fields %q", i, fields)
		}
	}
}

func perfB3Itoa(n int) string {
	return string(appendUint(nil, int64(n)))
}

func BenchmarkPerfB3H2HeadEncode(b *testing.B) {
	var tbl hpackEncTable
	tbl.reset()
	enc := HpackEncoder{Buf: make([]byte, 0, 256)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		enc.Buf = enc.Buf[:0]
		encodeH2ResponseHeadersIndexed(&enc, &tbl, 200, "text/plain; charset=utf-8", 13, nil, "ALOS")
	}
}

func TestPerfB3H2HeadMemoWithHeaders(t *testing.T) {
	var tbl hpackEncTable
	tbl.reset()
	dec := &HpackDecoder{maxTableSize: 4096, protocolMaxSize: 4096, maxHeaderListSize: 1 << 20}
	idBuf := []byte("req-0000")
	for i := 0; i < 400; i++ {
		var headers [][2]string
		switch {
		case i%7 == 3:
			idBuf[len(idBuf)-1] = byte('0' + i%10)
			headers = [][2]string{{"access-control-allow-origin", "*"}, {"x-request-id", UnsafeString(idBuf)}}
		case i < 200:
			headers = [][2]string{{"access-control-allow-origin", "*"}}
		default:
			idBuf[len(idBuf)-2] = byte('0' + i%10)
			headers = [][2]string{{"Cache-Control", "no-store"}, {"x-request-id", UnsafeString(idBuf)}}
		}
		enc := HpackEncoder{}
		encodeH2ResponseHeadersIndexed(&enc, &tbl, 200, "text/plain; charset=utf-8", 2, headers, "ALOS")
		fields := perfB3DecodeBlock(t, dec, enc.Buf)
		for _, h := range headers {
			if got := perfB3Field(fields, lowerASCIIForTest(h[0])); got != h[1] {
				t.Fatalf("response %d: %s = %q, want %q (fields %q)", i, h[0], got, h[1], fields)
			}
		}
		if perfB3Field(fields, "content-length") != "2" || perfB3Field(fields, "date") == "" || perfB3Field(fields, "server") != "ALOS" {
			t.Fatalf("response %d: fields %q", i, fields)
		}
	}
}

func lowerASCIIForTest(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func BenchmarkPerfB3H2HeadEncodeCORS(b *testing.B) {
	var tbl hpackEncTable
	tbl.reset()
	enc := HpackEncoder{Buf: make([]byte, 0, 256)}
	headers := [][2]string{{"access-control-allow-origin", "*"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		enc.Buf = enc.Buf[:0]
		encodeH2ResponseHeadersIndexed(&enc, &tbl, 200, "text/plain; charset=utf-8", 2, headers, "ALOS")
	}
}

func BenchmarkPerfB3H2HeadEncodeVarying(b *testing.B) {
	var tbl hpackEncTable
	tbl.reset()
	enc := HpackEncoder{Buf: make([]byte, 0, 256)}
	id := []byte("4f9c2a7e1b8d4c6a")
	headers := [][2]string{{"x-request-id", UnsafeString(id)}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		id[i&15] ^= 1
		enc.Buf = enc.Buf[:0]
		encodeH2ResponseHeadersIndexed(&enc, &tbl, 200, "text/plain; charset=utf-8", 2, headers, "ALOS")
	}
}
