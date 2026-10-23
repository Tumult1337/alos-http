//go:build linux && amd64

package core

import "testing"

func encodeTestRequestBlock(path string, extra [][2]string) []byte {
	enc := HpackEncoder{}
	enc.EncodeIndexed(2)
	enc.EncodeHeader(":path", path)
	enc.EncodeIndexed(7)
	enc.EncodeHeader(":authority", "memo.test")
	for _, h := range extra {
		enc.EncodeHeader(h[0], h[1])
	}
	return enc.Buf
}

func TestHpackDecodeRequestMemoIsExactAndInvalidated(t *testing.T) {
	d := NewHpackDecoder()
	blockA := encodeTestRequestBlock("/a", [][2]string{{"x-tag", "one"}})
	blockB := encodeTestRequestBlock("/b", [][2]string{{"x-tag", "two"}})
	hA, metaA, err := d.DecodeRequest(nil, blockA)
	if err != nil || metaA.path != "/a" || len(hA) != 5 || hA[4][1] != "one" {
		t.Fatalf("first decode: %v %+v %v", err, metaA, hA)
	}
	if !d.memoValid {
		t.Fatal("identical-safe block was not memoized")
	}
	hA2, metaA2, err := d.DecodeRequest(hA[:0], blockA)
	if err != nil || metaA2.path != "/a" || len(hA2) != 5 || hA2[4][1] != "one" {
		t.Fatalf("memo decode: %v %+v %v", err, metaA2, hA2)
	}
	hB, metaB, err := d.DecodeRequest(hA2[:0], blockB)
	if err != nil || metaB.path != "/b" || len(hB) != 5 || hB[4][1] != "two" {
		t.Fatalf("different block served stale memo: %v %+v %v", err, metaB, hB)
	}
	if _, _, err := d.DecodeRequest(nil, blockA); err != nil || d.memoMeta.path != "/a" {
		t.Fatalf("memo not refreshed to the latest block: %v %q", err, d.memoMeta.path)
	}
	incremental := HpackEncoder{}
	incremental.EncodeIndexed(2)
	incremental.EncodeHeader(":path", "/c")
	incremental.EncodeIndexed(7)
	incremental.EncodeHeader(":authority", "memo.test")
	incremental.EncodeInt(0x40, 6, 0)
	incremental.EncodeString("x-dyn")
	incremental.EncodeString("val")
	if _, meta, err := d.DecodeRequest(nil, incremental.Buf); err != nil || meta.path != "/c" {
		t.Fatalf("incremental block: %v %+v", err, meta)
	}
	if d.memoValid {
		t.Fatal("a block that changed the dynamic table must not be memoized")
	}
	root := encodeTestRequestBlock("/", nil)
	if _, meta, err := d.DecodeRequest(nil, root); err != nil || meta.path != "/" {
		t.Fatalf("root block: %v %+v", err, meta)
	}
	if !d.memoValid || d.memoMeta.path != "/" {
		t.Fatalf("root block not memoized: valid=%v path=%q", d.memoValid, d.memoMeta.path)
	}

}
