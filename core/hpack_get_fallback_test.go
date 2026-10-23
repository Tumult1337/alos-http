package core

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func hpackGetCompatibilityBlock(path string, huffman bool, authority []byte) []byte {
	encoder := HpackEncoder{Buf: []byte{0x82, 0x04}}
	if huffman {
		encoder.EncodeInt(0x80, 7, uint64(hpackHuffmanEncodedLen(path)))
		encoder.Buf = hpackHuffmanAppend(encoder.Buf, path)
	} else {
		encoder.EncodeInt(0, 7, uint64(len(path)))
		encoder.Buf = append(encoder.Buf, path...)
	}
	encoder.Buf = append(encoder.Buf, authority...)
	return append(encoder.Buf, 0x87)
}

func hpackGetCompatibilityWant(path, authority string) [][2]string {
	return [][2]string{{":method", "GET"}, {":path", path}, {":authority", authority}, {":scheme", "https"}}
}

func hpackGetCompatibilityCheck(t *testing.T, headers [][2]string, meta hpackRequestMeta, path, authority string) {
	t.Helper()
	if want := hpackGetCompatibilityWant(path, authority); !reflect.DeepEqual(headers, want) {
		t.Fatalf("decoded fields %q, want %q", headers, want)
	}
	wantPath, query, _ := strings.Cut(path, "?")
	if meta.method != "GET" || meta.path != wantPath || meta.rawPath != path || meta.query != query || meta.authority != authority || meta.scheme != "https" || meta.headerCount != 4 {
		t.Fatalf("unexpected request metadata: %+v", meta)
	}
}

func TestHpackGetFallbackValidRepresentations(t *testing.T) {
	for _, path := range []string{"/", "/other?q=1", "/long/compatibility/path"} {
		for _, huffman := range []bool{false, true} {
			for _, representation := range []struct {
				name string
				wire []byte
				seed bool
			}{
				{"without-indexing", []byte{0x01, 0x01, 'a'}, false},
				{"never-indexed", []byte{0x11, 0x01, 'a'}, false},
				{"incremental", []byte{0x41, 0x01, 'a'}, false},
				{"indexed", []byte{0xbe}, true},
			} {
				for _, requestWrapper := range []bool{false, true} {
					for _, reuse := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/path%s/huffman%v/wrapper%v/reuse%v", representation.name, path, huffman, requestWrapper, reuse), func(t *testing.T) {
							decoder := NewHpackDecoder()
							if representation.seed {
								if _, err := decoder.Decode([]byte{0x41, 0x01, 'a'}); err != nil {
									t.Fatalf("seed authority: %v", err)
								}
							}
							var headers [][2]string
							if reuse {
								headers = make([][2]string, 1, 8)
								headers[0] = [2]string{"stale", "value"}
							}
							block := hpackGetCompatibilityBlock(path, huffman, representation.wire)
							if (block[2]&0x80 != 0) != huffman {
								t.Fatal("fixture did not use the requested path string encoding")
							}
							var meta hpackRequestMeta
							var err error
							if requestWrapper {
								headers, meta, err = decoder.DecodeRequest(headers, block)
							} else {
								headers, meta, err = decoder.DecodeIntoRequest(headers, block)
							}
							if err != nil {
								t.Fatalf("valid GET block rejected: %v (huffman=%v wrapper=%v reuse=%v)", err, huffman, requestWrapper, reuse)
							}
							hpackGetCompatibilityCheck(t, headers, meta, path, "a")
						})
					}
				}
			}
		}
	}
}

func TestHpackGetFallbackLeavesSpeculativeStateUntouched(t *testing.T) {
	decoder := NewHpackDecoder()
	headers := make([][2]string, 1, 8)
	headers[0] = [2]string{"preserve", "buffer"}
	before := append([][2]string(nil), headers[:cap(headers)]...)
	block := hpackGetCompatibilityBlock("/", false, []byte{0x41, 0x01, 'a'})
	out, meta, claimed, err := decodeSimpleGetPathHTTPSRequest(decoder, headers, block)
	if err != nil || claimed || !reflect.DeepEqual(out, headers) || meta != (hpackRequestMeta{}) {
		t.Fatalf("helper claimed a non-exact layout: claimed=%v err=%v fields=%q metadata=%+v", claimed, err, out, meta)
	}
	if !reflect.DeepEqual(headers[:cap(headers)], before) || decoder.tableGen != 0 || decoder.dynLen != 0 {
		t.Fatal("helper changed header storage or HPACK table state before declining")
	}
}

func TestHpackGetFallbackStateAndMemo(t *testing.T) {
	decoder := NewHpackDecoder()
	incremental := hpackGetCompatibilityBlock("/", false, []byte{0x41, 0x01, 'a'})
	for insertion := 1; insertion <= 2; insertion++ {
		headers, meta, err := decoder.DecodeRequest(nil, incremental)
		if err != nil {
			t.Fatalf("incremental block %d: %v", insertion, err)
		}
		hpackGetCompatibilityCheck(t, headers, meta, "/", "a")
		if decoder.dynLen != insertion || decoder.tableGen != uint64(insertion) || decoder.memoValid {
			t.Fatalf("insertion %d: entries=%d generation=%d memo=%v", insertion, decoder.dynLen, decoder.tableGen, decoder.memoValid)
		}
	}
	indexed := hpackGetCompatibilityBlock("/", false, []byte{0xbe})
	headers, meta, err := decoder.DecodeRequest(nil, indexed)
	if err != nil {
		t.Fatalf("follow-up dynamic reference: %v", err)
	}
	hpackGetCompatibilityCheck(t, headers, meta, "/", "a")
	if !decoder.memoValid || !bytes.Equal(decoder.memoBlock, indexed) {
		t.Fatal("unchanged-table valid root block was not memoized")
	}
	headers, meta, err = decoder.DecodeRequest(headers[:0], indexed)
	if err != nil || decoder.tableGen != 2 || decoder.dynLen != 2 {
		t.Fatalf("memoized follow-up changed table state: gen=%d entries=%d err=%v", decoder.tableGen, decoder.dynLen, err)
	}
	hpackGetCompatibilityCheck(t, headers, meta, "/", "a")
}

func TestHpackGetFallbackLeadingTableUpdates(t *testing.T) {
	decoder := NewHpackDecoder()
	block := append([]byte{0x3f, 0x61}, hpackGetCompatibilityBlock("/", false, []byte{0x41, 0x01, 'a'})...)
	headers, meta, err := decoder.DecodeRequest(nil, block)
	if err != nil {
		t.Fatalf("leading update and incremental field: %v", err)
	}
	hpackGetCompatibilityCheck(t, headers, meta, "/", "a")
	if decoder.maxTableSize != 128 || decoder.tableGen != 2 || decoder.dynLen != 1 || decoder.memoValid {
		t.Fatalf("update/insertion state: max=%d gen=%d entries=%d memo=%v", decoder.maxTableSize, decoder.tableGen, decoder.dynLen, decoder.memoValid)
	}
	zero := append([]byte{0x20}, hpackGetCompatibilityBlock("/", false, []byte{0x01, 0x01, 'a'})...)
	headers, meta, err = decoder.DecodeRequest(nil, zero)
	if err != nil {
		t.Fatalf("leading zero update: %v", err)
	}
	hpackGetCompatibilityCheck(t, headers, meta, "/", "a")
	if decoder.maxTableSize != 0 || decoder.dynLen != 0 || decoder.tableGen != 3 {
		t.Fatalf("zero update state: max=%d entries=%d gen=%d", decoder.maxTableSize, decoder.dynLen, decoder.tableGen)
	}
}

func TestHpackGetFallbackRejectsInvalidBlocks(t *testing.T) {
	for _, test := range []struct {
		name  string
		block []byte
		want  error
	}{
		{"duplicate-authority", hpackGetCompatibilityBlock("/", false, []byte{0x01, 0x01, 'a', 0x01, 0x01, 'b'}), ErrH2BadHeader},
		{"regular-before-scheme", hpackGetCompatibilityBlock("/", false, []byte{0x0f, 0x2b, 0x01, 'a'}), ErrH2BadHeader},
		{"invalid-index", hpackGetCompatibilityBlock("/", false, []byte{0xbe}), ErrH2BadHeader},
		{"dangling-index", hpackGetCompatibilityBlock("/", false, []byte{0xff}), ErrH2BadHeader},
		{"truncated-literal", hpackGetCompatibilityBlock("/", false, []byte{0x01, 0x05, 'a'}), ErrH2BadHeader},
		{"truncated-path", []byte{0x82, 0x04, 0x05, '/', 0x87}, ErrH2BadHeader},
		{"malformed-path-fast", hpackGetCompatibilityBlock("/bad path", false, nil), ErrH2BadHeader},
		{"malformed-path-fallback", hpackGetCompatibilityBlock("/bad path", false, []byte{0x01, 0x01, 'a'}), ErrH2BadHeader},
		{"non-origin-path-fast", hpackGetCompatibilityBlock("relative", false, nil), errH2MalformedRequest},
		{"non-origin-path-fallback", hpackGetCompatibilityBlock("relative", false, []byte{0x01, 0x01, 'a'}), errH2MalformedRequest},
		{"late-table-update", hpackGetCompatibilityBlock("/", false, []byte{0x20}), errHpackSizeUpdateAfterField},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := NewHpackDecoder().DecodeRequest(nil, test.block); err != test.want {
				t.Fatalf("invalid block returned %v, want %v", err, test.want)
			}
		})
	}
}

func FuzzHpackGetFallbackValidBlocks(f *testing.F) {
	f.Add([]byte("ordinary"), false, uint8(0))
	f.Add([]byte("compressed"), true, uint8(1))
	f.Add([]byte("incremental"), false, uint8(2))
	f.Add([]byte("indexed"), true, uint8(3))
	f.Fuzz(func(t *testing.T, text []byte, huffman bool, representation uint8) {
		if len(text) > hpackMemoMaxBlock/8 {
			text = text[:hpackMemoMaxBlock/8]
		}
		pathBytes := []byte{'/'}
		for _, character := range text {
			pathBytes = append(pathBytes, 'a'+character%26)
		}
		path := string(pathBytes)
		decoder := NewHpackDecoder()
		representations := [][]byte{{0x01, 0x01, 'a'}, {0x11, 0x01, 'a'}, {0x41, 0x01, 'a'}, {0xbe}}
		mode := int(representation % uint8(len(representations)))
		if mode == 3 {
			if _, err := decoder.Decode([]byte{0x41, 0x01, 'a'}); err != nil {
				t.Fatal(err)
			}
		}
		block := hpackGetCompatibilityBlock(path, huffman, representations[mode])
		for range 2 {
			headers, meta, err := decoder.DecodeRequest(nil, block)
			if err != nil {
				t.Fatalf("valid generated block rejected: %v", err)
			}
			hpackGetCompatibilityCheck(t, headers, meta, path, "a")
		}
		if mode == 2 || mode == 3 {
			headers, meta, err := decoder.DecodeRequest(nil, hpackGetCompatibilityBlock(path, huffman, []byte{0xbe}))
			if err != nil {
				t.Fatalf("follow-up reference rejected: %v", err)
			}
			hpackGetCompatibilityCheck(t, headers, meta, path, "a")
		}
	})
}

func TestHpackGetFallbackPreservesOtherLayouts(t *testing.T) {
	for _, block := range [][]byte{nil, {0x82}, {0x82, 0x04}} {
		if _, _, claimed, err := decodeSimpleGetPathHTTPSRequest(NewHpackDecoder(), nil, block); claimed || err != nil {
			t.Fatalf("short layout claimed: %x claimed=%v err=%v", block, claimed, err)
		}
	}
	for _, test := range []struct {
		name           string
		block          []byte
		method, scheme string
		entries        int
	}{
		{"post", []byte{0x83, 0x04, 0x01, '/', 0x87}, "POST", "https", 0},
		{"incremental-path", []byte{0x82, 0x44, 0x01, '/', 0x87}, "GET", "https", 1},
		{"http", []byte{0x82, 0x04, 0x01, '/', 0x86}, "GET", "http", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			decoder := NewHpackDecoder()
			headers, meta, err := decoder.DecodeRequest(nil, test.block)
			want := [][2]string{{":method", test.method}, {":path", "/"}, {":scheme", test.scheme}}
			if err != nil || !reflect.DeepEqual(headers, want) || meta.method != test.method || meta.scheme != test.scheme || decoder.dynLen != test.entries || decoder.tableGen != uint64(test.entries) {
				t.Fatalf("nonmatching layout: fields=%q meta=%+v entries=%d gen=%d err=%v", headers, meta, decoder.dynLen, decoder.tableGen, err)
			}
		})
	}
}
