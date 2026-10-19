//go:build linux && amd64

package core

import (
	"bytes"
	"strconv"
	"testing"
)

func maskXORReference(payload []byte, maskKey [4]byte) {
	for i := range payload {
		payload[i] ^= maskKey[i&3]
	}
}

func checkMaskXOR(t testing.TB, data []byte, key [4]byte) {
	t.Helper()
	got := append([]byte(nil), data...)
	want := append([]byte(nil), data...)
	maskXOR(got, key)
	maskXORReference(want, key)
	if !bytes.Equal(got, want) {
		t.Fatalf("maskXOR differs from the reference for %d bytes, key %x", len(data), key)
	}
}

func TestWSUnmaskMatchesReference(t *testing.T) {
	key := [4]byte{0xa1, 0xb2, 0xc3, 0xd4}
	buf := make([]byte, 4096+64)
	for i := range buf {
		buf[i] = byte(i*7 + 3)
	}
	for _, offset := range []int{0, 1, 3, 7, 31} {
		for _, n := range []int{0, 1, 3, 4, 7, 8, 31, 32, 33, 63, 64, 127, 128, 129, 255, 256, 1000, 4096} {
			checkMaskXOR(t, buf[offset:offset+n], key)
		}
	}
	region := bytes.Repeat([]byte{0x55}, 300)
	maskXOR(region[10:290], key)
	for i := range 10 {
		if region[i] != 0x55 || region[290+i] != 0x55 {
			t.Fatal("maskXOR wrote outside the slice")
		}
	}
}

func FuzzWSUnmaskDifferential(f *testing.F) {
	f.Add([]byte("hello"), uint32(0x01020304), uint8(0))
	f.Add(bytes.Repeat([]byte{0xff}, 300), uint32(0xdeadbeef), uint8(5))
	f.Fuzz(func(t *testing.T, data []byte, key uint32, offset uint8) {
		start := int(offset) % (len(data) + 1)
		checkMaskXOR(t, data[start:], [4]byte{byte(key), byte(key >> 8), byte(key >> 16), byte(key >> 24)})
	})
}

func BenchmarkWSUnmask(b *testing.B) {
	key := [4]byte{1, 2, 3, 4}
	for _, n := range []int{16, 125, 1024, 16 << 10, 1 << 20} {
		buf := make([]byte, n)
		b.Run("swar-"+strconv.Itoa(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			for b.Loop() {
				maskXORSWAR(buf, key)
			}
		})
		b.Run("dispatch-"+strconv.Itoa(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			for b.Loop() {
				maskXOR(buf, key)
			}
		})
	}
}
