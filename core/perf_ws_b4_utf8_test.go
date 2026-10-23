//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

func b4UTF8Samples() [][]byte {
	pieces := [][]byte{
		[]byte("é"), []byte("€"), []byte("😀"), {0x80}, {0xC0, 0xAF}, {0xE0, 0x80, 0xAF}, {0xED, 0xA0, 0x80},
		{0xF4, 0x90, 0x80, 0x80}, {0xFF}, {0xC3}, {0xE2, 0x82}, {0xF0, 0x9F, 0x98},
	}
	var out [][]byte
	for n := 0; n <= 300; n++ {
		ascii := bytes.Repeat([]byte{'a'}, n)
		out = append(out, ascii)
		for _, p := range pieces {
			for _, at := range []int{0, n / 3, n / 2, n} {
				s := append(append(append([]byte{}, ascii[:at]...), p...), ascii[at:]...)
				out = append(out, s)
			}
		}
	}
	return out
}

func b4CheckValidUTF8(t *testing.T) {
	for _, s := range b4UTF8Samples() {
		if got, want := validUTF8(s), utf8.Valid(s); got != want {
			t.Fatalf("validUTF8(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestB4ValidUTF8MatchesStdlib(t *testing.T) {
	b4CheckValidUTF8(t)
}

func TestB4ValidUTF8WithoutAVX2(t *testing.T) {
	prev := hasAVX2
	hasAVX2 = false
	t.Cleanup(func() { hasAVX2 = prev })
	b4CheckValidUTF8(t)
}

func TestB4ValidUTF8PageBoundary(t *testing.T) {
	page := unix.Getpagesize()
	mem, err := unix.Mmap(-1, 0, 2*page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mem)
	if err := unix.Mprotect(mem[page:], unix.PROT_NONE); err != nil {
		t.Fatal(err)
	}
	for n := 0; n <= 512; n++ {
		buf := mem[page-n : page]
		for i := range buf {
			buf[i] = 'x'
		}
		if !validUTF8(buf) {
			t.Fatalf("ascii len %d reported invalid", n)
		}
		if n > 0 {
			buf[n-1] = 0xC3
			if validUTF8(buf) {
				t.Fatalf("truncated sequence at page end, len %d, reported valid", n)
			}
		}
		var key = [4]byte{1, 2, 3, 4}
		maskXOR(buf, key)
		maskXOR(buf, key)
	}
}

func FuzzB4ValidUTF8(f *testing.F) {
	for _, s := range b4UTF8Samples()[:64] {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s []byte) {
		if got, want := validUTF8(s), utf8.Valid(s); got != want {
			t.Fatalf("validUTF8(%q) = %v, want %v", s, got, want)
		}
	})
}

func BenchmarkB4ValidUTF8(b *testing.B) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"ascii64", bytes.Repeat([]byte{'a'}, 64)},
		{"ascii16K", perfWSText(16 << 10)},
		{"mixed16K", append(perfWSText(8<<10), bytes.Repeat([]byte("é"), 4<<10)...)},
	} {
		b.Run("stdlib/"+tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.data)))
			for b.Loop() {
				if !utf8.Valid(tc.data) {
					b.Fatal("invalid")
				}
			}
		})
		b.Run("simd/"+tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.data)))
			for b.Loop() {
				if !validUTF8(tc.data) {
					b.Fatal("invalid")
				}
			}
		})
	}
}
