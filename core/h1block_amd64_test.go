//go:build linux && amd64

package core

import (
	"bytes"
	"strings"
	"testing"
)

const h1BlockCandidateLetters = "cehtCEHT"

func h1BlockIndexRef(block []byte) (want h1BlockIndexOut, ok bool) {
	n := len(block)
	if n < 2 || n > h1BlockMaxBytes || block[n-2] != '\r' || block[n-1] != '\n' {
		return want, false
	}
	for pos := 0; pos < n; {
		rest := block[pos:]
		special, nameEnd := h1HeaderLineRef(rest)
		end, bad := classifyFirstSpecial(rest, special)
		if bad || end <= 0 || !validH1Colon(rest[:end], nameEnd) {
			return h1BlockIndexOut{}, false
		}
		want.starts[pos/64] |= 1 << (pos % 64)
		if strings.IndexByte(h1BlockCandidateLetters, block[pos]) >= 0 {
			want.cands[pos/64] |= 1 << (pos % 64)
		}
		colon := pos + nameEnd
		want.ends[colon/64] |= 1 << (colon % 64)
		pos += end + 2
	}
	return want, true
}

func checkBlockIndex(t *testing.T, block []byte) {
	t.Helper()
	want, wantOK := h1BlockIndexRef(block)
	var got h1BlockIndexOut
	gotOK := h1BlockIndex(block, &got)
	if !hasAVX2 {
		if gotOK {
			t.Fatal("h1BlockIndex reported ok without AVX2")
		}
		return
	}
	if gotOK != wantOK {
		t.Fatalf("%q: ok=%v, reference ok=%v", block, gotOK, wantOK)
	}
	if !gotOK {
		return
	}
	chunks := (len(block) + 63) / 64
	for i := 0; i < chunks; i++ {
		if got.starts[i] != want.starts[i] || got.ends[i] != want.ends[i] || got.cands[i] != want.cands[i] {
			t.Fatalf("%q chunk %d: starts %#x ends %#x cands %#x, want %#x %#x %#x", block, i, got.starts[i], got.ends[i], got.cands[i], want.starts[i], want.ends[i], want.cands[i])
		}
	}
}

func h1BlockTemplates() []string {
	var out []string
	base := "Host: example.com\r\nX-A: v\r\n"
	out = append(out, base, "A:\r\n", "a:b\r\n", "connection: close\r\nExpect: x\r\nTE: y\r\n")
	for _, total := range []int{62, 63, 64, 65, 66, 127, 128, 129, 191, 192, 193} {
		pad := total - len("X-Pad: \r\n") - len(base)
		if pad < 0 {
			continue
		}
		out = append(out, base+"X-Pad: "+strings.Repeat("v", pad)+"\r\n")
	}
	longName := strings.Repeat("N", 70)
	out = append(out, longName+": v\r\nHost: a\r\n")
	out = append(out, "X: "+strings.Repeat("w", 58)+"\r\n"+strings.Repeat("M", 40)+":\t z \r\n")
	return out
}

func TestH1BlockIndexMatchesReferenceOnEveryByte(t *testing.T) {
	checked := 0
	for _, tmpl := range h1BlockTemplates() {
		checkBlockIndex(t, []byte(tmpl))
		for pos := 0; pos < len(tmpl); pos++ {
			buf := []byte(tmpl)
			for c := 0; c < 256; c++ {
				buf[pos] = byte(c)
				checkBlockIndex(t, buf)
				checked++
			}
		}
	}
	t.Logf("checked %d blocks", checked)
}

func TestH1BlockIndexRejectsAndLimits(t *testing.T) {
	cases := []string{
		"",
		"\r\n",
		"a:b",
		"a:b\n",
		"a:b\r",
		"a:b\r\n\r\n",
		" a:b\r\n",
		"a :b\r\n",
		"a\r\n",
		":a\r\n",
		"a:b\rc\r\n",
		"a:b\nc\r\n",
		"a:\x00\r\n",
		"a:\x7f\r\n",
		"a:\x80\xff\r\n",
		"a:\t\r\n",
		"a:b\r\n\rc:d\r\n",
	}
	for _, c := range cases {
		checkBlockIndex(t, []byte(c))
	}
	full := bytes.Repeat([]byte("X-Fill: "+strings.Repeat("v", 64-len("X-Fill: \r\n"))+"\r\n"), h1BlockMaxBytes/64)
	if len(full) != h1BlockMaxBytes {
		t.Fatalf("fixture is %d bytes", len(full))
	}
	checkBlockIndex(t, full)
	var out h1BlockIndexOut
	if h1BlockIndex(append(full, "a:b\r\n"...), &out) {
		t.Fatal("accepted a block above h1BlockMaxBytes")
	}
}

func TestH1NextBit(t *testing.T) {
	var words [h1BlockMaxChunks]uint64
	words[0] = 1<<3 | 1<<40
	words[2] = 1 << 63
	cases := []struct{ from, want int }{{0, 3}, {3, 3}, {4, 40}, {41, 191}, {191, 191}, {192, -1}, {1000, -1}}
	for _, tc := range cases {
		if got := h1NextBit(&words, tc.from, 3); got != tc.want {
			t.Errorf("h1NextBit(from %d) = %d, want %d", tc.from, got, tc.want)
		}
	}
}

func FuzzH1BlockIndex(f *testing.F) {
	for _, tmpl := range h1BlockTemplates() {
		f.Add([]byte(tmpl))
	}
	f.Fuzz(func(t *testing.T, block []byte) {
		checkBlockIndex(t, block)
	})
}

func BenchmarkH1BlockIndex(b *testing.B) {
	for _, req := range gateRootFastRequests {
		start := bytes.Index(req.raw, []byte("\r\n")) + 2
		block := req.raw[start : len(req.raw)-2]
		b.Run(req.name, func(b *testing.B) {
			var out h1BlockIndexOut
			for b.Loop() {
				h1BlockIndex(block, &out)
			}
		})
	}
}
