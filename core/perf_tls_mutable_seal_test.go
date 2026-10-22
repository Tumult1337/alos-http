//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

func perfMutableSealWriter(t testing.TB, cs *CipherSuiteConfig) *TrafficAEAD {
	w, err := NewTrafficAEAD(cs.HashFn, bytes.Repeat([]byte{7}, cs.HashLen), cs)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestPerfTLSMutableBodySealMatchesCopy(t *testing.T) {
	const maxContent = MaxRecordPayload - 1
	headLens := []int{0, 1, 120, maxContent - 1, maxContent, maxContent + 7, 2*maxContent + 3}
	bodyLens := []int{0, 1, 100, maxContent - 121, maxContent - 120, maxContent - 119, maxContent, maxContent + 1, 3 * maxContent, 3*maxContent + 5, 64 << 10, 1 << 20}
	for i := range SupportedSuites {
		cs := &SupportedSuites[i]
		for _, hl := range headLens {
			head := bytes.Repeat([]byte{'h'}, hl)
			for _, bl := range bodyLens {
				for _, spare := range []int{0, 1, 64} {
					backing := make([]byte, bl+spare)
					for j := range backing {
						backing[j] = byte(j*13 + 1)
					}
					body := backing[: bl : bl+spare]
					orig := bytes.Clone(backing)
					want := buildTLSAppDataRecordsParts([]byte("prefix"), perfMutableSealWriter(t, cs), head, bytes.Clone(body))
					got := buildTLSAppDataRecordsMutableBody([]byte("prefix"), perfMutableSealWriter(t, cs), head, body)
					if !bytes.Equal(got, want) {
						t.Fatalf("suite %#x head=%d body=%d spare=%d: records differ from the copying seal", cs.ID, hl, bl, spare)
					}
					if !bytes.Equal(backing, orig) {
						t.Fatalf("suite %#x head=%d body=%d spare=%d: body or its spare capacity was not restored", cs.ID, hl, bl, spare)
					}
				}
			}
		}
	}
}

func TestPerfTLSRecordAroundMatchesCopy(t *testing.T) {
	const maxContent = MaxRecordPayload - 1
	prefix := []byte{0, 0x3f, 0xf6, 0, 0, 0, 0, 0, 1}
	cs := &SupportedSuites[0]
	backing := make([]byte, 3*maxContent)
	for j := range backing {
		backing[j] = byte(j*7 + 3)
	}
	orig := bytes.Clone(backing)
	for _, tc := range []struct{ off, n int }{
		{0, 100},
		{len(prefix) - 1, 50},
		{len(prefix), maxContent - len(prefix)},
		{maxContent, maxContent - len(prefix)},
		{len(backing) - 10, 9},
		{len(backing) - 10, 10},
	} {
		want := buildTLSAppDataRecordsParts(nil, perfMutableSealWriter(t, cs), prefix, bytes.Clone(backing[tc.off:tc.off+tc.n]))
		got := sealTLSRecordAround(nil, perfMutableSealWriter(t, cs), prefix, backing, tc.off, tc.n)
		if !bytes.Equal(got, want) {
			t.Fatalf("off=%d n=%d: record differs from the copying seal", tc.off, tc.n)
		}
		if !bytes.Equal(backing, orig) {
			t.Fatalf("off=%d n=%d: body bytes around the record were not restored", tc.off, tc.n)
		}
	}
}

func TestPerfTLSMutableBodySealZeroAlloc(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under -race")
	}
	cs := &SupportedSuites[0]
	w := perfMutableSealWriter(t, cs)
	head := bytes.Repeat([]byte{'h'}, 120)
	body := make([]byte, 64<<10, 64<<10+1)
	dst := buildTLSAppDataRecordsMutableBody(nil, w, head, body)
	allocs := testing.AllocsPerRun(50, func() {
		dst = buildTLSAppDataRecordsMutableBody(dst[:0], w, head, body)
	})
	if allocs > 0 {
		t.Fatalf("mutable-body seal allocated %.1f per run, want 0", allocs)
	}
}

func benchPerfTLSMutableSeal(b *testing.B, size int, mutable bool) {
	cs := &SupportedSuites[0]
	w := perfMutableSealWriter(b, cs)
	head := bytes.Repeat([]byte{'h'}, 120)
	body := make([]byte, size, size+1)
	dst := buildTLSAppDataRecordsParts(nil, w, head, body)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if mutable {
			dst = buildTLSAppDataRecordsMutableBody(dst[:0], w, head, body)
		} else {
			dst = buildTLSAppDataRecordsParts(dst[:0], w, head, body)
		}
	}
}

func BenchmarkPerfTLS13SealCopy64K(b *testing.B) {
	benchPerfTLSMutableSeal(b, 64<<10, false)
}

func BenchmarkPerfTLS13SealMutable64K(b *testing.B) {
	benchPerfTLSMutableSeal(b, 64<<10, true)
}

func BenchmarkPerfTLS13SealCopy112K(b *testing.B) {
	benchPerfTLSMutableSeal(b, 7*(MaxRecordPayload-1), false)
}

func BenchmarkPerfTLS13SealMutable112K(b *testing.B) {
	benchPerfTLSMutableSeal(b, 7*(MaxRecordPayload-1), true)
}
