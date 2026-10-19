//go:build linux && amd64

package core

import (
	"testing"
	"unsafe"

	"github.com/guno1928/turbo"
)

func fpFixCheckCRNULKernel(t *testing.T, buf []byte) {
	t.Helper()
	gotCRs, gotNUL := fpCountCRFindNULAVX2(unsafe.SliceData(buf), len(buf))
	wantCRs, wantNUL := fpCountCRFindNULGeneric(buf)
	if gotCRs != wantCRs || gotNUL != wantNUL {
		t.Fatalf("buf %q: avx2 (%d,%v), generic (%d,%v)", buf, gotCRs, gotNUL, wantCRs, wantNUL)
	}
}

func TestFPFixCountCRFindNULAVX2MatchesGeneric(t *testing.T) {
	if !hasAVX2 {
		t.Skip("no AVX2")
	}
	alphabet := []byte{'a', ':', ' ', '\r', '\n', 0, '\t', 0x8d, 0x80}
	turbo.Seed(0x5eed)
	for round := 0; round < 50000; round++ {
		buf := make([]byte, avx2ScanMinLen+turbo.Intn(300))
		for i := range buf {
			if turbo.Intn(3) == 0 {
				buf[i] = alphabet[turbo.Intn(len(alphabet))]
			} else {
				buf[i] = 'x'
			}
		}
		fpFixCheckCRNULKernel(t, buf)
	}
}

func TestFPFixCountCRFindNULAVX2EveryPosition(t *testing.T) {
	if !hasAVX2 {
		t.Skip("no AVX2")
	}
	for n := avx2ScanMinLen; n <= 4*avx2ScanMinLen; n++ {
		for at := 0; at < n; at++ {
			for _, b := range []byte{'\r', 0} {
				buf := make([]byte, n)
				for i := range buf {
					buf[i] = 'y'
				}
				buf[at] = b
				fpFixCheckCRNULKernel(t, buf)
			}
		}
	}
}
