//go:build linux && amd64

package core

import "unsafe"

const avx2ScanMinLen = 32

//go:noescape
func firstH1SpecialAVX2(p *byte, n int) int

//go:noescape
func h1HeaderLineAVX2(p *byte, n int) (special, nameEnd int)

func firstH1Special(p []byte) int {
	if hasAVX2 && len(p) >= avx2ScanMinLen {
		return firstH1SpecialAVX2(unsafe.SliceData(p), len(p))
	}
	return firstH1SpecialSWAR(p)
}

func h1HeaderLineSpecials(p []byte) (special, nameEnd int) {
	if hasAVX2 && len(p) >= avx2ScanMinLen {
		return h1HeaderLineAVX2(unsafe.SliceData(p), len(p))
	}
	return h1HeaderLineSWAR(p)
}
