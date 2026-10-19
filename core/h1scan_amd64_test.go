//go:build linux && amd64

package core

import "unsafe"

func scanH1LineAVX2(p []byte) (end int, bad bool) {
	if len(p) < avx2ScanMinLen {
		return scanH1LineSWAR(p)
	}
	return classifyFirstSpecial(p, firstH1SpecialAVX2(unsafe.SliceData(p), len(p)))
}

func init() {
	if hasAVX2 {
		h1ScanArchVariants = append(h1ScanArchVariants, h1ScanVariant{"AVX2", scanH1LineAVX2})
	}
}
