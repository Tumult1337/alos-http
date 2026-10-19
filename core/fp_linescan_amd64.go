//go:build linux && amd64

package core

import "unsafe"

//go:noescape
func fpCountCRFindNULAVX2(p *byte, n int) (crs int, nul bool)

func fpCountCRFindNUL(block []byte) (int, bool) {
	if hasAVX2 && len(block) >= avx2ScanMinLen {
		return fpCountCRFindNULAVX2(unsafe.SliceData(block), len(block))
	}
	return fpCountCRFindNULGeneric(block)
}
