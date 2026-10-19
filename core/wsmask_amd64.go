//go:build linux && amd64

package core

import "unsafe"

const wsMaskSIMDBlock = 32

//go:noescape
func maskXORAVX2(p *byte, n int, mask uint64)

func maskXOR(payload []byte, maskKey [4]byte) {
	if hasAVX2 && len(payload) >= wsMaskSIMDBlock {
		bulk := len(payload) &^ (wsMaskSIMDBlock - 1)
		maskXORAVX2(unsafe.SliceData(payload), bulk, wsMaskWord(maskKey))
		maskXORSWAR(payload[bulk:], maskKey)
		return
	}
	maskXORSWAR(payload, maskKey)
}
