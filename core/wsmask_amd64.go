//go:build linux && amd64

package core

import (
	"unicode/utf8"
	"unsafe"
)

const wsMaskSIMDBlock = 32

const utf8SIMDMinLen = 64

//go:noescape
func maskXORAVX2(p *byte, n int, mask uint64)

//go:noescape
func asciiPrefixAVX2(p *byte, n int) int

func maskXOR(payload []byte, maskKey [4]byte) {
	if hasAVX2 && len(payload) >= wsMaskSIMDBlock {
		bulk := len(payload) &^ (wsMaskSIMDBlock - 1)
		maskXORAVX2(unsafe.SliceData(payload), bulk, wsMaskWord(maskKey))
		maskXORSWAR(payload[bulk:], maskKey)
		return
	}
	maskXORSWAR(payload, maskKey)
}

func validUTF8(p []byte) bool {
	if hasAVX2 && len(p) >= utf8SIMDMinLen {
		p = p[asciiPrefixAVX2(unsafe.SliceData(p), len(p)&^(wsMaskSIMDBlock-1)):]
	}
	return utf8.Valid(p)
}
