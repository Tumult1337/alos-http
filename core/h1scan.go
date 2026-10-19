//go:build linux && amd64

package core

import (
	"encoding/binary"
	"math/bits"
)

const (
	swarOnes = 0x0101010101010101
	swarHigh = 0x8080808080808080
)

func isH1Special(c byte) bool {
	return c < 0x20 && c != '\t' || c == 0x7f
}

func classifyH1Special(p []byte, i int) (end int, bad bool) {
	if p[i] == '\r' {
		if i+1 == len(p) {
			return -1, false
		}
		if p[i+1] == '\n' {
			return i, false
		}
	}
	return i, true
}

func firstH1SpecialSWAR(p []byte) int {
	i := 0
	for ; i+8 <= len(p); i += 8 {
		w := binary.LittleEndian.Uint64(p[i:])
		below := (w - 0x20*swarOnes) &^ w & swarHigh
		del := w ^ 0x7f*swarOnes
		del = (del - swarOnes) &^ del & swarHigh
		for m := below | del; m != 0; m &= m - 1 {
			j := i + bits.TrailingZeros64(m)>>3
			if isH1Special(p[j]) {
				return j
			}
		}
	}
	for ; i < len(p); i++ {
		if isH1Special(p[i]) {
			return i
		}
	}
	return -1
}

func firstNonTokenByte(p []byte) int {
	for i := 0; i < len(p); i++ {
		if !h1TokenChar[p[i]] {
			return i
		}
	}
	return -1
}

func classifyFirstSpecial(p []byte, i int) (end int, bad bool) {
	if i < 0 {
		return -1, false
	}
	return classifyH1Special(p, i)
}

func h1HeaderLineSWAR(p []byte) (special, nameEnd int) {
	nameEnd = firstNonTokenByte(p)
	if nameEnd < 0 {
		return -1, -1
	}
	special = firstH1SpecialSWAR(p[nameEnd:])
	if special < 0 {
		return -1, nameEnd
	}
	return nameEnd + special, nameEnd
}

func validH1Colon(line []byte, nameEnd int) bool {
	return nameEnd > 0 && nameEnd < len(line) && line[nameEnd] == ':'
}

func trimOWS(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

const h1ScalarScanMax = 32

const (
	h1ClassToken uint8 = 1 << iota
	h1ClassHost
	h1ClassSpecial
)

var h1FieldClass = func() (table [256]uint8) {
	for i := range table {
		c := byte(i)
		if h1TokenChar[c] {
			table[i] |= h1ClassToken
		}
		if invalidHostChar[c] == 0 {
			table[i] |= h1ClassHost
		}
		if isH1Special(c) {
			table[i] |= h1ClassSpecial
		}
	}
	return table
}()

func h1HeaderLineScalar(p []byte) (special, nameEnd int, hostSafe bool) {
	i := 0
	for i < len(p) && h1FieldClass[p[i]]&h1ClassToken != 0 {
		i++
	}
	if i == len(p) {
		return -1, -1, false
	}
	nameEnd = i
	common := uint8(0)
	if p[i] == ':' {
		common = ^uint8(0)
		i++
		for i < len(p) && (p[i] == ' ' || p[i] == '\t') {
			i++
		}
	}
	for ; i < len(p); i++ {
		class := h1FieldClass[p[i]]
		if class&h1ClassSpecial != 0 {
			return i, nameEnd, common&h1ClassHost != 0
		}
		common &= class
	}
	return -1, nameEnd, false
}

const h1BlockMaxChunks = 16

const h1BlockMaxBytes = h1BlockMaxChunks * 64

const h1BlockMinBytes = 48

type h1BlockIndexOut struct {
	starts [h1BlockMaxChunks]uint64
	ends   [h1BlockMaxChunks]uint64
	cands  [h1BlockMaxChunks]uint64
}

func h1NextBit(words *[h1BlockMaxChunks]uint64, from, chunks int) int {
	i := from >> 6
	if i >= chunks {
		return -1
	}
	w := words[i] & (^uint64(0) << (from & 63))
	for w == 0 {
		i++
		if i >= chunks {
			return -1
		}
		w = words[i]
	}
	return i<<6 | bits.TrailingZeros64(w)
}
