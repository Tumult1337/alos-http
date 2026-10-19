//go:build linux && amd64

package core

import "bytes"

var fpCR = []byte("\r")

func fpCountCRFindNULGeneric(block []byte) (int, bool) {
	return bytes.Count(block, fpCR), bytes.IndexByte(block, 0) >= 0
}
