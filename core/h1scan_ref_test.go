//go:build linux && amd64

package core

func firstH1SpecialRef(p []byte) int {
	for i := 0; i < len(p); i++ {
		if isH1Special(p[i]) {
			return i
		}
	}
	return -1
}

func scanH1LineRef(p []byte) (end int, bad bool) {
	return classifyFirstSpecial(p, firstH1SpecialRef(p))
}

func scanH1LineSWAR(p []byte) (end int, bad bool) {
	return classifyFirstSpecial(p, firstH1SpecialSWAR(p))
}

func h1HeaderLineRef(p []byte) (special, nameEnd int) {
	return firstH1SpecialRef(p), firstNonTokenByte(p)
}

func h1HeaderLineScan(p []byte) (special, nameEnd int, hostSafe bool) {
	if len(p) < h1ScalarScanMax {
		return h1HeaderLineScalar(p)
	}
	special, nameEnd = h1HeaderLineSpecials(p)
	return special, nameEnd, false
}
