//go:build linux && amd64

package core

import "bytes"

type h1RejectReason uint8

const (
	h1RejectNone h1RejectReason = iota
	h1RejectRequestLine
	h1RejectName
	h1RejectCTL
	h1RejectFold
	h1RejectNoColon
	h1RejectHost
	h1RejectTransferEncoding
)

type h1Expect uint8

const (
	h1ExpectNone h1Expect = iota
	h1ExpectContinue
	h1ExpectUnknown
)

func classifyExpect(prev h1Expect, value []byte) h1Expect {
	if prev == h1ExpectUnknown || len(value) == 0 {
		return prev
	}
	if asciiEqualFoldBytes(value, "100-continue") {
		return h1ExpectContinue
	}
	return h1ExpectUnknown
}

func h1HeaderLineReject(line []byte) h1RejectReason {
	if line[0] == ' ' || line[0] == '\t' {
		return h1RejectFold
	}
	if bytes.IndexByte(line, ':') <= 0 {
		return h1RejectNoColon
	}
	return h1RejectName
}

func splitAbsoluteForm(target string) (authority, rest string, ok bool) {
	var schemeLen int
	switch {
	case len(target) >= 7 && EqualFoldASCII(target[:7], "http://"):
		schemeLen = 7
	case len(target) >= 8 && EqualFoldASCII(target[:8], "https://"):
		schemeLen = 8
	default:
		return "", "", false
	}
	after := target[schemeLen:]
	end := len(after)
	for i := 0; i < len(after); i++ {
		if after[i] == '/' || after[i] == '?' {
			end = i
			break
		}
	}
	authority, rest = after[:end], after[end:]
	if rest == "" || rest[0] == '?' {
		rest = "/" + rest
	}
	return authority, rest, true
}
