//go:build linux && amd64

package core

import "strings"

var hopByHopHeaderNames = [...]string{
	"connection",
	"keep-alive",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"proxy-connection",
	"proxy-authenticate",
	"proxy-authorization",
}

var hopByHopLengthMask = func() uint64 {
	var mask uint64
	for _, h := range hopByHopHeaderNames {
		mask |= 1 << uint(len(h))
	}
	return mask
}()

func hopByHopLengthPossible(n int) bool {
	return n < 64 && hopByHopLengthMask&(1<<uint(n)) != 0
}

func isHopByHopName[T ~string | ~[]byte](name T) bool {
	if !hopByHopLengthPossible(len(name)) {
		return false
	}
	for _, h := range hopByHopHeaderNames {
		if len(h) == len(name) && string(name) == h {
			return true
		}
	}
	return false
}

func isHopByHopBytes(name []byte) bool { return isHopByHopName(name) }

func isHopByHopStr(name string) bool { return isHopByHopName(name) }

func isHopByHopFold(name string) bool {
	if !hopByHopLengthPossible(len(name)) {
		return false
	}
	for _, h := range hopByHopHeaderNames {
		if headerNameIs(name, h) {
			return true
		}
	}
	return false
}

const connectionSpecificResponseLengthMask uint64 = 1<<len("te") | 1<<len("upgrade") | 1<<len("connection") | 1<<len("proxy-connection") | 1<<len("transfer-encoding")

func isConnectionSpecificResponseField(name string) bool {
	return len(name) < 64 && connectionSpecificResponseLengthMask&(1<<uint(len(name))) != 0 && isConnectionSpecificResponseName(name)
}

func isConnectionSpecificResponseName(name string) bool {
	switch len(name) {
	case len("te"):
		return headerNameIs(name, "te")
	case len("upgrade"):
		return headerNameIs(name, "upgrade")
	case len("connection"):
		return headerNameIs(name, "connection") || headerNameIs(name, "keep-alive")
	case len("proxy-connection"):
		return headerNameIs(name, "proxy-connection")
	case len("transfer-encoding"):
		return headerNameIs(name, "transfer-encoding")
	}
	return false
}

const (
	maxConnectionTokens = 16
	asciiCaseBit        = 0x20
)

type connectionTokens struct {
	names    []string
	overflow map[string]struct{}
}

func connectionNominations(headers [][2]string) (t connectionTokens) {
	for i := range headers {
		if name := headers[i][0]; len(name) == len("connection") && name[0]|asciiCaseBit == 'c' {
			t.addIfConnection(name, headers[i][1])
		}
	}
	return t
}

func (t *connectionTokens) addIfConnection(name, value string) {
	if EqualFoldASCII(name, "connection") {
		t.add(value)
	}
}

func (t *connectionTokens) add(value string) {
	for value != "" {
		var token string
		token, value, _ = strings.Cut(value, ",")
		token = trimASCIISpace(token)
		if token == "" || isHopByHopFold(token) {
			continue
		}
		if len(t.names) < maxConnectionTokens {
			t.names = append(t.names, token)
			continue
		}
		if t.overflow == nil {
			t.overflow = make(map[string]struct{})
		}
		t.overflow[ToLowerASCII(token)] = struct{}{}
	}
}

func (t *connectionTokens) nominates(name string) bool {
	return len(t.names) != 0 && t.lookup(name)
}

func (t *connectionTokens) lookup(name string) bool {
	for _, token := range t.names {
		if EqualFoldASCII(token, name) {
			return true
		}
	}
	if t.overflow == nil {
		return false
	}
	_, ok := t.overflow[ToLowerASCII(name)]
	return ok
}
