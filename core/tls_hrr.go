//go:build linux && amd64

package core

import "bytes"

var helloRetryRequestRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

const tlsHSMessageHash = 254

type tls13Retry struct {
	suite            *CipherSuiteConfig
	group            tlsGroup
	transcriptPrefix []byte
	helloIdentity    []byte
}

func newHelloRetry(cs *CipherSuiteConfig, group tlsGroup, ch *ParsedClientHello, firstHello []byte) (*tls13Retry, []byte) {
	h := cs.HashFn()
	h.Write(firstHello)
	prefix := []byte{tlsHSMessageHash, 0, 0, byte(cs.HashLen)}
	prefix = h.Sum(prefix)
	hrr := buildHelloRetryRequest(ch.SessionID, cs.ID, group)
	prefix = append(prefix, hrr...)
	return &tls13Retry{
		suite:            cs,
		group:            group,
		transcriptPrefix: prefix,
		helloIdentity:    appendHelloIdentity(nil, ch),
	}, hrr
}

func (r *tls13Retry) acceptSecondHello(ch *ParsedClientHello) ([]byte, tlsAlert, bool) {
	share := ch.keyShareFor(r.group)
	if ch.keyShareCount != 1 || share == nil {
		return nil, alertIllegalParameter, false
	}
	if !bytes.Equal(appendHelloIdentity(nil, ch), r.helloIdentity) {
		return nil, alertIllegalParameter, false
	}
	return share, 0, true
}

func appendHelloIdentity(dst []byte, ch *ParsedClientHello) []byte {
	dst = append(dst, byte(ch.LegacyVersion>>8), byte(ch.LegacyVersion))
	dst = append(dst, ch.Random[:]...)
	dst = appendLenPrefixed(dst, ch.SessionID)
	dst = appendLenPrefixed(dst, []byte(ch.ServerName))
	dst = appendU16List(dst, ch.CipherSuites)
	dst = appendU16List(dst, ch.SupportedVersions)
	dst = appendU16List(dst, ch.SupportedGroups)
	dst = appendU16List(dst, ch.SignatureSchemes)
	dst = append(dst, byte(len(ch.ALPNProtos)>>8), byte(len(ch.ALPNProtos)))
	for _, p := range ch.ALPNProtos {
		dst = appendLenPrefixed(dst, []byte(p))
	}
	return dst
}

func appendLenPrefixed(dst, b []byte) []byte {
	dst = append(dst, byte(len(b)>>8), byte(len(b)))
	return append(dst, b...)
}

func appendU16List(dst []byte, list []uint16) []byte {
	dst = append(dst, byte(len(list)>>8), byte(len(list)))
	for _, v := range list {
		dst = append(dst, byte(v>>8), byte(v))
	}
	return dst
}
