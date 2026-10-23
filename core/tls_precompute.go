//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/hmac"
	"hash"
)

type hkdfLabelTemplate struct {
	prefix    []byte
	totalLen  int
	outLen    int
	digestLen int
}

func newHKDFLabelTemplate(label string, outLen, ctxLen, digestLen int) hkdfLabelTemplate {
	const tls13Prefix = "tls13 "
	fullLen := len(tls13Prefix) + len(label)
	prefixLen := 2 + 1 + fullLen + 1
	prefix := make([]byte, prefixLen)
	prefix[0] = byte(outLen >> 8)
	prefix[1] = byte(outLen)
	prefix[2] = byte(fullLen)
	copy(prefix[3:], tls13Prefix)
	copy(prefix[3+len(tls13Prefix):], label)
	prefix[3+fullLen] = byte(ctxLen)
	return hkdfLabelTemplate{
		prefix:    prefix,
		totalLen:  prefixLen + ctxLen,
		outLen:    outLen,
		digestLen: digestLen,
	}
}

func (t hkdfLabelTemplate) ExpandTo(h func() hash.Hash, secret, ctx, dst []byte) []byte {
	if cap(dst) < t.digestLen {
		dst = make([]byte, 0, t.digestLen)
	} else {
		dst = dst[:0]
	}
	if m := acquireTLSHMAC(h, secret); m != nil {
		m.write(t.prefix)
		m.write(ctx)
		m.write(hkdfExpandOneByte[:])
		dst = m.sumTo(dst)
		m.release()
		return dst[:t.outLen]
	}
	return hmacGenericAppend(h, secret, t.prefix, ctx, hkdfExpandOneByte[:], dst)[:t.outLen]
}

func hmacGenericAppend(h func() hash.Hash, key, a, b, c, dst []byte) []byte {
	mac := hmac.New(h, bytes.Clone(key))
	msg := make([]byte, 0, len(a)+len(b)+len(c))
	msg = append(append(append(msg, a...), b...), c...)
	mac.Write(msg)
	return append(dst, mac.Sum(nil)...)
}

// TLSExtractTo performs the TLS 1.3 HKDF-Extract step (HMAC(salt, ikm)), appending the result to dst and returning the extended slice.
func TLSExtractTo(h func() hash.Hash, salt, ikm, dst []byte) []byte {
	if m := acquireTLSHMAC(h, salt); m != nil {
		m.write(ikm)
		dst = m.sumTo(dst[:0])
		m.release()
		return dst
	}
	return hmacGenericAppend(h, salt, ikm, nil, nil, dst[:0])
}

func init() {
	for i := range SupportedSuites {
		SupportedSuites[i].initPrecompute()
	}
}

func (cs *CipherSuiteConfig) initPrecompute() {
	cs.zeroHashInput = make([]byte, cs.HashLen)
	cs.emptyTranscriptHash = EmptyTranscriptHash(cs.HashFn)

	cs.labelDerived = newHKDFLabelTemplate("derived", cs.HashLen, cs.HashLen, cs.HashLen)
	cs.labelFinished = newHKDFLabelTemplate("finished", cs.HashLen, 0, cs.HashLen)
	cs.labelKey = newHKDFLabelTemplate("key", cs.KeyLen, 0, cs.HashLen)
	cs.labelIV = newHKDFLabelTemplate("iv", cs.IVLen, 0, cs.HashLen)
	cs.labelClientHSTraffic = newHKDFLabelTemplate("c hs traffic", cs.HashLen, cs.HashLen, cs.HashLen)
	cs.labelServerHSTraffic = newHKDFLabelTemplate("s hs traffic", cs.HashLen, cs.HashLen, cs.HashLen)
	cs.labelClientAppTraffic = newHKDFLabelTemplate("c ap traffic", cs.HashLen, cs.HashLen, cs.HashLen)
	cs.labelServerAppTraffic = newHKDFLabelTemplate("s ap traffic", cs.HashLen, cs.HashLen, cs.HashLen)
	cs.labelResBinder = newHKDFLabelTemplate("res binder", cs.HashLen, cs.HashLen, cs.HashLen)
	cs.labelResMaster = newHKDFLabelTemplate("res master", cs.HashLen, cs.HashLen, cs.HashLen)
	cs.labelResumption = newHKDFLabelTemplate("resumption", cs.HashLen, 0, cs.HashLen)
	cs.labelTrafficUpdate = newHKDFLabelTemplate("traffic upd", cs.HashLen, 0, cs.HashLen)

	var earlyBuf [64]byte
	cs.earlySecret = append(cs.earlySecret[:0], TLSExtractTo(cs.HashFn, cs.zeroHashInput, cs.zeroHashInput, earlyBuf[:0])...)
	var derivedBuf [64]byte
	cs.derivedFromEarly = append(cs.derivedFromEarly[:0], cs.labelDerived.ExpandTo(cs.HashFn, cs.earlySecret, cs.emptyTranscriptHash, derivedBuf[:0])...)
}

// DeriveSecretTo derives a TLS 1.3 secret from secret and transcriptHash using the given HKDF label template, appending the result to dst.
func (cs *CipherSuiteConfig) DeriveSecretTo(tmpl *hkdfLabelTemplate, secret, transcriptHash, dst []byte) []byte {
	return tmpl.ExpandTo(cs.HashFn, secret, transcriptHash, dst)
}

// ComputeFinishedTo computes a TLS 1.3 Finished message MAC over transcriptHash using baseSecret, appending the result to dst.
func (cs *CipherSuiteConfig) ComputeFinishedTo(baseSecret, transcriptHash, dst []byte) []byte {
	var finishedKeyBuf [64]byte
	finishedKey := cs.labelFinished.ExpandTo(cs.HashFn, baseSecret, nil, finishedKeyBuf[:0])
	if m := acquireTLSHMAC(cs.HashFn, finishedKey); m != nil {
		m.write(transcriptHash)
		dst = m.sumTo(dst[:0])
		m.release()
	} else {
		dst = hmacGenericAppend(cs.HashFn, finishedKey, transcriptHash, nil, nil, dst[:0])
	}
	clear(finishedKeyBuf[:])
	return dst
}
