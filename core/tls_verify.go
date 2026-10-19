//go:build linux && amd64

package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

var errTLS = errors.New("outbound: tls handshake failed")

const (
	tlsRecHandshake       = 22
	tlsRecAppData         = 23
	tlsRecAlert           = 21
	tlsRecChangeCipher    = 20
	tlsHSClientHello      = 1
	tlsHSServerHello      = 2
	tlsHSEncryptedExts    = 8
	tlsHSCertificate      = 11
	tlsHSCertVerify       = 15
	tlsHSFinished         = 20
	suiteAES128GCMSHA256  = 0x1301
	suiteAES256GCMSHA384  = 0x1302
	tlsGroupX25519        = 0x001d
	tlsMaxRecordPlaintext = 16384
)

func verifyHandshakeSignature(pub any, scheme uint16, signed, sig []byte) error {
	switch scheme {
	case 0x0804, 0x0805, 0x0806:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errTLS
		}
		h, id := signatureHash(scheme)
		h.Write(signed)
		return rsa.VerifyPSS(key, id, h.Sum(nil), sig,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: id})
	case 0x0403, 0x0503, 0x0603:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errTLS
		}
		h, _ := signatureHash(scheme)
		h.Write(signed)
		if !ecdsa.VerifyASN1(key, h.Sum(nil), sig) {
			return errTLS
		}
		return nil
	case 0x0807:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errTLS
		}
		if !ed25519.Verify(key, signed, sig) {
			return errTLS
		}
		return nil
	default:
		return errTLS
	}
}

func signatureHash(scheme uint16) (hash.Hash, crypto.Hash) {
	switch scheme {
	case 0x0805, 0x0503, 0x0501:
		return sha512.New384(), crypto.SHA384
	case 0x0806, 0x0603, 0x0601:
		return sha512.New(), crypto.SHA512
	default:
		return sha256.New(), crypto.SHA256
	}
}

func verifyTLS12Signature(pub any, scheme uint16, signed, sig []byte) error {
	switch scheme {
	case 0x0401, 0x0501, 0x0601:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errTLS
		}
		h, id := signatureHash(scheme)
		h.Write(signed)
		return rsa.VerifyPKCS1v15(key, id, h.Sum(nil), sig)
	}
	return verifyHandshakeSignature(pub, scheme, signed, sig)
}
