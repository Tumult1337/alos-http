//go:build linux && amd64

package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
)

const (
	suite12RSAAES128  = 0xc02f
	suite12ECDSAES128 = 0xc02b
	suite12RSAAES256  = 0xc030
	suite12ECDSAES256 = 0xc02c
)

const (
	tlsHSServerKeyExchange = 12
	tlsHSServerHelloDone   = 14
)

const (
	hs12AwaitCertificate uint8 = iota
	hs12AwaitKeyExchange
	hs12AwaitHelloDone
	hs12AwaitHelloDoneAfterRequest
	hs12FlightDone
)

var tls12ServerFlight = []hsTransition{
	{hs12AwaitCertificate, tlsHSCertificate, hs12AwaitKeyExchange},
	{hs12AwaitKeyExchange, tlsHSServerKeyExchange, hs12AwaitHelloDone},
	{hs12AwaitHelloDone, tlsHSCertificateRequest, hs12AwaitHelloDoneAfterRequest},
	{hs12AwaitHelloDone, tlsHSServerHelloDone, hs12FlightDone},
	{hs12AwaitHelloDoneAfterRequest, tlsHSServerHelloDone, hs12FlightDone},
}

type aead12 struct {
	aead     cipher.AEAD
	iv       [4]byte
	seq      uint64
	nonceBuf [tls12NonceLen]byte
	aadBuf   [tls12AADLen]byte
}

func (t *tlsTransport) begin12() error {
	switch t.suite {
	case suite12RSAAES128, suite12ECDSAES128, suite12RSAAES256, suite12ECDSAES256:
	default:
		return errTLS
	}
	if suiteUsesAES256(t.suite) {
		t.hashFn = sha512.New384
		t.hashLen = 48
	} else {
		t.hashFn = sha256.New
		t.hashLen = 32
	}
	t.version = 0x0303
	t.state = tls12ExpectHandshake
	return nil
}

func (t *tlsTransport) feed12Record(c *backendConn, ctype byte, body []byte) error {
	switch ctype {
	case tlsRecChangeCipher:
		if t.state != tls12ExpectFinished || t.serverCipherActive {
			return errTLS
		}
		t.serverCipherActive = true
		return nil
	case tlsRecHandshake:
		if t.serverCipherActive {
			plain, err := t.open12(&t.server12, tlsRecHandshake, body)
			if err != nil {
				return err
			}
			return t.handle12Finished(c, plain)
		}
		if t.state != tls12ExpectHandshake {
			return errTLS
		}
		return t.handle12Handshake(c, body)
	case tlsRecAppData:
		if t.state != tlsDone {
			return errTLS
		}
		plain, err := t.open12(&t.server12, tlsRecAppData, body)
		if err != nil {
			return err
		}
		return c.proto.onData(c, plain)
	case tlsRecAlert:
		return errFPConnClosed
	}
	return nil
}

func (t *tlsTransport) handle12Handshake(c *backendConn, data []byte) error {
	t.inHS = append(t.inHS, data...)
	for {
		if len(t.inHS) < 4 {
			return nil
		}
		mlen := int(t.inHS[1])<<16 | int(t.inHS[2])<<8 | int(t.inHS[3])
		if len(t.inHS) < 4+mlen {
			return nil
		}
		msg := t.inHS[:4+mlen]
		mtype := msg[0]
		if err := t.stepHandshake(tls12ServerFlight, mtype); err != nil {
			return err
		}
		t.transcript = append(t.transcript, msg...)
		switch mtype {
		case tlsHSCertificate:
			if err := t.parseCertificate(msg[4:]); err != nil {
				return err
			}
		case tlsHSCertificateRequest:
			if err := t.parseCertificateRequest12(msg[4:]); err != nil {
				return err
			}
		case tlsHSServerKeyExchange:
			if err := t.parseServerKeyExchange(msg[4:]); err != nil {
				return err
			}
		case tlsHSServerHelloDone:
			if err := t.send12ClientFlight(c); err != nil {
				return err
			}
		}
		t.inHS = t.inHS[4+mlen:]
	}
}

func (t *tlsTransport) parseServerKeyExchange(body []byte) error {
	if len(body) < 4 {
		return errTLS
	}
	if body[0] != 3 {
		return errTLS
	}
	group := uint16(body[1])<<8 | uint16(body[2])
	if group != tlsGroupX25519 {
		return errTLS
	}
	pubLen := int(body[3])
	if 4+pubLen > len(body) {
		return errTLS
	}
	t.serverPub12 = make([]byte, pubLen)
	copy(t.serverPub12, body[4:4+pubLen])
	paramsEnd := 4 + pubLen

	if t.skipVerify {
		return nil
	}
	if len(body) < paramsEnd+4 {
		return errTLS
	}
	sigScheme := uint16(body[paramsEnd])<<8 | uint16(body[paramsEnd+1])
	sigLen := int(body[paramsEnd+2])<<8 | int(body[paramsEnd+3])
	sigStart := paramsEnd + 4
	if sigStart+sigLen > len(body) {
		return errTLS
	}
	sig := body[sigStart : sigStart+sigLen]
	signed := make([]byte, 0, 64+paramsEnd)
	signed = append(signed, t.clientRandom[:]...)
	signed = append(signed, t.serverRandom[:]...)
	signed = append(signed, body[:paramsEnd]...)
	return t.verifySKESignature(sigScheme, signed, sig)
}

func (t *tlsTransport) verifySKESignature(scheme uint16, signed, sig []byte) error {
	if len(t.certs) == 0 {
		return errTLS
	}
	leaf, err := x509.ParseCertificate(t.certs[0])
	if err != nil {
		return err
	}
	return verifyTLS12Signature(leaf.PublicKey, scheme, signed, sig)
}

func (t *tlsTransport) send12ClientFlight(c *backendConn) error {
	if !t.skipVerify {
		if err := t.verifyCerts(); err != nil {
			return err
		}
	}
	chain, signer, err := t.requestedClientChain()
	if err != nil {
		return err
	}
	peerPub, err := ecdh.X25519().NewPublicKey(t.serverPub12)
	if err != nil {
		return err
	}
	shared, err := t.priv.ECDH(peerPub)
	if err != nil {
		return err
	}

	crsr := make([]byte, 0, 64)
	crsr = append(crsr, t.clientRandom[:]...)
	crsr = append(crsr, t.serverRandom[:]...)
	master := t.prf(shared, "master secret", crsr, 48)
	t.master12 = master

	srcr := make([]byte, 0, 64)
	srcr = append(srcr, t.serverRandom[:]...)
	srcr = append(srcr, t.clientRandom[:]...)
	keyLen := t.keyLen()
	kb := t.prf(master, "key expansion", srcr, 2*keyLen+8)
	cwk := kb[:keyLen]
	swk := kb[keyLen : 2*keyLen]
	civ := kb[2*keyLen : 2*keyLen+4]
	siv := kb[2*keyLen+4 : 2*keyLen+8]
	t.client12 = makeAEAD12(cwk, civ)
	t.server12 = makeAEAD12(swk, siv)

	if t.certRequested {
		t.writeClientCertificate12(c, chain)
	}
	pub := t.priv.PublicKey().Bytes()
	cke := make([]byte, 0, 5+len(pub))
	cke = append(cke, 16, 0, 0, byte(len(pub)+1), byte(len(pub)))
	cke = append(cke, pub...)
	t.transcript = append(t.transcript, cke...)
	c.wbuf.write(tlsPlaintextRecord(tlsRecHandshake, cke))
	if len(chain) > 0 {
		if err := t.writeClientCertificateVerify12(c, signer); err != nil {
			return err
		}
	}

	verifyData := t.prf(master, "client finished", t.hashOf(t.transcript), 12)
	fin := make([]byte, 4+12)
	fin[0] = tlsHSFinished
	fin[3] = 12
	copy(fin[4:], verifyData)
	t.transcript = append(t.transcript, fin...)

	c.wbuf.write(tlsPlaintextRecord(tlsRecChangeCipher, []byte{0x01}))
	c.wbuf.write(t.seal12(&t.client12, tlsRecHandshake, fin))
	t.state = tls12ExpectFinished
	return nil
}

func (t *tlsTransport) handle12Finished(c *backendConn, plain []byte) error {
	const verifyDataLen = 12
	if len(plain) != 4+verifyDataLen || plain[0] != tlsHSFinished ||
		plain[1] != 0 || plain[2] != 0 || plain[3] != verifyDataLen {
		return errTLS
	}
	expected := t.prf(t.master12, "server finished", t.hashOf(t.transcript), verifyDataLen)
	if !hmac.Equal(plain[4:4+verifyDataLen], expected) {
		return errTLS
	}
	t.negALPN = "http/1.1"
	if t.alpnNegotiatedH2 {
		t.negALPN = "h2"
	}
	t.state = tlsDone
	c.be.onTransportReady(c)
	return nil
}

func (t *tlsTransport) prf(secret []byte, label string, seed []byte, length int) []byte {
	labelSeed := make([]byte, 0, len(label)+len(seed))
	labelSeed = append(labelSeed, label...)
	labelSeed = append(labelSeed, seed...)
	out := make([]byte, 0, length)
	a := labelSeed
	for len(out) < length {
		am := hmac.New(t.hashFn, secret)
		am.Write(a)
		a = am.Sum(nil)
		pm := hmac.New(t.hashFn, secret)
		pm.Write(a)
		pm.Write(labelSeed)
		out = append(out, pm.Sum(nil)...)
	}
	return out[:length]
}

func makeAEAD12(key, iv []byte) aead12 {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	var k aead12
	k.aead = gcm
	copy(k.iv[:], iv)
	return k
}

func (k *aead12) putAAD(contentType byte, plainLen int) []byte {
	aad := &k.aadBuf
	s := k.seq
	for i := 0; i < 8; i++ {
		aad[7-i] = byte(s)
		s >>= 8
	}
	aad[8] = contentType
	aad[9] = 0x03
	aad[10] = 0x03
	aad[11] = byte(plainLen >> 8)
	aad[12] = byte(plainLen)
	return aad[:]
}

func (t *tlsTransport) seal12(k *aead12, contentType byte, plain []byte) []byte {
	return t.seal12To(nil, k, contentType, plain)
}

func (t *tlsTransport) seal12To(dst []byte, k *aead12, contentType byte, plain []byte) []byte {
	nonce := &k.nonceBuf
	copy(nonce[:4], k.iv[:])
	seq := k.seq
	for i := 0; i < 8; i++ {
		nonce[11-i] = byte(seq)
		seq >>= 8
	}
	aad := k.putAAD(contentType, len(plain))
	total := tls12ExplicitNonceLen + len(plain) + k.aead.Overhead()
	dst = growSlice(dst, tls12RecordHeaderLen+total)
	dst = append(dst, contentType, 0x03, 0x03, byte(total>>8), byte(total))
	dst = append(dst, nonce[4:]...)
	dst = k.aead.Seal(dst, nonce[:], plain, aad)
	k.seq++
	return dst
}

func (t *tlsTransport) open12(k *aead12, contentType byte, body []byte) ([]byte, error) {
	if len(body) < 8+16 || k.aead == nil {
		return nil, errTLS
	}
	nonce := &k.nonceBuf
	copy(nonce[:4], k.iv[:])
	copy(nonce[4:], body[:8])
	ct := body[8:]
	plainLen := len(ct) - 16
	aad := k.putAAD(contentType, plainLen)
	out, err := k.aead.Open(nil, nonce[:], ct, aad)
	if err != nil {
		return nil, err
	}
	k.seq++
	return out, nil
}
