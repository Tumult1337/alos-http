//go:build linux && amd64

package core

import "crypto"

func parseSchemeList(data []byte) ([]uint16, bool) {
	if len(data) < 2 {
		return nil, false
	}
	n := int(data[0])<<8 | int(data[1])
	if n%2 != 0 || 2+n > len(data) {
		return nil, false
	}
	schemes := make([]uint16, 0, n/2)
	for i := 2; i < 2+n; i += 2 {
		schemes = append(schemes, uint16(data[i])<<8|uint16(data[i+1]))
	}
	return schemes, true
}

func (t *tlsTransport) parseCertificateRequest13(body []byte) error {
	if len(body) < 3 || body[0] != 0 {
		return errTLS
	}
	extLen := int(body[1])<<8 | int(body[2])
	exts := body[3:]
	if extLen != len(exts) {
		return errTLS
	}
	for len(exts) >= 4 {
		etype := uint16(exts[0])<<8 | uint16(exts[1])
		elen := int(exts[2])<<8 | int(exts[3])
		if 4+elen > len(exts) {
			return errTLS
		}
		if etype == tlsExtSignatureSchemes {
			schemes, ok := parseSchemeList(exts[4 : 4+elen])
			if !ok {
				return errTLS
			}
			t.certRequestSchemes = schemes
		}
		exts = exts[4+elen:]
	}
	if len(exts) != 0 || t.certRequestSchemes == nil {
		return errTLS
	}
	t.certRequested = true
	return nil
}

func (t *tlsTransport) parseCertificateRequest12(body []byte) error {
	if len(body) < 1 || 1+int(body[0]) > len(body) {
		return errTLS
	}
	schemes, ok := parseSchemeList(body[1+int(body[0]):])
	if !ok {
		return errTLS
	}
	t.certRequestSchemes = schemes
	t.certRequested = true
	return nil
}

func (t *tlsTransport) requestedClientChain() ([][]byte, crypto.Signer, error) {
	if !t.certRequested {
		return nil, nil, nil
	}
	return t.trust.clientChain()
}

func (t *tlsTransport) clientAuthMessages13() ([]byte, error) {
	if !t.certRequested {
		return nil, nil
	}
	chain, signer, err := t.requestedClientChain()
	if err != nil {
		return nil, err
	}
	msgs := buildCertificate13(chain, nil)
	t.transcript = append(t.transcript, msgs...)
	if len(chain) == 0 {
		return msgs, nil
	}
	scheme, sig, err := signTLS13(signer, clientCertVerifyContent13(t.hashOf(t.transcript)), t.certRequestSchemes)
	if err != nil {
		return nil, err
	}
	cv := BuildCertificateVerify(scheme, sig)
	t.transcript = append(t.transcript, cv...)
	return append(msgs, cv...), nil
}

func (t *tlsTransport) writeClientCertificate12(c *backendConn, chain [][]byte) {
	msg := buildTLS12Certificate(chain)
	t.transcript = append(t.transcript, msg...)
	writePlaintextHandshake(c, msg)
}

func (t *tlsTransport) writeClientCertificateVerify12(c *backendConn, signer crypto.Signer) error {
	scheme, sig, err := tls12Sign(signer, t.transcript, t.certRequestSchemes)
	if err != nil {
		return err
	}
	msg := BuildCertificateVerify(scheme, sig)
	t.transcript = append(t.transcript, msg...)
	writePlaintextHandshake(c, msg)
	return nil
}

func writePlaintextHandshake(c *backendConn, msg []byte) {
	for len(msg) > 0 {
		chunk := msg[:min(len(msg), tlsMaxRecordPlaintext)]
		msg = msg[len(chunk):]
		c.wbuf.write(tlsPlaintextRecord(tlsRecHandshake, chunk))
	}
}

func (t *tlsTransport) writeHandshake13(c *backendConn, flight []byte) error {
	for len(flight) > 0 {
		chunk := flight[:min(len(flight), tlsMaxRecordPlaintext)]
		flight = flight[len(chunk):]
		rec, err := t.sealRecord(&t.clientHSKey, tlsRecHandshake, chunk)
		if err != nil {
			return err
		}
		c.wbuf.write(rec)
	}
	return nil
}
