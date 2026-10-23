//go:build linux && amd64

package core

import "testing"

func fpG2CertList(entries ...[]byte) []byte {
	var list []byte
	for _, e := range entries {
		list = append(list, byte(len(e)>>16), byte(len(e)>>8), byte(len(e)))
		list = append(list, e...)
	}
	return append([]byte{byte(len(list) >> 16), byte(len(list) >> 8), byte(len(list))}, list...)
}

func TestFPTLS12CertificateRejectsMalformedChain(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"zero-length entry", fpG2CertList([]byte{0x30}, nil)},
		{"only zero-length entries", fpG2CertList(nil, nil, nil)},
		{"empty list", fpG2CertList()},
		{"list length past body", append([]byte{0, 0, 9}, 0, 0, 1, 0x30)},
		{"trailing bytes after list", append(fpG2CertList([]byte{0x30}), 0xff)},
		{"entry past list", []byte{0, 0, 4, 0, 0, 5, 0x30}},
		{"truncated entry length", []byte{0, 0, 2, 0, 0}},
	} {
		tr := &tlsTransport{skipVerify: true, version: 0x0303, state: tls12ExpectHandshake}
		if err := tr.handle12Handshake(nil, fpFixHandshakeMsg(tlsHSCertificate, tc.body)); err == nil {
			t.Errorf("%s: accepted, %d entries stored", tc.name, len(tr.certs))
		}
	}
	tr := &tlsTransport{skipVerify: true, version: 0x0303, state: tls12ExpectHandshake}
	if err := tr.handle12Handshake(nil, fpFixHandshakeMsg(tlsHSCertificate, fpG2CertList([]byte{0x30, 0x01}, []byte{0x30}))); err != nil {
		t.Fatalf("a well-formed chain was rejected: %v", err)
	}
	if len(tr.certs) != 2 || string(tr.certs[0]) != "\x30\x01" || string(tr.certs[1]) != "\x30" {
		t.Fatalf("stored chain = %q", tr.certs)
	}
}

func TestFPTLS13CertificateRejectsMalformedChain(t *testing.T) {
	entry13 := func(der, ext []byte) []byte {
		out := append([]byte(nil), der...)
		out = append(out, byte(len(ext)>>8), byte(len(ext)))
		return append(out, ext...)
	}
	wrap := func(list []byte) []byte { return append([]byte{0}, list...) }
	rawList := func(entries ...[]byte) []byte {
		var list []byte
		for _, e := range entries {
			list = append(list, e...)
		}
		return append([]byte{byte(len(list) >> 16), byte(len(list) >> 8), byte(len(list))}, list...)
	}
	withLen := func(der []byte, ext []byte) []byte {
		return append([]byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}, entry13(der, ext)...)
	}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"zero-length entry", wrap(rawList(withLen([]byte{0x30}, nil), withLen(nil, nil)))},
		{"empty list", wrap(rawList())},
		{"extensions past list", wrap(rawList([]byte{0, 0, 1, 0x30, 0, 9}))},
		{"missing extensions length", wrap(rawList([]byte{0, 0, 1, 0x30}))},
		{"context past body", []byte{5, 0}},
		{"non-empty request context", append([]byte{1, 7}, rawList(withLen([]byte{0x30}, nil))...)},
	} {
		tr := &tlsTransport{skipVerify: true, version: 0x0304, state: tlsExpectEncrypted}
		if err := tr.handleEncryptedHandshake(nil, append(append([]byte(nil), fpFixEE13...), fpFixHandshakeMsg(tlsHSCertificate, tc.body)...)); err == nil {
			t.Errorf("%s: accepted, %d entries stored", tc.name, len(tr.certs))
		}
	}
	tr := &tlsTransport{skipVerify: true, version: 0x0304, state: tlsExpectEncrypted}
	good := wrap(rawList(withLen([]byte{0x30, 0x01}, []byte{0, 0}), withLen([]byte{0x30}, nil)))
	if err := tr.handleEncryptedHandshake(nil, append(append([]byte(nil), fpFixEE13...), fpFixHandshakeMsg(tlsHSCertificate, good)...)); err != nil {
		t.Fatalf("a well-formed chain was rejected: %v", err)
	}
	if len(tr.certs) != 2 || string(tr.certs[0]) != "\x30\x01" || string(tr.certs[1]) != "\x30" {
		t.Fatalf("stored chain = %q", tr.certs)
	}
}
