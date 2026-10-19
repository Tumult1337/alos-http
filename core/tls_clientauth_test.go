//go:build linux && amd64

package core

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"hash"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type clientCertFixture struct {
	roots    *x509.CertPool
	valid    tls.Certificate
	expired  tls.Certificate
	unknown  tls.Certificate
	wrongKey tls.Certificate
	ed25519  tls.Certificate
	serverEK tls.Certificate
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var testCertSerial atomic.Int64

func nextTestSerial() *big.Int { return big.NewInt(testCertSerial.Add(1)) }

func newTestCA(t testing.TB, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := wallNow()
	tmpl := &x509.Certificate{
		SerialNumber:          nextTestSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key}
}

type leafSpec struct {
	cn        string
	notBefore time.Time
	notAfter  time.Time
	usage     x509.ExtKeyUsage
	key       crypto.Signer
	dnsNames  []string
	ips       []net.IP
	ocspURLs  []string
}

func (ca testCA) issue(t testing.TB, spec leafSpec) tls.Certificate {
	t.Helper()
	key := spec.key
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	tmpl := &x509.Certificate{
		SerialNumber: nextTestSerial(),
		Subject:      pkix.Name{CommonName: spec.cn},
		NotBefore:    spec.notBefore,
		NotAfter:     spec.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{spec.usage},
		DNSNames:     spec.dnsNames,
		IPAddresses:  spec.ips,
		OCSPServer:   spec.ocspURLs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newClientCertFixture(t testing.TB) *clientCertFixture {
	t.Helper()
	ca := newTestCA(t, "alos test client CA")
	other := newTestCA(t, "untrusted CA")
	now := wallNow()
	live := leafSpec{notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), usage: x509.ExtKeyUsageClientAuth}
	f := &clientCertFixture{roots: x509.NewCertPool()}
	f.roots.AddCert(ca.cert)

	spec := live
	spec.cn = "valid-client"
	f.valid = ca.issue(t, spec)

	spec = live
	spec.cn = "expired-client"
	spec.notBefore, spec.notAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	f.expired = ca.issue(t, spec)

	spec = live
	spec.cn = "unknown-client"
	f.unknown = other.issue(t, spec)

	spec = live
	spec.cn = "wrongkey-client"
	wk := ca.issue(t, spec)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.wrongKey = tls.Certificate{Certificate: wk.Certificate, PrivateKey: otherKey}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec = live
	spec.cn = "ed25519-client"
	spec.key = edKey
	f.ed25519 = ca.issue(t, spec)

	spec = live
	spec.cn = "server-eku-client"
	spec.usage = x509.ExtKeyUsageServerAuth
	f.serverEK = ca.issue(t, spec)
	return f
}

func TestClientAuthPolicyCheckChain(t *testing.T) {
	f := newClientCertFixture(t)
	creds := []struct {
		name  string
		chain [][]byte
	}{
		{"none", nil},
		{"valid", f.valid.Certificate},
		{"unknown CA", f.unknown.Certificate},
		{"expired", f.expired.Certificate},
		{"server-only EKU", f.serverEK.Certificate},
		{"garbage DER", [][]byte{{0x30, 0x03, 0x01, 0x01, 0xff}}},
	}
	want := map[ClientAuthType][]tlsAlert{
		RequestClientCert:          {0, 0, 0, 0, 0, alertBadCertificate},
		RequireAnyClientCert:       {alertCertificateRequired, 0, 0, 0, 0, alertBadCertificate},
		VerifyClientCertIfGiven:    {0, 0, alertUnknownCA, alertCertificateExpired, alertBadCertificate, alertBadCertificate},
		RequireAndVerifyClientCert: {alertCertificateRequired, 0, alertUnknownCA, alertCertificateExpired, alertBadCertificate, alertBadCertificate},
	}
	for mode, alerts := range want {
		p := clientAuthPolicy{mode: mode, roots: f.roots}
		for i, c := range creds {
			certs, alert, ok := p.checkChain(c.chain)
			if ok != (alerts[i] == 0) || alert != alerts[i] {
				t.Errorf("mode %d %s: ok=%v alert=%d, want alert %d", mode, c.name, ok, alert, alerts[i])
				continue
			}
			if ok && len(certs) != len(c.chain) {
				t.Errorf("mode %d %s: %d certs for a %d-cert chain", mode, c.name, len(certs), len(c.chain))
			}
		}
	}
}

func TestClientAuthPolicyPredicates(t *testing.T) {
	cases := []struct {
		mode                        ClientAuthType
		requests, requires, verifie bool
		std                         tls.ClientAuthType
	}{
		{NoClientCert, false, false, false, tls.NoClientCert},
		{RequestClientCert, true, false, false, tls.RequestClientCert},
		{RequireAnyClientCert, true, true, false, tls.RequireAnyClientCert},
		{VerifyClientCertIfGiven, true, false, true, tls.VerifyClientCertIfGiven},
		{RequireAndVerifyClientCert, true, true, true, tls.RequireAndVerifyClientCert},
	}
	for _, c := range cases {
		p := clientAuthPolicy{mode: c.mode}
		if p.requests() != c.requests || p.requires() != c.requires || p.verifies() != c.verifie || c.mode.tlsClientAuth() != c.std {
			t.Errorf("mode %d predicates wrong", c.mode)
		}
	}
}

func TestClientAuthForPerHostOverride(t *testing.T) {
	roots := x509.NewCertPool()
	require := RequireAndVerifyClientCert
	srv := &Server{config: Config{TLSClientAuth: RequestClientCert}}
	srv.clientAuthByHost = clientAuthOverrides([]CertConfig{
		{Domain: "plain.test"},
		{Domain: "MTLS.test.", ClientAuth: &require},
		{Domain: "roots.test", ClientCAs: roots},
	})
	if len(srv.clientAuthByHost) != 2 {
		t.Fatalf("%d overrides, want 2", len(srv.clientAuthByHost))
	}
	if p := srv.clientAuthFor(&CertEntry{Domain: "mtls.test"}); p.mode != RequireAndVerifyClientCert || p.roots != nil {
		t.Fatalf("mtls.test policy %+v", p)
	}
	if p := srv.clientAuthFor(&CertEntry{Domain: "roots.test"}); p.mode != RequestClientCert || p.roots != roots {
		t.Fatalf("roots.test policy %+v", p)
	}
	if p := srv.clientAuthFor(&CertEntry{Domain: "plain.test"}); p.mode != RequestClientCert {
		t.Fatalf("plain.test policy %+v", p)
	}
	if p := srv.clientAuthFor(nil); p.mode != RequestClientCert {
		t.Fatalf("nil entry policy %+v", p)
	}
}

func TestCertChainCodec(t *testing.T) {
	chain := [][]byte{bytes.Repeat([]byte{1}, 300), {2}, bytes.Repeat([]byte{3}, 70000)}
	got, ok := decodeCertChain(encodeCertChain(chain))
	if !ok || len(got) != len(chain) {
		t.Fatalf("round trip ok=%v len=%d", ok, len(got))
	}
	for i := range chain {
		if !bytes.Equal(got[i], chain[i]) {
			t.Fatalf("cert %d differs", i)
		}
	}
	if got, ok := decodeCertChain(nil); !ok || got != nil {
		t.Fatal("empty identity must decode to no chain")
	}
	tooLong := make([][]byte, maxClientCertChainLen+1)
	for i := range tooLong {
		tooLong[i] = []byte{byte(i)}
	}
	for name, b := range map[string][]byte{
		"truncated length": {0, 0},
		"zero-length cert": {0, 0, 0},
		"overrun":          {0, 0, 5, 1, 2},
		"too many certs":   encodeCertChain(tooLong),
	} {
		if _, ok := decodeCertChain(b); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestResumedIdentity(t *testing.T) {
	f := newClientCertFixture(t)
	valid := encodeCertChain(f.valid.Certificate)
	cases := []struct {
		name   string
		mode   ClientAuthType
		stored []byte
		ok     bool
		certs  int
	}{
		{"anonymous ticket, no client auth", NoClientCert, nil, true, 0},
		{"anonymous ticket, optional cert", VerifyClientCertIfGiven, nil, true, 0},
		{"anonymous ticket, cert now required", RequireAndVerifyClientCert, nil, false, 0},
		{"cert ticket, client auth now off", NoClientCert, valid, false, 0},
		{"cert ticket, still trusted", RequireAndVerifyClientCert, valid, true, 1},
		{"cert ticket, request only", RequestClientCert, valid, true, 1},
		{"expired cert ticket", RequireAnyClientCert, encodeCertChain(f.expired.Certificate), false, 0},
		{"cert no longer trusted", RequireAndVerifyClientCert, encodeCertChain(f.unknown.Certificate), false, 0},
		{"corrupt identity", RequestClientCert, []byte{0, 0, 9, 1}, false, 0},
	}
	for _, c := range cases {
		certs, chain, ok := clientAuthPolicy{mode: c.mode, roots: f.roots}.resumedIdentity(c.stored)
		if ok != c.ok || len(certs) != c.certs || len(chain) != c.certs {
			t.Errorf("%s: ok=%v certs=%d chain=%d, want ok=%v certs=%d", c.name, ok, len(certs), len(chain), c.ok, c.certs)
		}
	}
}

func certificate13Body(chain [][]byte, context byte, ext []byte) []byte {
	var list []byte
	for _, der := range chain {
		list = append(list, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
		list = append(list, der...)
		list = append(list, byte(len(ext)>>8), byte(len(ext)))
		list = append(list, ext...)
	}
	body := []byte{context}
	if context != 0 {
		body = append(body, 7)
	}
	body = append(body, byte(len(list)>>16), byte(len(list)>>8), byte(len(list)))
	return append(body, list...)
}

func TestParseClientCertificate(t *testing.T) {
	der := []byte{1, 2, 3}
	chain, alert, ok := parseClientCertificate(certificate13Body([][]byte{der, der}, 0, []byte{0, 5, 0, 0}), true)
	if !ok || alert != 0 || len(chain) != 2 || !bytes.Equal(chain[0], der) {
		t.Fatalf("TLS 1.3 two-cert parse: ok=%v alert=%d chain=%d", ok, alert, len(chain))
	}
	chain, _, ok = parseClientCertificate(certificate13Body(nil, 0, nil), true)
	if !ok || len(chain) != 0 {
		t.Fatal("TLS 1.3 empty Certificate rejected")
	}
	tls12Body := encodeCertChain([][]byte{der})
	tls12Body = append([]byte{0, 0, byte(len(tls12Body))}, tls12Body...)
	chain, _, ok = parseClientCertificate(tls12Body, false)
	if !ok || len(chain) != 1 {
		t.Fatal("TLS 1.2 Certificate rejected")
	}
	src := certificate13Body([][]byte{der}, 0, nil)
	chain, _, _ = parseClientCertificate(src, true)
	src[len(src)-3] = 0xee
	if chain[0][2] == 0xee {
		t.Fatal("parsed chain aliases the input buffer")
	}

	tooMany := make([][]byte, maxClientCertChainLen+1)
	for i := range tooMany {
		tooMany[i] = der
	}
	bad := map[string]struct {
		body  []byte
		tls13 bool
		alert tlsAlert
	}{
		"non-empty request context": {certificate13Body([][]byte{der}, 1, nil), true, alertIllegalParameter},
		"missing context":           {nil, true, alertIllegalParameter},
		"list length mismatch":      {[]byte{0, 0, 0, 9}, true, alertDecodeError},
		"zero-length cert":          {certificate13Body([][]byte{{}}, 0, nil), true, alertDecodeError},
		"truncated extensions":      {[]byte{0, 0, 0, 5, 0, 0, 1, 9, 0}, true, alertDecodeError},
		"extension overrun":         {[]byte{0, 0, 0, 6, 0, 0, 1, 9, 0, 4}, true, alertDecodeError},
		"too many certs":            {certificate13Body(tooMany, 0, nil), true, alertDecodeError},
		"TLS 1.2 short":             {[]byte{0, 0}, false, alertDecodeError},
	}
	for name, c := range bad {
		if _, alert, ok := parseClientCertificate(c.body, c.tls13); ok || alert != c.alert {
			t.Errorf("%s: ok=%v alert=%d, want alert %d", name, ok, alert, c.alert)
		}
	}
}

func TestParseCertificateVerify(t *testing.T) {
	body := []byte{0x04, 0x03, 0, 2, 0xaa, 0xbb}
	scheme, sig, _, ok := parseCertificateVerify(body, clientCertSchemes13)
	if !ok || scheme != 0x0403 || !bytes.Equal(sig, []byte{0xaa, 0xbb}) {
		t.Fatal("well-formed CertificateVerify rejected")
	}
	if _, _, alert, ok := parseCertificateVerify([]byte{0x02, 0x01, 0, 1, 0}, clientCertSchemes13); ok || alert != alertIllegalParameter {
		t.Fatalf("SHA-1 scheme: ok=%v alert=%d", ok, alert)
	}
	if _, _, alert, ok := parseCertificateVerify([]byte{0x08, 0x07, 0, 1, 0}, clientCertSchemes12); ok || alert != alertIllegalParameter {
		t.Fatalf("Ed25519 on TLS 1.2: ok=%v alert=%d", ok, alert)
	}
	for _, b := range [][]byte{nil, {4, 3, 0}, {4, 3, 0, 3, 1}} {
		if _, _, alert, ok := parseCertificateVerify(b, clientCertSchemes13); ok || alert != alertDecodeError {
			t.Errorf("%x: ok=%v alert=%d", b, ok, alert)
		}
	}
}

func TestCertificateRequestMessages(t *testing.T) {
	cr := certificateRequest13
	if cr[0] != tlsHSCertificateRequest || readU24(cr[1:]) != len(cr)-4 || cr[4] != 0 {
		t.Fatalf("CertificateRequest13 header %x", cr[:5])
	}
	extsLen := int(cr[5])<<8 | int(cr[6])
	if 7+extsLen != len(cr) || uint16(cr[7])<<8|uint16(cr[8]) != tlsExtSignatureSchemes {
		t.Fatalf("CertificateRequest13 must carry exactly signature_algorithms: %x", cr)
	}
	cr = certificateRequest12
	if cr[0] != tlsHSCertificateRequest || readU24(cr[1:]) != len(cr)-4 {
		t.Fatalf("CertificateRequest12 header %x", cr[:4])
	}
	if cr[4] != 2 || cr[5] != tls12CertTypeECDSASign || cr[6] != tls12CertTypeRSASign {
		t.Fatalf("CertificateRequest12 cert types %x", cr[4:7])
	}
	if cr[len(cr)-2] != 0 || cr[len(cr)-1] != 0 {
		t.Fatal("CertificateRequest12 must send an empty CA list")
	}
}

type clientFlight13 struct {
	cs     *CipherSuiteConfig
	secret []byte
	mirror hash.Hash
}

func newClientFlight13(cs *CipherSuiteConfig, prefix []byte) (*clientFlight13, func(clientAuthPolicy) *tls13ClientAuth) {
	secret := bytes.Repeat([]byte{0x42}, cs.HashLen)
	mirror := cs.HashFn()
	mirror.Write(prefix)
	f := &clientFlight13{cs: cs, secret: secret, mirror: mirror}
	mk := func(p clientAuthPolicy) *tls13ClientAuth {
		tr := cs.HashFn()
		tr.Write(prefix)
		return newTLS13ClientAuth(p, cs, tr, secret)
	}
	return f, mk
}

func (f *clientFlight13) certificate(chain [][]byte) []byte {
	msg := BuildCertificate(chain)
	f.mirror.Write(msg)
	return msg
}

func (f *clientFlight13) certVerify(t testing.TB, key crypto.Signer) []byte {
	t.Helper()
	signed := clientCertVerifyContent13(f.mirror.Sum(nil))
	var scheme uint16
	var sig []byte
	var err error
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(signed)
		scheme = 0x0403
		sig, err = ecdsa.SignASN1(rand.Reader, k, digest[:])
	case ed25519.PrivateKey:
		scheme = 0x0807
		sig = ed25519.Sign(k, signed)
	}
	if err != nil {
		t.Fatal(err)
	}
	msg := BuildCertificateVerify(scheme, sig)
	f.mirror.Write(msg)
	return msg
}

func (f *clientFlight13) finished() []byte {
	msg := BuildFinished(f.cs.ComputeFinishedTo(f.secret, f.mirror.Sum(nil), nil))
	f.mirror.Write(msg)
	return msg
}

func TestTLS13ClientAuthFlight(t *testing.T) {
	fx := newClientCertFixture(t)
	cs := tls13SuiteByID(0x1301)
	prefix := []byte("ClientHello..server Finished")
	verify := clientAuthPolicy{mode: RequireAndVerifyClientCert, roots: fx.roots}
	optional := clientAuthPolicy{mode: VerifyClientCertIfGiven, roots: fx.roots}

	t.Run("valid ECDSA cert byte by byte", func(t *testing.T) {
		f, mk := newClientFlight13(cs, prefix)
		a := mk(verify)
		flight := append(f.certificate(fx.valid.Certificate), f.certVerify(t, fx.valid.PrivateKey.(crypto.Signer))...)
		flight = append(flight, f.finished()...)
		for i, b := range flight {
			done, alert, ok := a.feed([]byte{b})
			if !ok {
				t.Fatalf("byte %d: alert %d", i, alert)
			}
			if done != (i == len(flight)-1) {
				t.Fatalf("byte %d: done=%v", i, done)
			}
		}
		if len(a.peerCerts) != 1 || a.peerCerts[0].Subject.CommonName != "valid-client" {
			t.Fatalf("peer certs %v", a.peerCerts)
		}
	})

	t.Run("Ed25519 cert", func(t *testing.T) {
		f, mk := newClientFlight13(cs, prefix)
		a := mk(verify)
		flight := append(f.certificate(fx.ed25519.Certificate), f.certVerify(t, fx.ed25519.PrivateKey.(crypto.Signer))...)
		if done, alert, ok := a.feed(append(flight, f.finished()...)); !done || !ok {
			t.Fatalf("done=%v alert=%d", done, alert)
		}
	})

	t.Run("empty Certificate skips CertificateVerify", func(t *testing.T) {
		f, mk := newClientFlight13(cs, prefix)
		a := mk(optional)
		flight := append(f.certificate(nil), f.finished()...)
		if done, alert, ok := a.feed(flight); !done || !ok || a.peerCerts != nil {
			t.Fatalf("done=%v alert=%d certs=%v", done, alert, a.peerCerts)
		}
	})

	failures := []struct {
		name   string
		policy clientAuthPolicy
		flight func(t *testing.T, f *clientFlight13) []byte
		alert  tlsAlert
	}{
		{"empty Certificate when required", verify, func(t *testing.T, f *clientFlight13) []byte {
			return f.certificate(nil)
		}, alertCertificateRequired},
		{"wrong key", verify, func(t *testing.T, f *clientFlight13) []byte {
			return append(f.certificate(fx.wrongKey.Certificate), f.certVerify(t, fx.wrongKey.PrivateKey.(crypto.Signer))...)
		}, alertDecryptError},
		{"Finished before CertificateVerify", verify, func(t *testing.T, f *clientFlight13) []byte {
			return append(f.certificate(fx.valid.Certificate), f.finished()...)
		}, alertUnexpectedMessage},
		{"Finished without Certificate", optional, func(t *testing.T, f *clientFlight13) []byte {
			return f.finished()
		}, alertUnexpectedMessage},
		{"CertificateVerify after an empty Certificate", optional, func(t *testing.T, f *clientFlight13) []byte {
			return append(f.certificate(nil), f.certVerify(t, fx.valid.PrivateKey.(crypto.Signer))...)
		}, alertUnexpectedMessage},
		{"bad Finished", verify, func(t *testing.T, f *clientFlight13) []byte {
			flight := append(f.certificate(fx.valid.Certificate), f.certVerify(t, fx.valid.PrivateKey.(crypto.Signer))...)
			fin := f.finished()
			fin[len(fin)-1] ^= 1
			return append(flight, fin...)
		}, alertDecryptError},
		{"data after Finished", optional, func(t *testing.T, f *clientFlight13) []byte {
			return append(append(f.certificate(nil), f.finished()...), 0x14)
		}, alertUnexpectedMessage},
		{"oversized message header", optional, func(t *testing.T, f *clientFlight13) []byte {
			return []byte{tlsHSCertificate, 0x01, 0x00, 0x01}
		}, alertDecodeError},
	}
	for _, c := range failures {
		t.Run(c.name, func(t *testing.T) {
			f, mk := newClientFlight13(cs, prefix)
			a := mk(c.policy)
			done, alert, ok := a.feed(c.flight(t, f))
			if ok || done || alert != c.alert {
				t.Fatalf("done=%v ok=%v alert=%d, want alert %d", done, ok, alert, c.alert)
			}
		})
	}
}

func TestTLS13ClientAuthPendingTicketCarriesIdentity(t *testing.T) {
	fx := newClientCertFixture(t)
	cs := tls13SuiteByID(0x1301)
	f, mk := newClientFlight13(cs, nil)
	a := mk(clientAuthPolicy{mode: RequireAndVerifyClientCert, roots: fx.roots})
	if a.pendingTicket("h2") != nil {
		t.Fatal("ticket issued without a held master secret")
	}
	a.holdTicketMaster(bytes.Repeat([]byte{7}, cs.HashLen), "mtls.test")
	flight := append(f.certificate(fx.valid.Certificate), f.certVerify(t, fx.valid.PrivateKey.(crypto.Signer))...)
	if done, _, ok := a.feed(append(flight, f.finished()...)); !done || !ok {
		t.Fatal("flight rejected")
	}
	p := a.pendingTicket("h2")
	if p == nil || p.sni != "mtls.test" || p.alpn != "h2" {
		t.Fatalf("pending ticket %+v", p)
	}
	chain, ok := decodeCertChain(p.clientCert)
	if !ok || len(chain) != 1 || !bytes.Equal(chain[0], fx.valid.Certificate[0]) {
		t.Fatal("ticket does not carry the client certificate")
	}
	if a.ticketMasterLen != 0 || a.ticketMaster != [64]byte{} {
		t.Fatal("master secret not wiped after issuing the ticket")
	}
	if a.pendingTicket("h2") != nil {
		t.Fatal("second ticket issued from a wiped master secret")
	}
}

func TestVerifyTLS12ClientSignature(t *testing.T) {
	fx := newClientCertFixture(t)
	digest := sha256.Sum256([]byte("handshake messages"))
	key := fx.valid.PrivateKey.(*ecdsa.PrivateKey)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !verifyTLS12ClientSignature(&key.PublicKey, 0x0403, digest[:], sig) {
		t.Fatal("valid ECDSA signature rejected")
	}
	other := fx.wrongKey.PrivateKey.(*ecdsa.PrivateKey)
	for name, ok := range map[string]bool{
		"other key":      verifyTLS12ClientSignature(&other.PublicKey, 0x0403, digest[:], sig),
		"RSA scheme":     verifyTLS12ClientSignature(&key.PublicKey, 0x0401, digest[:], sig),
		"PSS scheme":     verifyTLS12ClientSignature(&key.PublicKey, 0x0804, digest[:], sig),
		"unknown scheme": verifyTLS12ClientSignature(&key.PublicKey, 0x0807, digest[:], sig),
	} {
		if ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzParseClientCertificate(f *testing.F) {
	f.Add(certificate13Body([][]byte{{1, 2, 3}}, 0, []byte{0, 5, 0, 0}), true)
	f.Add(certificate13Body(nil, 0, nil), true)
	f.Add([]byte{0, 0, 4, 0, 0, 1, 9}, false)
	f.Fuzz(func(t *testing.T, body []byte, tls13 bool) {
		chain, alert, ok := parseClientCertificate(body, tls13)
		if ok != (alert == 0) || len(chain) > maxClientCertChainLen {
			t.Fatalf("ok=%v alert=%d chain=%d", ok, alert, len(chain))
		}
		for _, der := range chain {
			if len(der) == 0 {
				t.Fatal("empty certificate accepted")
			}
		}
	})
}

func FuzzTLS13ClientAuthFeed(f *testing.F) {
	cs := tls13SuiteByID(0x1301)
	fl, _ := newClientFlight13(cs, nil)
	f.Add(append(fl.certificate(nil), fl.finished()...), uint8(3))
	f.Add([]byte{tlsHSCertificate, 0, 0, 4, 0, 0, 0, 0}, uint8(1))
	f.Fuzz(func(t *testing.T, flight []byte, step uint8) {
		_, mk := newClientFlight13(cs, nil)
		a := mk(clientAuthPolicy{mode: RequestClientCert})
		n := int(step%16) + 1
		for len(flight) > 0 {
			chunk := flight[:min(n, len(flight))]
			flight = flight[len(chunk):]
			done, alert, ok := a.feed(chunk)
			if ok != (alert == 0) {
				t.Fatalf("ok=%v alert=%d", ok, alert)
			}
			if !ok || done {
				return
			}
		}
	})
}
