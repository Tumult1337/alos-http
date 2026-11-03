//go:build linux && amd64

package core

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"hash"
	"time"

	"github.com/guno1928/turbo"
)

type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

const (
	alertBadCertificate      tlsAlert = 42
	alertCertificateExpired  tlsAlert = 45
	alertUnknownCA           tlsAlert = 48
	alertCertificateRequired tlsAlert = 116

	tlsHSCertificateRequest = 13
	tlsHSClientKeyExchange  = 16
	tlsExtSignatureSchemes  = 0x000d
	tls12CertTypeRSASign    = 1
	tls12CertTypeECDSASign  = 64

	maxHandshakeMessageLen = 64 << 10
	maxClientCertChainLen  = 10
	certLenFieldLen        = 3
)

var (
	clientCertSchemes13 = []uint16{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807}
	clientCertSchemes12 = []uint16{0x0403, 0x0804, 0x0401}
	clientCVContext     = []byte("TLS 1.3, client CertificateVerify")

	certificateRequest13 = buildCertificateRequest13()
	certificateRequest12 = buildCertificateRequest12()
)

func (t ClientAuthType) tlsClientAuth() tls.ClientAuthType {
	switch t {
	case RequestClientCert:
		return tls.RequestClientCert
	case RequireAnyClientCert:
		return tls.RequireAnyClientCert
	case VerifyClientCertIfGiven:
		return tls.VerifyClientCertIfGiven
	case RequireAndVerifyClientCert:
		return tls.RequireAndVerifyClientCert
	}
	return tls.NoClientCert
}

type clientAuthPolicy struct {
	mode  ClientAuthType
	roots *x509.CertPool
}

type clientAuthOverride struct {
	mode  *ClientAuthType
	roots *x509.CertPool
}

func clientAuthOverrides(certs []CertConfig) map[string]clientAuthOverride {
	var m map[string]clientAuthOverride
	for _, cc := range certs {
		if cc.ClientAuth == nil && cc.ClientCAs == nil {
			continue
		}
		if m == nil {
			m = make(map[string]clientAuthOverride)
		}
		m[normalizeCertDomain(cc.Domain)] = clientAuthOverride{mode: cc.ClientAuth, roots: cc.ClientCAs}
	}
	return m
}

func (s *Server) clientAuthFor(entry *CertEntry) clientAuthPolicy {
	p := clientAuthPolicy{mode: s.config.TLSClientAuth, roots: s.config.TLSClientCAs}
	if entry == nil || s.clientAuthByHost == nil {
		return p
	}
	if o, ok := s.clientAuthByHost[normalizeCertDomain(entry.Domain)]; ok {
		if o.mode != nil {
			p.mode = *o.mode
		}
		if o.roots != nil {
			p.roots = o.roots
		}
	}
	return p
}

func (s *Server) misdirectsClientAuth(handshakeEntry *CertEntry, host string) bool {
	return s.clientAuthByHost != nil && handshakeEntry != nil && host != "" && s.hostClientAuthDiffers(handshakeEntry, host)
}

func (s *Server) hostClientAuthDiffers(handshakeEntry *CertEntry, host string) bool {
	hostPolicy := s.clientAuthFor(s.certStore.Lookup(stripPort(host)))
	return hostPolicy.requests() && hostPolicy != s.clientAuthFor(handshakeEntry)
}

func (p clientAuthPolicy) requests() bool { return p.mode != NoClientCert }

func (p clientAuthPolicy) requires() bool {
	return p.mode == RequireAnyClientCert || p.mode == RequireAndVerifyClientCert
}

func (p clientAuthPolicy) verifies() bool {
	return p.mode == VerifyClientCertIfGiven || p.mode == RequireAndVerifyClientCert
}

func wallNow() time.Time { return time.Unix(0, turbo.UnixNano()) }

func (p clientAuthPolicy) checkChain(chain [][]byte) ([]*x509.Certificate, tlsAlert, bool) {
	if len(chain) == 0 {
		if p.requires() {
			return nil, alertCertificateRequired, false
		}
		return nil, 0, true
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, alertBadCertificate, false
		}
		certs[i] = c
	}
	if !p.verifies() {
		return certs, 0, true
	}
	opts := x509.VerifyOptions{
		Roots:         p.roots,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   wallNow(),
	}
	for _, c := range certs[1:] {
		opts.Intermediates.AddCert(c)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return nil, verifyFailureAlert(err), false
	}
	return certs, 0, true
}

func verifyFailureAlert(err error) tlsAlert {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return alertUnknownCA
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return alertCertificateExpired
	}
	return alertBadCertificate
}

func (p clientAuthPolicy) resumedIdentity(stored []byte) ([]*x509.Certificate, [][]byte, bool) {
	chain, ok := decodeCertChain(stored)
	if !ok {
		return nil, nil, false
	}
	if len(chain) == 0 {
		return nil, nil, !p.requires()
	}
	if p.mode == NoClientCert {
		return nil, nil, false
	}
	certs, _, ok := p.checkChain(chain)
	if !ok || wallNow().After(certs[0].NotAfter) {
		return nil, nil, false
	}
	return certs, chain, true
}

func encodeCertChain(chain [][]byte) []byte {
	var out []byte
	for _, der := range chain {
		out = append(out, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
		out = append(out, der...)
	}
	return out
}

func readU24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

func decodeCertChain(b []byte) ([][]byte, bool) {
	var chain [][]byte
	for len(b) > 0 {
		if len(b) < certLenFieldLen || len(chain) == maxClientCertChainLen {
			return nil, false
		}
		n := readU24(b)
		if n == 0 || certLenFieldLen+n > len(b) {
			return nil, false
		}
		chain = append(chain, bytes.Clone(b[certLenFieldLen:certLenFieldLen+n]))
		b = b[certLenFieldLen+n:]
	}
	return chain, true
}

func parseClientCertificate(body []byte, tls13 bool) ([][]byte, tlsAlert, bool) {
	if tls13 {
		if len(body) < 1 || body[0] != 0 {
			return nil, alertIllegalParameter, false
		}
		body = body[1:]
	}
	if len(body) < certLenFieldLen || readU24(body) != len(body)-certLenFieldLen {
		return nil, alertDecodeError, false
	}
	list := body[certLenFieldLen:]
	var chain [][]byte
	for len(list) > 0 {
		if len(list) < certLenFieldLen || len(chain) == maxClientCertChainLen {
			return nil, alertDecodeError, false
		}
		n := readU24(list)
		if n == 0 || certLenFieldLen+n > len(list) {
			return nil, alertDecodeError, false
		}
		chain = append(chain, bytes.Clone(list[certLenFieldLen:certLenFieldLen+n]))
		list = list[certLenFieldLen+n:]
		if tls13 {
			if len(list) < 2 {
				return nil, alertDecodeError, false
			}
			extLen := int(list[0])<<8 | int(list[1])
			if 2+extLen > len(list) {
				return nil, alertDecodeError, false
			}
			list = list[2+extLen:]
		}
	}
	return chain, 0, true
}

func parseCertificateVerify(body []byte, allowed []uint16) (uint16, []byte, tlsAlert, bool) {
	if len(body) < 4 || 4+(int(body[2])<<8|int(body[3])) != len(body) {
		return 0, nil, alertDecodeError, false
	}
	scheme := uint16(body[0])<<8 | uint16(body[1])
	for _, s := range allowed {
		if s == scheme {
			return scheme, body[4:], 0, true
		}
	}
	return 0, nil, alertIllegalParameter, false
}

func clientCertVerifyContent13(transcriptHash []byte) []byte {
	signed := make([]byte, 0, len(cvPrefix)+len(clientCVContext)+1+len(transcriptHash))
	signed = append(signed, cvPrefix[:]...)
	signed = append(signed, clientCVContext...)
	signed = append(signed, 0x00)
	return append(signed, transcriptHash...)
}

func verifyTLS12ClientSignature(pub any, scheme uint16, digest, sig []byte) bool {
	switch scheme {
	case 0x0403:
		key, ok := pub.(*ecdsa.PublicKey)
		return ok && ecdsa.VerifyASN1(key, digest, sig)
	case 0x0401:
		key, ok := pub.(*rsa.PublicKey)
		return ok && rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, sig) == nil
	case 0x0804:
		key, ok := pub.(*rsa.PublicKey)
		return ok && rsa.VerifyPSS(key, crypto.SHA256, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) == nil
	}
	return false
}

func appendSchemeList(dst []byte, schemes []uint16) []byte {
	dst = append(dst, byte(len(schemes)*2>>8), byte(len(schemes)*2))
	for _, s := range schemes {
		dst = append(dst, byte(s>>8), byte(s))
	}
	return dst
}

func buildCertificateRequest13() []byte {
	sigalgs := appendSchemeList(nil, clientCertSchemes13)
	ext := []byte{byte(tlsExtSignatureSchemes >> 8), byte(tlsExtSignatureSchemes & 0xff), byte(len(sigalgs) >> 8), byte(len(sigalgs))}
	ext = append(ext, sigalgs...)
	body := []byte{0x00, byte(len(ext) >> 8), byte(len(ext))}
	return HSWrap(tlsHSCertificateRequest, append(body, ext...))
}

func buildCertificateRequest12() []byte {
	body := []byte{2, tls12CertTypeECDSASign, tls12CertTypeRSASign}
	body = appendSchemeList(body, clientCertSchemes12)
	body = append(body, 0x00, 0x00)
	return tls12Handshake(tlsHSCertificateRequest, body)
}

func nextHandshakeMessage(buf []byte) (msg []byte, complete bool, tooLarge bool) {
	if len(buf) < tlsHandshakeHeaderLen {
		return nil, false, false
	}
	n := readU24(buf[1:])
	if n > maxHandshakeMessageLen {
		return nil, false, true
	}
	if len(buf) < tlsHandshakeHeaderLen+n {
		return nil, false, false
	}
	return buf[:tlsHandshakeHeaderLen+n], true, false
}

type clientAuthStage uint8

const (
	expectClientCertificate clientAuthStage = iota
	expectClientCertVerify
	expectClientFinished
)

type tls13ClientAuth struct {
	policy     clientAuthPolicy
	cs         *CipherSuiteConfig
	transcript hash.Hash
	hsSecret   [64]byte
	hsLen      int
	stage      clientAuthStage
	pending    []byte
	peerCerts  []*x509.Certificate
	peerChain  [][]byte

	ticketMaster    [64]byte
	ticketMasterLen int
	ticketSNI       string
}

func (a *tls13ClientAuth) holdTicketMaster(masterSecret []byte, sni string) {
	a.ticketMasterLen = copy(a.ticketMaster[:], masterSecret)
	a.ticketSNI = sni
}

func (a *tls13ClientAuth) pendingTicket(alpn string) *pendingTicket {
	if a.ticketMasterLen == 0 {
		return nil
	}
	var hashBuf [64]byte
	p := newPendingTicket(a.cs, a.ticketMaster[:a.ticketMasterLen], a.transcript.Sum(hashBuf[:0]), a.ticketSNI, alpn, a.peerChain)
	clear(a.ticketMaster[:])
	a.ticketMasterLen = 0
	return p
}

func newTLS13ClientAuth(policy clientAuthPolicy, cs *CipherSuiteConfig, transcript hash.Hash, clientHSSecret []byte) *tls13ClientAuth {
	a := &tls13ClientAuth{policy: policy, cs: cs, transcript: transcript}
	a.hsLen = copy(a.hsSecret[:], clientHSSecret)
	return a
}

func (a *tls13ClientAuth) feed(plain []byte) (done bool, alert tlsAlert, ok bool) {
	a.pending = append(a.pending, plain...)
	for {
		msg, complete, tooLarge := nextHandshakeMessage(a.pending)
		if tooLarge {
			return false, alertDecodeError, false
		}
		if !complete {
			return false, 0, true
		}
		done, alert, ok := a.handleMessage(msg)
		a.pending = a.pending[len(msg):]
		if !ok || done {
			if done && len(a.pending) != 0 {
				return false, alertUnexpectedMessage, false
			}
			return done, alert, ok
		}
	}
}

func (a *tls13ClientAuth) handleMessage(msg []byte) (done bool, alert tlsAlert, ok bool) {
	body := msg[tlsHandshakeHeaderLen:]
	switch {
	case a.stage == expectClientCertificate && msg[0] == tlsHSCertificate:
		chain, alert, ok := parseClientCertificate(body, true)
		if !ok {
			return false, alert, false
		}
		certs, alert, ok := a.policy.checkChain(chain)
		if !ok {
			return false, alert, false
		}
		a.peerCerts, a.peerChain = certs, chain
		a.transcript.Write(msg)
		a.stage = expectClientFinished
		if len(chain) > 0 {
			a.stage = expectClientCertVerify
		}
		return false, 0, true
	case a.stage == expectClientCertVerify && msg[0] == tlsHSCertVerify:
		scheme, sig, alert, ok := parseCertificateVerify(body, clientCertSchemes13)
		if !ok {
			return false, alert, false
		}
		var hashBuf [64]byte
		signed := clientCertVerifyContent13(a.transcript.Sum(hashBuf[:0]))
		if verifyHandshakeSignature(a.peerCerts[0].PublicKey, scheme, signed, sig) != nil {
			return false, alertDecryptError, false
		}
		a.transcript.Write(msg)
		a.stage = expectClientFinished
		return false, 0, true
	case a.stage == expectClientFinished && msg[0] == tlsHSFinished:
		var hashBuf, finBuf [64]byte
		want := a.cs.ComputeFinishedTo(a.hsSecret[:a.hsLen], a.transcript.Sum(hashBuf[:0]), finBuf[:0])
		if !hmac.Equal(body, want) {
			return false, alertDecryptError, false
		}
		a.transcript.Write(msg)
		clear(a.hsSecret[:])
		return true, 0, true
	}
	return false, alertUnexpectedMessage, false
}

func (st *tls12State) requestClientCert(policy clientAuthPolicy) {
	st.clientAuth = policy
	st.expectCert = true
	st.cvTranscript = sha256.New()
}

func (st *tls12State) record(msg []byte) {
	st.transcript.Write(msg)
	if st.cvTranscript != nil {
		st.cvTranscript.Write(msg)
	}
}

func (st *tls12State) clientFlightComplete() bool {
	return st.reader != nil && !st.expectCert && !st.expectCV && len(st.pending) == 0
}

func (st *tls12State) handleClientFlight(payload []byte) (tlsAlert, bool) {
	buf := payload
	if len(st.pending) > 0 {
		st.pending = append(st.pending, payload...)
		buf = st.pending
	}
	for len(buf) > 0 {
		msg, complete, tooLarge := nextHandshakeMessage(buf)
		if tooLarge {
			return alertDecodeError, false
		}
		if !complete {
			break
		}
		if alert, ok := st.handleClientMessage(msg); !ok {
			return alert, false
		}
		buf = buf[len(msg):]
	}
	st.pending = append(st.pending[:0], buf...)
	return 0, true
}

func (st *tls12State) handleClientMessage(msg []byte) (tlsAlert, bool) {
	body := msg[tlsHandshakeHeaderLen:]
	switch {
	case st.expectCert:
		if msg[0] != tlsHSCertificate {
			return alertUnexpectedMessage, false
		}
		chain, alert, ok := parseClientCertificate(body, false)
		if !ok {
			return alert, false
		}
		certs, alert, ok := st.clientAuth.checkChain(chain)
		if !ok {
			if alert == alertCertificateRequired {
				alert = alertBadCertificate
			}
			return alert, false
		}
		st.peerCerts, st.peerChain = certs, chain
		st.expectCert = false
		st.record(msg)
	case msg[0] == tlsHSClientKeyExchange && st.reader == nil:
		peer, ok := parseTLS12ClientKeyExchange(msg)
		if !ok {
			return alertDecodeError, false
		}
		st.record(msg)
		if !st.deriveKeys(peer) {
			return alertIllegalParameter, false
		}
		st.expectCV = len(st.peerChain) > 0
		if !st.expectCV {
			st.cvTranscript = nil
		}
	case msg[0] == tlsHSCertVerify && st.expectCV:
		scheme, sig, alert, ok := parseCertificateVerify(body, clientCertSchemes12)
		if !ok {
			return alert, false
		}
		var digestBuf [sha256.Size]byte
		if !verifyTLS12ClientSignature(st.peerCerts[0].PublicKey, scheme, st.cvTranscript.Sum(digestBuf[:0]), sig) {
			return alertDecryptError, false
		}
		st.record(msg)
		st.expectCV = false
		st.cvTranscript = nil
	default:
		return alertUnexpectedMessage, false
	}
	return 0, true
}

func (r *Request) TLSPeerCertificates() []*x509.Certificate {
	return r.peerCerts
}
