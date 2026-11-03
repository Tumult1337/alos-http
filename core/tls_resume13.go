//go:build linux && amd64

package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"time"
)

const (
	tlsExtPreSharedKey       = 0x0029
	tlsExtPSKModes           = 0x002d
	pskModeDHE               = 1
	tlsHSNewSessionTicket    = 4
	tlsVersion13             = 0x0304
	maxTLS13TicketLifetime   = 7 * 24 * time.Hour
	pskBinderListLenLen      = 2
	pskIdentityListLenLen    = 2
	pskObfuscatedAgeLen      = 4
	pskSelectedIdentityFirst = 0
)

func parsePSKModes(data []byte) bool {
	if len(data) < 1 || int(data[0]) != len(data)-1 {
		return false
	}
	for _, mode := range data[1:] {
		if mode == pskModeDHE {
			return true
		}
	}
	return false
}

func parsePreSharedKey(ch *ParsedClientHello, data []byte, dataOffset int) {
	if len(data) < pskIdentityListLenLen {
		return
	}
	idsLen := int(binary.BigEndian.Uint16(data))
	if pskIdentityListLenLen+idsLen+pskBinderListLenLen > len(data) {
		return
	}
	ids := data[pskIdentityListLenLen : pskIdentityListLenLen+idsLen]
	for len(ids) >= 2 {
		n := int(binary.BigEndian.Uint16(ids))
		if 2+n+pskObfuscatedAgeLen > len(ids) || n == 0 {
			ch.pskIdentities = 0
			return
		}
		if ch.pskIdentities == 0 {
			ch.pskIdentity = ids[2 : 2+n]
		}
		ch.pskIdentities++
		ids = ids[2+n+pskObfuscatedAgeLen:]
	}
	if len(ids) != 0 {
		ch.pskIdentities = 0
		return
	}
	bindersAt := pskIdentityListLenLen + idsLen
	ch.pskBindersOffset = dataOffset + bindersAt
	bindersLen := int(binary.BigEndian.Uint16(data[bindersAt:]))
	binders := data[bindersAt+pskBinderListLenLen:]
	if bindersLen != len(binders) {
		ch.pskBinders = 0
		return
	}
	for len(binders) >= 1 {
		n := int(binders[0])
		if 1+n > len(binders) || n < 32 {
			ch.pskBinders = 0
			return
		}
		if ch.pskBinders == 0 {
			ch.pskBinder = binders[1 : 1+n]
		}
		ch.pskBinders++
		binders = binders[1+n:]
	}
}

func tls13SuiteByID(id uint16) *CipherSuiteConfig {
	for i := range SupportedSuites {
		if SupportedSuites[i].ID == id {
			return &SupportedSuites[i]
		}
	}
	return nil
}

type resumeRequest struct {
	ch               *ParsedClientHello
	cs               *CipherSuiteConfig
	policy           clientAuthPolicy
	requiredALPN     string
	transcriptPrefix []byte
	hello            []byte
}

type resumedSession struct {
	early     []byte
	peerCerts []*x509.Certificate
	peerChain [][]byte
}

func (s *Server) acceptResumption(req resumeRequest, dst []byte) (resumedSession, tlsAlert, bool) {
	ch, cs := req.ch, req.cs
	if ch.pskIdentities == 0 && ch.pskBinders == 0 {
		return resumedSession{}, 0, true
	}
	if ch.pskNotLast || ch.pskIdentities != ch.pskBinders || ch.pskBindersOffset > len(req.hello) {
		return resumedSession{}, alertIllegalParameter, false
	}
	if s.tickets == nil || !ch.pskDHE {
		return resumedSession{}, 0, true
	}
	t, ok := s.tickets.open(ch.pskIdentity)
	if !ok || t.tlsVersion != tlsVersion13 || t.sni != ch.ServerName || len(t.secret) != cs.HashLen || req.requiredALPN != "" && t.alpn != req.requiredALPN {
		return resumedSession{}, 0, true
	}
	if ts := tls13SuiteByID(t.suite); ts == nil || ts.HashLen != cs.HashLen {
		return resumedSession{}, 0, true
	}
	certs, chain, ok := req.policy.resumedIdentity(t.clientCert)
	if !ok {
		return resumedSession{}, 0, true
	}
	early := TLSExtractTo(cs.HashFn, cs.zeroHashInput, t.secret, dst)
	var binderKeyBuf, helloHashBuf, binderBuf [64]byte
	binderKey := cs.DeriveSecretTo(&cs.labelResBinder, early, cs.emptyTranscriptHash, binderKeyBuf[:0])
	h := cs.HashFn()
	h.Write(req.transcriptPrefix)
	h.Write(req.hello[:ch.pskBindersOffset])
	want := cs.ComputeFinishedTo(binderKey, h.Sum(helloHashBuf[:0]), binderBuf[:0])
	clear(binderKeyBuf[:])
	if !hmac.Equal(want, ch.pskBinder) {
		clear(early)
		return resumedSession{}, alertDecryptError, false
	}
	return resumedSession{early: early, peerCerts: certs, peerChain: chain}, 0, true
}

type pendingTicket struct {
	suite      *CipherSuiteConfig
	resMaster  [64]byte
	n          int
	sni        string
	alpn       string
	clientCert []byte
}

func (s *Server) issuesTickets(ch *ParsedClientHello) bool {
	return s.tickets != nil && ch.pskDHE
}

func newPendingTicket(cs *CipherSuiteConfig, masterSecret, resumptionHash []byte, sni, alpn string, peerChain [][]byte) *pendingTicket {
	p := &pendingTicket{suite: cs, sni: sni, alpn: alpn, clientCert: encodeCertChain(peerChain)}
	p.n = len(cs.DeriveSecretTo(&cs.labelResMaster, masterSecret, resumptionHash, p.resMaster[:0]))
	return p
}

func (s *Server) newSessionTicketMessage(p *pendingTicket) []byte {
	msg, ok := s.appendSessionTicketMessage(nil, p)
	if !ok {
		return nil
	}
	return msg
}

func (s *Server) appendSessionTicketMessage(dst []byte, p *pendingTicket) ([]byte, bool) {
	cs := p.suite
	var pskBuf [64]byte
	psk := cs.DeriveSecretTo(&cs.labelResumption, p.resMaster[:p.n], nil, pskBuf[:0])
	clear(p.resMaster[:])
	msgStart := len(dst)
	lifetime := min(s.tickets.lifetime, maxTLS13TicketLifetime)
	dst = append(dst, tlsHSNewSessionTicket, 0, 0, 0)
	dst = binary.BigEndian.AppendUint32(dst, uint32(lifetime/time.Second))
	ageOff := len(dst)
	dst = append(dst, 0, 0, 0, 0)
	rand.Read(dst[ageOff : ageOff+4])
	ageAdd := binary.BigEndian.Uint32(dst[ageOff:])
	dst = append(dst, 0)
	ticketLenOff := len(dst)
	dst = append(dst, 0, 0)
	ticketStart := len(dst)
	dst, ok := s.tickets.appendSealed(dst, &sessionTicket{
		tlsVersion: tlsVersion13,
		suite:      cs.ID,
		createdMs:  s.tickets.nowMs(),
		ageAdd:     ageAdd,
		secret:     psk,
		sni:        p.sni,
		alpn:       p.alpn,
		clientCert: p.clientCert,
	})
	clear(pskBuf[:])
	ticketLen := len(dst) - ticketStart
	if !ok || ticketLen > maxTicketWireLen {
		return dst[:msgStart], false
	}
	binary.BigEndian.PutUint16(dst[ticketLenOff:], uint16(ticketLen))
	dst = append(dst, 0, 0)
	bodyLen := len(dst) - msgStart - 4
	dst[msgStart+1] = byte(bodyLen >> 16)
	dst[msgStart+2] = byte(bodyLen >> 8)
	dst[msgStart+3] = byte(bodyLen)
	return dst, true
}
