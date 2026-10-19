//go:build linux && amd64

package core

import (
	"crypto/x509"
	"encoding/binary"
	"slices"
	"time"
)

const (
	tlsExtSessionTicket  = 0x0023
	tlsVersion12         = 0x0303
	tls12MasterSecretLen = 48
)

func tls12SuiteByID(id uint16) *tls12Suite {
	for i := range tls12Suites {
		if tls12Suites[i].id == id {
			return &tls12Suites[i]
		}
	}
	return nil
}

type tls12Resumption struct {
	ticket    sessionTicket
	suite     *tls12Suite
	peerCerts []*x509.Certificate
	peerChain [][]byte
}

func (s *Server) acceptTLS12Ticket(ch *ParsedClientHello, kt tls12KeyType, policy clientAuthPolicy) (tls12Resumption, tlsAlert, bool) {
	if s.tickets == nil || len(ch.sessionTicket) == 0 {
		return tls12Resumption{}, 0, true
	}
	t, ok := s.tickets.open(ch.sessionTicket)
	if !ok || t.tlsVersion != tlsVersion12 || t.sni != ch.ServerName || len(t.secret) != tls12MasterSecretLen {
		return tls12Resumption{}, 0, true
	}
	suite := tls12SuiteByID(t.suite)
	if suite == nil || suite.keyType != kt || !slices.Contains(ch.CipherSuites, t.suite) {
		return tls12Resumption{}, 0, true
	}
	if t.ems && !ch.extendedMasterSecret {
		return tls12Resumption{}, alertHandshakeFailure, false
	}
	if t.ems != ch.extendedMasterSecret {
		return tls12Resumption{}, 0, true
	}
	certs, chain, ok := policy.resumedIdentity(t.clientCert)
	if !ok {
		return tls12Resumption{}, 0, true
	}
	return tls12Resumption{ticket: t, suite: suite, peerCerts: certs, peerChain: chain}, 0, true
}

func (s *Server) tls12NewSessionTicket(st *tls12State, alpn string) []byte {
	ticket := s.tickets.seal(&sessionTicket{
		tlsVersion: tlsVersion12,
		suite:      st.suite.id,
		createdMs:  s.tickets.nowMs(),
		secret:     st.master,
		ems:        st.ems,
		sni:        st.sni,
		alpn:       alpn,
		clientCert: encodeCertChain(st.peerChain),
	})
	lifetime := s.tickets.lifetime
	if ticket == nil || len(ticket) > maxTicketWireLen {
		ticket, lifetime = nil, 0
	}
	body := make([]byte, 0, 4+2+len(ticket))
	body = binary.BigEndian.AppendUint32(body, uint32(lifetime/time.Second))
	body = binary.BigEndian.AppendUint16(body, uint16(len(ticket)))
	body = append(body, ticket...)
	return tls12Handshake(tlsHSNewSessionTicket, body)
}
