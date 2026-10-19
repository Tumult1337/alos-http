//go:build linux && amd64

package core

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

const (
	ticketFormatVersion    = 1
	ticketKeyLen           = 32
	ticketNonceLen         = 12
	ticketPrefixLen        = 1 + ticketNonceLen
	ticketKeyRotation      = 24 * time.Hour
	defaultTicketLifetime  = 48 * time.Hour
	maxTicketSecretLen     = 48
	maxTicketFieldLen      = 0xffff
	maxTicketClientCertLen = 0xffffff
	maxTicketWireLen       = 0xffff
)

type sessionTicket struct {
	tlsVersion uint16
	suite      uint16
	createdMs  int64
	ageAdd     uint32
	secret     []byte
	ems        bool
	sni        string
	alpn       string
	clientCert []byte
}

type ticketCodec struct {
	ring     *aeadKeyRing
	lifetime time.Duration
}

func newTicketCodec(lifetime time.Duration, now func() int64) *ticketCodec {
	return &ticketCodec{ring: newAEADKeyRing(ticketKeyLen, ticketKeyRotation, now), lifetime: lifetime}
}

func (tc *ticketCodec) nowMs() int64 {
	return tc.ring.now() / int64(time.Millisecond)
}

func appendTicketPlaintext(dst []byte, t *sessionTicket) []byte {
	dst = append(dst, ticketFormatVersion)
	dst = binary.BigEndian.AppendUint16(dst, t.tlsVersion)
	dst = binary.BigEndian.AppendUint16(dst, t.suite)
	dst = binary.BigEndian.AppendUint64(dst, uint64(t.createdMs))
	dst = binary.BigEndian.AppendUint32(dst, t.ageAdd)
	dst = append(dst, byte(len(t.secret)))
	dst = append(dst, t.secret...)
	if t.ems {
		dst = append(dst, 1)
	} else {
		dst = append(dst, 0)
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(t.sni)))
	dst = append(dst, t.sni...)
	dst = append(dst, byte(len(t.alpn)))
	dst = append(dst, t.alpn...)
	n := len(t.clientCert)
	dst = append(dst, byte(n>>16), byte(n>>8), byte(n))
	return append(dst, t.clientCert...)
}

func (tc *ticketCodec) seal(t *sessionTicket) []byte {
	if len(t.secret) > maxTicketSecretLen || len(t.sni) > maxTicketFieldLen || len(t.alpn) > 0xff || len(t.clientCert) > maxTicketClientCertLen {
		return nil
	}
	plain := appendTicketPlaintext(make([]byte, 0, 64+len(t.secret)+len(t.sni)+len(t.alpn)+len(t.clientCert)), t)
	k := tc.ring.current()
	out := make([]byte, ticketPrefixLen, ticketPrefixLen+len(plain)+k.cur.Overhead())
	out[0] = k.curID
	rand.Read(out[1:ticketPrefixLen])
	out = k.cur.Seal(out, out[1:ticketPrefixLen], plain, out[:1])
	clear(plain)
	return out
}

func (tc *ticketCodec) open(ticket []byte) (sessionTicket, bool) {
	if len(ticket) < ticketPrefixLen {
		return sessionTicket{}, false
	}
	aead := tc.ring.forID(ticket[0])
	if aead == nil {
		return sessionTicket{}, false
	}
	plain, err := aead.Open(nil, ticket[1:ticketPrefixLen], ticket[ticketPrefixLen:], ticket[:1])
	if err != nil {
		return sessionTicket{}, false
	}
	t, ok := parseTicketPlaintext(plain)
	if !ok {
		return sessionTicket{}, false
	}
	age := time.Duration(tc.nowMs()-t.createdMs) * time.Millisecond
	if age < 0 || age > tc.lifetime {
		return sessionTicket{}, false
	}
	return t, true
}

type ticketReader struct {
	b  []byte
	ok bool
}

func (r *ticketReader) take(n int) []byte {
	if !r.ok || n > len(r.b) {
		r.ok = false
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *ticketReader) uint(n int) uint64 {
	var v uint64
	for _, c := range r.take(n) {
		v = v<<8 | uint64(c)
	}
	return v
}

func parseTicketPlaintext(b []byte) (sessionTicket, bool) {
	r := ticketReader{b: b, ok: true}
	var t sessionTicket
	if r.uint(1) != ticketFormatVersion {
		return t, false
	}
	t.tlsVersion = uint16(r.uint(2))
	t.suite = uint16(r.uint(2))
	t.createdMs = int64(r.uint(8))
	t.ageAdd = uint32(r.uint(4))
	t.secret = r.take(int(r.uint(1)))
	switch r.uint(1) {
	case 0:
	case 1:
		t.ems = true
	default:
		return t, false
	}
	t.sni = string(r.take(int(r.uint(2))))
	t.alpn = string(r.take(int(r.uint(1))))
	t.clientCert = r.take(int(r.uint(3)))
	if !r.ok || len(r.b) != 0 || len(t.secret) == 0 {
		return sessionTicket{}, false
	}
	return t, true
}
