//go:build linux && amd64

package core

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicTokenTypeRetry      byte = 0x01
	quicTokenTypeNewToken   byte = 0x02
	quicRetryTokenLifetime       = 10 * time.Second
	quicNewTokenLifetime         = 24 * time.Hour
	quicTokenKeyRotation         = 24 * time.Hour
	quicTokenKeyLen              = 16
	quicTokenNonceLen            = 12
	quicTokenPrefixLen           = 2 + quicTokenNonceLen
	quicTokenIssuedLen           = 8
	quicErrInvalidToken          = 0x0b
	quicLongHeaderTypeShift      = 4
	quicRetryUnusedBits          = 0x0f
)

var (
	quicRetryIntegrityKey   = [16]byte{0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e}
	quicRetryIntegrityNonce = [12]byte{0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb}
	quicRetryIntegrityAEAD  = sync.OnceValue(func() cipher.AEAD { return newGCMFromKey(quicRetryIntegrityKey[:]) })
)

type quicTokenVerdict uint8

const (
	quicTokenAbsent quicTokenVerdict = iota
	quicTokenUnusable
	quicTokenRetryValid
	quicTokenRetryInvalid
	quicTokenNewTokenValid
)

type quicTokenCodec struct {
	ring *aeadKeyRing
	now  func() int64
}

type quicRetryClaims struct {
	odcid     []byte
	retrySCID []byte
}

func newQUICTokenCodec(now func() int64) *quicTokenCodec {
	if now == nil {
		now = turbo.UnixNano
	}
	return &quicTokenCodec{ring: newAEADKeyRing(quicTokenKeyLen, quicTokenKeyRotation, now), now: now}
}

func quicTokenAAD(dst []byte, typ, keyID byte, addr netip.AddrPort) []byte {
	ip := addr.Addr().As16()
	dst = append(dst, typ, keyID)
	dst = append(dst, ip[:]...)
	if typ == quicTokenTypeRetry {
		dst = binary.BigEndian.AppendUint16(dst, addr.Port())
	}
	return dst
}

func (c *quicTokenCodec) seal(typ byte, addr netip.AddrPort, plaintext []byte) []byte {
	k := c.ring.current()
	token := make([]byte, quicTokenPrefixLen, quicTokenPrefixLen+len(plaintext)+k.cur.Overhead())
	token[0], token[1] = typ, k.curID
	rand.Read(token[2:quicTokenPrefixLen])
	var aadBuf [2 + 16 + 2]byte
	aad := quicTokenAAD(aadBuf[:0], typ, k.curID, addr)
	return k.cur.Seal(token, token[2:quicTokenPrefixLen], plaintext, aad)
}

func (c *quicTokenCodec) retryToken(addr netip.AddrPort, odcid, retrySCID []byte) []byte {
	plain := binary.BigEndian.AppendUint64(nil, uint64(c.now()))
	plain = append(plain, byte(len(odcid)))
	plain = append(plain, odcid...)
	plain = append(plain, byte(len(retrySCID)))
	plain = append(plain, retrySCID...)
	return c.seal(quicTokenTypeRetry, addr, plain)
}

func (c *quicTokenCodec) newToken(addr netip.AddrPort) []byte {
	return c.seal(quicTokenTypeNewToken, addr, binary.BigEndian.AppendUint64(nil, uint64(c.now())))
}

func (c *quicTokenCodec) open(token []byte, addr netip.AddrPort) (typ byte, plain []byte, ok bool) {
	if len(token) < quicTokenPrefixLen {
		return 0, nil, false
	}
	typ = token[0]
	if typ != quicTokenTypeRetry && typ != quicTokenTypeNewToken {
		return typ, nil, false
	}
	aead := c.ring.forID(token[1])
	if aead == nil {
		return typ, nil, false
	}
	var aadBuf [2 + 16 + 2]byte
	aad := quicTokenAAD(aadBuf[:0], typ, token[1], addr)
	plain, err := aead.Open(nil, token[2:quicTokenPrefixLen], token[quicTokenPrefixLen:], aad)
	return typ, plain, err == nil
}

func (c *quicTokenCodec) fresh(plain []byte, lifetime time.Duration) bool {
	if len(plain) < quicTokenIssuedLen {
		return false
	}
	issued := int64(binary.BigEndian.Uint64(plain))
	age := time.Duration(c.now() - issued)
	return age >= 0 && age <= lifetime
}

func (c *quicTokenCodec) validate(token []byte, addr netip.AddrPort) (quicTokenVerdict, quicRetryClaims) {
	if len(token) == 0 {
		return quicTokenAbsent, quicRetryClaims{}
	}
	typ, plain, ok := c.open(token, addr)
	if typ != quicTokenTypeRetry {
		if ok && c.fresh(plain, quicNewTokenLifetime) {
			return quicTokenNewTokenValid, quicRetryClaims{}
		}
		return quicTokenUnusable, quicRetryClaims{}
	}
	if !ok || !c.fresh(plain, quicRetryTokenLifetime) {
		return quicTokenRetryInvalid, quicRetryClaims{}
	}
	claims, parsed := parseRetryClaims(plain[quicTokenIssuedLen:])
	if !parsed {
		return quicTokenRetryInvalid, quicRetryClaims{}
	}
	return quicTokenRetryValid, claims
}

func parseRetryClaims(b []byte) (quicRetryClaims, bool) {
	var claims quicRetryClaims
	if len(b) < 1 || int(b[0]) > quicMaxCIDLen || len(b) < 1+int(b[0])+1 {
		return claims, false
	}
	claims.odcid = b[1 : 1+int(b[0])]
	b = b[1+int(b[0]):]
	if int(b[0]) > quicMaxCIDLen || len(b) != 1+int(b[0]) {
		return claims, false
	}
	claims.retrySCID = b[1:]
	return claims, true
}

func quicBuildRetryPacket(clientSCID, retrySCID, odcid, token []byte) []byte {
	pkt := make([]byte, 0, 1+4+1+len(clientSCID)+1+len(retrySCID)+len(token)+16)
	first := quicLongHeaderBit | quicFixedBit | quicRetryType<<quicLongHeaderTypeShift | byte(turbo.Uint64())&quicRetryUnusedBits
	pkt = append(pkt, first)
	pkt = binary.BigEndian.AppendUint32(pkt, quicVersion1)
	pkt = append(pkt, byte(len(clientSCID)))
	pkt = append(pkt, clientSCID...)
	pkt = append(pkt, byte(len(retrySCID)))
	pkt = append(pkt, retrySCID...)
	pkt = append(pkt, token...)
	return append(pkt, quicRetryIntegrityTag(odcid, pkt)...)
}

func quicRetryIntegrityTag(odcid, retryWithoutTag []byte) []byte {
	pseudo := make([]byte, 0, 1+len(odcid)+len(retryWithoutTag))
	pseudo = append(pseudo, byte(len(odcid)))
	pseudo = append(pseudo, odcid...)
	pseudo = append(pseudo, retryWithoutTag...)
	return quicRetryIntegrityAEAD().Seal(nil, quicRetryIntegrityNonce[:], nil, pseudo)
}

func quicBuildInvalidTokenClose(clientDCID, clientSCID []byte) []byte {
	return quicBuildInitialClose(clientDCID, clientSCID, quicErrInvalidToken)
}

const quicErrConnectionRefused = 0x02

func quicBuildInitialClose(clientDCID, clientSCID []byte, errorCode uint64) []byte {
	_, serverKeys, err := quicDeriveInitialKeys(clientDCID)
	if err != nil {
		return nil
	}
	frames := quicAppendConnCloseFrame(nil, errorCode, 0, "")
	return quicBuildInitialPacket(nil, clientSCID, clientDCID, nil, frames, 0, -1, serverKeys)
}

type quicInitialAdmission struct {
	reply     []byte
	create    bool
	validated bool
	odcid     []byte
	retrySCID []byte
}

func (s *Server) admitInitial(hdr *quicPacketHeader, from netip.AddrPort) quicInitialAdmission {
	verdict, claims := s.quicTokens.validate(hdr.token, from)
	switch verdict {
	case quicTokenRetryValid:
		if string(claims.retrySCID) != string(hdr.dcid) {
			return quicInitialAdmission{reply: quicBuildInvalidTokenClose(hdr.dcid, hdr.scid)}
		}
		return quicInitialAdmission{create: true, validated: true, odcid: claims.odcid, retrySCID: claims.retrySCID}
	case quicTokenNewTokenValid:
		return quicInitialAdmission{create: true, validated: true}
	case quicTokenRetryInvalid:
		return quicInitialAdmission{reply: quicBuildInvalidTokenClose(hdr.dcid, hdr.scid)}
	}
	retrySCID := make([]byte, quicConnIDLen)
	rand.Read(retrySCID)
	token := s.quicTokens.retryToken(from, hdr.dcid, retrySCID)
	return quicInitialAdmission{reply: quicBuildRetryPacket(hdr.scid, retrySCID, hdr.dcid, token)}
}

func (qc *QUICConn) applyAdmission(a quicInitialAdmission) {
	if a.validated {
		qc.addressValidated.Store(true)
	}
	if a.odcid != nil {
		qc.origDstLen = copy(qc.origDstConnID[:], a.odcid)
	}
	if a.retrySCID != nil {
		qc.retrySrcLen = copy(qc.retrySrcConnID[:], a.retrySCID)
	}
}

func (qc *QUICConn) sendNewToken() {
	if qc.server == nil || qc.server.quicTokens == nil {
		return
	}
	addr := qc.currentPath()
	if !addr.IsValid() {
		return
	}
	token := qc.server.quicTokens.newToken(addr)
	frame := quicAppendVarint(nil, quicFrameNewToken)
	frame = quicAppendVarint(frame, uint64(len(token)))
	frame = append(frame, token...)
	qc.sendFrames(quicSpaceAppData, frame, true)
}
