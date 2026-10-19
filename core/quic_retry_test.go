//go:build linux && amd64

package core

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

var (
	retryClient    = netip.MustParseAddrPort("203.0.113.5:44321")
	retryOtherIP   = netip.MustParseAddrPort("203.0.113.6:44321")
	retryOtherPort = netip.MustParseAddrPort("203.0.113.5:44322")
	retryODCID     = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	retryClientCID = []byte{0xc1, 0xc2, 0xc3, 0xc4}
)

type fakeClock struct{ ns atomic.Int64 }

func newFakeClock(start int64) *fakeClock {
	c := &fakeClock{}
	c.ns.Store(start)
	return c
}

func (c *fakeClock) now() int64              { return c.ns.Load() }
func (c *fakeClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

func TestQUICRetryIntegrityTagRFC9001Vector(t *testing.T) {
	pkt, err := hex.DecodeString("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba")
	if err != nil {
		t.Fatal(err)
	}
	body, tag := pkt[:len(pkt)-16], pkt[len(pkt)-16:]
	if got := quicRetryIntegrityTag(retryODCID, body); !bytes.Equal(got, tag) {
		t.Fatalf("integrity tag %x, RFC 9001 A.4 says %x", got, tag)
	}
	scid, _ := hex.DecodeString("f067a5502a4262b5")
	built := quicBuildRetryPacket(nil, scid, retryODCID, []byte("token"))
	if built[0]&0xf0 != 0xf0 || !bytes.Equal(built[1:len(built)-16], body[1:]) {
		t.Fatalf("built Retry %x, want %x apart from the unused bits", built, pkt)
	}
	if !bytes.Equal(quicRetryIntegrityTag(retryODCID, built[:len(built)-16]), built[len(built)-16:]) {
		t.Fatal("built Retry carries a tag that does not verify")
	}
}

func TestQUICTokenCodec(t *testing.T) {
	clock := newFakeClock(int64(1000 * time.Hour))
	c := newQUICTokenCodec(clock.now)
	retrySCID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	retry := c.retryToken(retryClient, retryODCID, retrySCID)

	verdict, claims := c.validate(retry, retryClient)
	if verdict != quicTokenRetryValid || !bytes.Equal(claims.odcid, retryODCID) || !bytes.Equal(claims.retrySCID, retrySCID) {
		t.Fatalf("fresh Retry token: verdict %d claims %+v", verdict, claims)
	}
	for name, addr := range map[string]netip.AddrPort{"other IP": retryOtherIP, "other port": retryOtherPort} {
		if v, _ := c.validate(retry, addr); v != quicTokenRetryInvalid {
			t.Fatalf("Retry token from %s: verdict %d", name, v)
		}
	}
	tampered := append([]byte(nil), retry...)
	tampered[len(tampered)-1] ^= 1
	if v, _ := c.validate(tampered, retryClient); v != quicTokenRetryInvalid {
		t.Fatalf("tampered Retry token: verdict %d", v)
	}
	clock.advance(9 * time.Second)
	if v, _ := c.validate(retry, retryClient); v != quicTokenRetryValid {
		t.Fatalf("9s-old Retry token: verdict %d", v)
	}
	clock.advance(2 * time.Second)
	if v, _ := c.validate(retry, retryClient); v != quicTokenRetryInvalid {
		t.Fatalf("11s-old Retry token: verdict %d", v)
	}

	nt := c.newToken(retryClient)
	if v, _ := c.validate(nt, retryOtherPort); v != quicTokenNewTokenValid {
		t.Fatalf("NEW_TOKEN from the same IP on another port: verdict %d", v)
	}
	if v, _ := c.validate(nt, retryOtherIP); v != quicTokenUnusable {
		t.Fatalf("NEW_TOKEN from another IP: verdict %d", v)
	}
	clock.advance(23 * time.Hour)
	if v, _ := c.validate(nt, retryClient); v != quicTokenNewTokenValid {
		t.Fatalf("23h-old NEW_TOKEN: verdict %d", v)
	}
	clock.advance(2 * time.Hour)
	if v, _ := c.validate(nt, retryClient); v != quicTokenUnusable {
		t.Fatalf("25h-old NEW_TOKEN: verdict %d", v)
	}

	for _, junk := range [][]byte{{0x09, 1}, bytes.Repeat([]byte{0x7f}, 40), {quicTokenTypeNewToken}, {quicTokenTypeRetry}, append([]byte{quicTokenTypeNewToken}, make([]byte, 40)...)} {
		if v, _ := c.validate(junk, retryClient); v != quicTokenUnusable {
			t.Fatalf("junk token %x: verdict %d", junk, v)
		}
	}
	if v, _ := c.validate(append([]byte{quicTokenTypeRetry, 1}, make([]byte, 40)...), retryClient); v != quicTokenRetryInvalid {
		t.Fatalf("forged Retry token: verdict %d", v)
	}
	if v, _ := c.validate(nil, retryClient); v != quicTokenAbsent {
		t.Fatalf("no token: verdict %d", v)
	}
}

func TestQUICRetryClaimsRejectMalformed(t *testing.T) {
	for _, b := range [][]byte{nil, {0}, {21, 0}, {1, 9}, {1, 9, 21}, {1, 9, 2, 1}, {1, 9, 1, 1, 0}} {
		if _, ok := parseRetryClaims(b); ok {
			t.Fatalf("claims %x parsed", b)
		}
	}
	claims, ok := parseRetryClaims([]byte{1, 9, 2, 7, 8})
	if !ok || !bytes.Equal(claims.odcid, []byte{9}) || !bytes.Equal(claims.retrySCID, []byte{7, 8}) {
		t.Fatalf("well-formed claims: ok=%v %+v", ok, claims)
	}
}

func TestQUICTokenKeyRotationKeepsPreviousKey(t *testing.T) {
	clock := newFakeClock(int64(time.Hour))
	c := newQUICTokenCodec(clock.now)
	clock.advance(quicTokenKeyRotation - time.Second)
	nt := c.newToken(retryClient)
	firstID := nt[1]
	clock.advance(2 * time.Second)
	if v, _ := c.validate(nt, retryClient); v != quicTokenNewTokenValid {
		t.Fatalf("token from the previous key after one rotation: verdict %d", v)
	}
	if fresh := c.newToken(retryClient); fresh[1] == firstID {
		t.Fatal("rotation did not change the key ID")
	}
	clock.advance(quicTokenKeyRotation)
	if _, _, ok := c.open(nt, retryClient); ok {
		t.Fatal("token from a key two rotations old still opens")
	}
}

type parsedRetry struct {
	dcid, scid, token, tag []byte
}

func parseRetryPacket(t *testing.T, pkt []byte) parsedRetry {
	t.Helper()
	if len(pkt) < 7+16 || pkt[0]&0xf0 != 0xf0 || binary.BigEndian.Uint32(pkt[1:5]) != quicVersion1 {
		t.Fatalf("not a v1 Retry packet: %x", pkt)
	}
	p := 5
	dl := int(pkt[p])
	dcid := pkt[p+1 : p+1+dl]
	p += 1 + dl
	sl := int(pkt[p])
	scid := pkt[p+1 : p+1+sl]
	p += 1 + sl
	return parsedRetry{dcid: dcid, scid: scid, token: pkt[p : len(pkt)-16], tag: pkt[len(pkt)-16:]}
}

func initialCloseCode(t *testing.T, pkt, clientDCID []byte) uint64 {
	t.Helper()
	if len(pkt) == 0 {
		t.Fatal("no reply packet")
	}
	pkt = append([]byte(nil), pkt...)
	hdr, _, err := quicParseLongHeader(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.pktType != int(quicInitialType) {
		t.Fatalf("reply packet type %d, want Initial", hdr.pktType)
	}
	_, serverKeys, err := quicDeriveInitialKeys(clientDCID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := quicDecryptPacket(pkt, &hdr, serverKeys, -1)
	if err != nil {
		t.Fatalf("INVALID_TOKEN close does not decrypt with the Initial keys: %v", err)
	}
	var code uint64 = 1 << 62
	_ = quicParseFrames(plain, &quicFrameVisitor{onConnClose: func(f quicConnCloseFrame) { code = f.errorCode }})
	return code
}

func transportParams(t *testing.T, tp []byte) map[uint64][]byte {
	t.Helper()
	params := map[uint64][]byte{}
	for i := 0; i < len(tp); {
		id, n := quicParseVarint(tp[i:])
		if n <= 0 {
			t.Fatalf("bad transport parameter id at %d", i)
		}
		i += n
		l, n2 := quicParseVarint(tp[i:])
		if n2 <= 0 || i+n2+int(l) > len(tp) {
			t.Fatalf("bad transport parameter length at %d", i)
		}
		i += n2
		params[id] = tp[i : i+int(l)]
		i += int(l)
	}
	return params
}

func TestQUICAdmitInitialRetryFlow(t *testing.T) {
	srv := New(Config{})
	first := quicPacketHeader{dcid: retryODCID, scid: retryClientCID}
	a := srv.admitInitial(&first, retryClient)
	if a.create || a.reply == nil {
		t.Fatalf("Initial without a token: create=%v reply=%d bytes", a.create, len(a.reply))
	}
	r := parseRetryPacket(t, a.reply)
	if !bytes.Equal(r.dcid, retryClientCID) || len(r.scid) != quicConnIDLen || bytes.Equal(r.scid, retryODCID) {
		t.Fatalf("Retry CIDs dcid=%x scid=%x", r.dcid, r.scid)
	}
	if !bytes.Equal(quicRetryIntegrityTag(retryODCID, a.reply[:len(a.reply)-16]), r.tag) {
		t.Fatal("Retry integrity tag does not verify against the original DCID")
	}
	if len(a.reply) >= quicMinInitialDatagram {
		t.Fatalf("Retry of %d bytes is not smaller than the Initial it answers", len(a.reply))
	}

	second := quicPacketHeader{dcid: r.scid, scid: retryClientCID, token: r.token}
	b := srv.admitInitial(&second, retryClient)
	if !b.create || !b.validated || b.reply != nil || !bytes.Equal(b.odcid, retryODCID) || !bytes.Equal(b.retrySCID, r.scid) {
		t.Fatalf("Initial with the Retry token: %+v", b)
	}

	qc := newTestQUIC(srv)
	qc.applyAdmission(b)
	params := transportParams(t, quicBuildTransportParams(qc))
	if !bytes.Equal(params[quicTPOrigDstCID], retryODCID) || !bytes.Equal(params[quicTPRetrySrcCID], r.scid) {
		t.Fatalf("original_destination_connection_id %x retry_source_connection_id %x", params[quicTPOrigDstCID], params[quicTPRetrySrcCID])
	}
	if !qc.addressValidated.Load() {
		t.Fatal("Retry-validated connection still under the amplification limit")
	}

	plain := newTestQUIC(srv)
	if _, ok := transportParams(t, quicBuildTransportParams(plain))[quicTPRetrySrcCID]; ok {
		t.Fatal("retry_source_connection_id sent on a connection that never saw a Retry")
	}

	wrongDCID := quicPacketHeader{dcid: []byte{9, 9, 9, 9, 9, 9, 9, 9}, scid: retryClientCID, token: r.token}
	if c := srv.admitInitial(&wrongDCID, retryClient); c.create || initialCloseCode(t, c.reply, wrongDCID.dcid) != quicErrInvalidToken {
		t.Fatal("Retry token used with another DCID was not refused with INVALID_TOKEN")
	}
	if c := srv.admitInitial(&second, retryOtherIP); c.create || initialCloseCode(t, c.reply, second.dcid) != quicErrInvalidToken {
		t.Fatal("Retry token from another address was not refused with INVALID_TOKEN")
	}
}

func TestQUICAdmitInitialNewTokenSkipsRetry(t *testing.T) {
	srv := New(Config{})
	nt := srv.quicTokens.newToken(retryClient)
	hdr := quicPacketHeader{dcid: retryODCID, scid: retryClientCID, token: nt}
	a := srv.admitInitial(&hdr, retryOtherPort)
	if !a.create || !a.validated || a.retrySCID != nil || a.odcid != nil || a.reply != nil {
		t.Fatalf("Initial with a NEW_TOKEN: %+v", a)
	}
	hdr.token = srv.quicTokens.newToken(retryOtherIP)
	if b := srv.admitInitial(&hdr, retryClient); b.create || len(b.reply) == 0 || b.reply[0]&0xf0 != 0xf0 {
		t.Fatal("NEW_TOKEN for another IP did not fall back to Retry")
	}
	other := New(Config{})
	hdr.token = nt
	if b := other.admitInitial(&hdr, retryClient); b.create || len(b.reply) == 0 || b.reply[0]&0xf0 != 0xf0 {
		t.Fatal("NEW_TOKEN from another server instance did not fall back to Retry")
	}
}

func TestQUICAdmitInitialExpiredNewTokenGetsRetry(t *testing.T) {
	srv := New(Config{})
	clock := newFakeClock(int64(1000 * time.Hour))
	srv.quicTokens = newQUICTokenCodec(clock.now)
	hdr := quicPacketHeader{dcid: retryODCID, scid: retryClientCID, token: srv.quicTokens.newToken(retryClient)}
	clock.advance(quicNewTokenLifetime + time.Second)
	if a := srv.admitInitial(&hdr, retryClient); a.create || len(a.reply) == 0 || a.reply[0]&0xf0 != 0xf0 {
		t.Fatal("expired NEW_TOKEN did not fall back to Retry")
	}
}

func TestQUICNewTokenSentAfterHandshake(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.qc.sendNewToken()
	var token []byte
	for _, raw := range p.pc.snapshot() {
		pkt := append([]byte(nil), raw...)
		hdr, err := quicParseShortHeader(pkt, p.qc.dstCIDLen)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := quicDecryptPacket(pkt, &hdr, p.keys, -1)
		if err != nil {
			t.Fatal(err)
		}
		_ = quicParseFrames(plain, &quicFrameVisitor{onNewToken: func(tok []byte) { token = append([]byte(nil), tok...) }})
	}
	if token == nil {
		t.Fatal("no NEW_TOKEN frame sent")
	}
	if v, _ := p.srv.quicTokens.validate(token, pathA); v != quicTokenNewTokenValid {
		t.Fatalf("NEW_TOKEN frame carried a token with verdict %d", v)
	}
}

func clientInitial(t *testing.T, dcid, scid, token []byte) []byte {
	t.Helper()
	clientKeys, _, err := quicDeriveInitialKeys(dcid)
	if err != nil {
		t.Fatal(err)
	}
	return quicBuildInitialPacket(nil, dcid, scid, token, make([]byte, quicMinInitialDatagram), 0, -1, clientKeys)
}

type initialSender func(data []byte)

func checkRetryAdmission(t *testing.T, srv *Server, send initialSender, sent func() [][]byte, connMap *quicConnMap) {
	t.Helper()
	send(clientInitial(t, retryODCID, retryClientCID, nil))
	replies := sent()
	if len(replies) != 1 || connMap.Len() != 0 {
		t.Fatalf("tokenless Initial: %d replies, %d map entries; want one Retry and no state", len(replies), connMap.Len())
	}
	r := parseRetryPacket(t, replies[0])
	if !bytes.Equal(quicRetryIntegrityTag(retryODCID, replies[0][:len(replies[0])-16]), r.tag) {
		t.Fatal("Retry tag does not verify")
	}

	send(clientInitial(t, r.scid, retryClientCID, r.token))
	qc, ok := connMap.Load(quicCIDKey(r.scid))
	if !ok {
		t.Fatal("Initial carrying the Retry token did not create a connection")
	}
	t.Cleanup(qc.close)
	if !qc.addressValidated.Load() || !bytes.Equal(qc.getOrigDstCID(), retryODCID) || !bytes.Equal(qc.retrySrcConnID[:qc.retrySrcLen], r.scid) {
		t.Fatalf("admitted conn: validated=%v odcid=%x retrySCID=%x", qc.addressValidated.Load(), qc.getOrigDstCID(), qc.retrySrcConnID[:qc.retrySrcLen])
	}
	if n := len(sent()); n != 1 {
		t.Fatalf("server sent %d datagrams after admission, want none beyond the Retry", n-1)
	}
}

func FuzzQUICTokenValidate(f *testing.F) {
	c := newQUICTokenCodec(nil)
	f.Add(c.retryToken(retryClient, retryODCID, retryClientCID), uint16(44321))
	f.Add(c.newToken(retryClient), uint16(1))
	f.Add([]byte{quicTokenTypeRetry, 1}, uint16(0))
	f.Add([]byte{}, uint16(0))
	f.Fuzz(func(t *testing.T, token []byte, port uint16) {
		addr := netip.AddrPortFrom(retryClient.Addr(), port)
		verdict, claims := c.validate(token, addr)
		switch verdict {
		case quicTokenRetryValid:
			if len(claims.odcid) > quicMaxCIDLen || len(claims.retrySCID) > quicMaxCIDLen {
				t.Fatalf("claims exceed the CID limit: %+v", claims)
			}
			if port != retryClient.Port() {
				t.Fatalf("Retry token accepted from port %d", port)
			}
		case quicTokenAbsent:
			if len(token) != 0 {
				t.Fatal("non-empty token reported absent")
			}
		}
		if verdict == quicTokenRetryValid || verdict == quicTokenNewTokenValid {
			if len(token) < quicTokenPrefixLen+quicTokenIssuedLen+quicAEADTagLen {
				t.Fatalf("%d-byte token validated", len(token))
			}
		}
	})
}
