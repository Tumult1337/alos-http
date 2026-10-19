//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
)

func helloWithShares(groups []tlsGroup, shares map[tlsGroup][]byte) *ParsedClientHello {
	ch := &ParsedClientHello{}
	for _, g := range groups {
		ch.SupportedGroups = append(ch.SupportedGroups, uint16(g))
	}
	for _, g := range []tlsGroup{groupX25519, groupP256, groupX25519MLKEM768} {
		if share, ok := shares[g]; ok {
			ch.recordKeyShare(g, share)
		}
	}
	return ch
}

func TestSelectKeyShare(t *testing.T) {
	x := make([]byte, x25519ShareLen)
	p := make([]byte, p256ShareLen)
	m := make([]byte, mlkemHybridClientShareLen)
	all := []tlsGroup{groupX25519MLKEM768, groupX25519, groupP256}
	cases := []struct {
		name      string
		groups    []tlsGroup
		shares    map[tlsGroup][]byte
		preferPQ  bool
		want      tlsGroup
		wantRetry bool
		wantOK    bool
	}{
		{"X25519 share", all, map[tlsGroup][]byte{groupX25519: x}, false, groupX25519, false, true},
		{"hybrid and X25519 shares prefer X25519", all, map[tlsGroup][]byte{groupX25519: x, groupX25519MLKEM768: m}, false, groupX25519, false, true},
		{"hybrid and X25519 shares with PQ preference", all, map[tlsGroup][]byte{groupX25519: x, groupX25519MLKEM768: m}, true, groupX25519MLKEM768, false, true},
		{"PQ preference still takes an offered X25519 share over a retry", all, map[tlsGroup][]byte{groupX25519: x}, true, groupX25519, false, true},
		{"only P-256 share", all, map[tlsGroup][]byte{groupP256: p}, false, groupP256, false, true},
		{"P-256 beats nothing", []tlsGroup{groupP256}, map[tlsGroup][]byte{groupP256: p}, false, groupP256, false, true},
		{"no share, X25519 supported", []tlsGroup{0x0018, groupX25519}, nil, false, groupX25519, true, true},
		{"no share, only P-256 supported", []tlsGroup{0x0018, groupP256}, nil, false, groupP256, true, true},
		{"no share, PQ preference retries for hybrid", all, nil, true, groupX25519MLKEM768, true, true},
		{"nothing supported", []tlsGroup{0x0018, 0x0019}, nil, false, 0, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			choice, ok := selectKeyShare(helloWithShares(tc.groups, tc.shares), tc.preferPQ)
			if ok != tc.wantOK || choice.group != tc.want || choice.retry != tc.wantRetry {
				t.Fatalf("got group=%#04x retry=%v ok=%v, want group=%#04x retry=%v ok=%v", uint16(choice.group), choice.retry, ok, uint16(tc.want), tc.wantRetry, tc.wantOK)
			}
			if ok && !choice.retry && choice.share == nil {
				t.Fatal("selected a share but returned no share bytes")
			}
		})
	}
}

func TestRecordKeyShareKeepsFirstPerGroup(t *testing.T) {
	first := bytes.Repeat([]byte{1}, x25519ShareLen)
	second := bytes.Repeat([]byte{2}, x25519ShareLen)
	ch := &ParsedClientHello{}
	ch.recordKeyShare(groupX25519, first)
	ch.recordKeyShare(groupX25519, second)
	ch.recordKeyShare(0x0018, []byte{9})
	if ch.keyShareCount != 3 {
		t.Fatalf("keyShareCount = %d, want 3", ch.keyShareCount)
	}
	if !bytes.Equal(ch.x25519Share, first) || !bytes.Equal(ch.X25519PubKey, first) {
		t.Fatal("a repeated group replaced the first share")
	}
}

func testKeyServer(t testing.TB) *Server {
	t.Helper()
	srv := &Server{x25519Pool: newX25519KeyPool(1)}
	t.Cleanup(srv.x25519Pool.Close)
	return srv
}

func TestCompleteKeyShareX25519(t *testing.T) {
	srv := testKeyServer(t)
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var kx serverKeyShare
	if alert, ok := srv.completeKeyShare(&kx, groupX25519, client.PublicKey().Bytes()); !ok {
		t.Fatalf("alert %d", alert)
	}
	serverPub, err := ecdh.X25519().NewPublicKey(kx.share())
	if err != nil {
		t.Fatal(err)
	}
	want, err := client.ECDH(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kx.secret(), want) {
		t.Fatal("server and client X25519 secrets differ")
	}
}

func TestCompleteKeyShareP256(t *testing.T) {
	srv := testKeyServer(t)
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var kx serverKeyShare
	if alert, ok := srv.completeKeyShare(&kx, groupP256, client.PublicKey().Bytes()); !ok {
		t.Fatalf("alert %d", alert)
	}
	if len(kx.share()) != p256ShareLen {
		t.Fatalf("server share is %d bytes, want %d", len(kx.share()), p256ShareLen)
	}
	serverPub, err := ecdh.P256().NewPublicKey(kx.share())
	if err != nil {
		t.Fatal(err)
	}
	want, err := client.ECDH(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kx.secret(), want) {
		t.Fatal("server and client P-256 secrets differ")
	}
}

func TestCompleteKeyShareX25519MLKEM768(t *testing.T) {
	srv := testKeyServer(t)
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	xClient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	share := append(dk.EncapsulationKey().Bytes(), xClient.PublicKey().Bytes()...)
	var kx serverKeyShare
	if alert, ok := srv.completeKeyShare(&kx, groupX25519MLKEM768, share); !ok {
		t.Fatalf("alert %d", alert)
	}
	if len(kx.share()) != mlkemHybridServerShareLen || len(kx.secret()) != maxSharedSecretLen {
		t.Fatalf("share %d bytes, secret %d bytes; want %d and %d", len(kx.share()), len(kx.secret()), mlkemHybridServerShareLen, maxSharedSecretLen)
	}
	mlkemSecret, err := dk.Decapsulate(kx.share()[:mlkem.CiphertextSize768])
	if err != nil {
		t.Fatal(err)
	}
	serverX, err := ecdh.X25519().NewPublicKey(kx.share()[mlkem.CiphertextSize768:])
	if err != nil {
		t.Fatal(err)
	}
	xSecret, err := xClient.ECDH(serverX)
	if err != nil {
		t.Fatal(err)
	}
	if want := append(mlkemSecret, xSecret...); !bytes.Equal(kx.secret(), want) {
		t.Fatal("hybrid secret is not mlkem_ss || x25519_ss")
	}
}

func TestCompleteKeyShareRejectsBadShares(t *testing.T) {
	srv := testKeyServer(t)
	badP256 := append([]byte{0x04}, make([]byte, p256ShareLen-1)...)
	badMLKEM := append(bytes.Repeat([]byte{0xff}, mlkem.EncapsulationKeySize768), make([]byte, x25519ShareLen)...)
	cases := []struct {
		name  string
		group tlsGroup
		share []byte
	}{
		{"X25519 short", groupX25519, make([]byte, x25519ShareLen-1)},
		{"X25519 low-order point", groupX25519, make([]byte, x25519ShareLen)},
		{"P-256 point not on curve", groupP256, badP256},
		{"P-256 compressed point", groupP256, make([]byte, 33)},
		{"hybrid 1215 bytes", groupX25519MLKEM768, make([]byte, mlkemHybridClientShareLen-1)},
		{"hybrid encapsulation key out of range", groupX25519MLKEM768, badMLKEM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var kx serverKeyShare
			alert, ok := srv.completeKeyShare(&kx, tc.group, tc.share)
			if ok || alert != alertIllegalParameter {
				t.Fatalf("ok=%v alert=%d, want illegal_parameter", ok, alert)
			}
		})
	}
}

func retryHello() *ParsedClientHello {
	ch := &ParsedClientHello{
		LegacyVersion:     0x0303,
		SessionID:         []byte{1, 2, 3},
		ServerName:        "retry.test",
		CipherSuites:      []uint16{0x1301, 0x1302},
		SupportedVersions: []uint16{0x0304},
		SupportedGroups:   []uint16{0x0018, uint16(groupP256)},
		SignatureSchemes:  []uint16{0x0403},
		ALPNProtos:        []string{"h2", "http/1.1"},
	}
	ch.Random[0] = 7
	return ch
}

func TestHelloRetryAcceptsOnlyAConsistentSecondHello(t *testing.T) {
	cs := NegotiateSuite([]uint16{0x1301})
	first := retryHello()
	retry, hrr := newHelloRetry(cs, groupP256, first, []byte("first hello"))
	if !bytes.Equal(hrr[6:38], helloRetryRequestRandom[:]) {
		t.Fatal("HelloRetryRequest does not carry the RFC 8446 random")
	}
	share := make([]byte, p256ShareLen)
	cases := []struct {
		name   string
		mutate func(*ParsedClientHello)
		ok     bool
	}{
		{"consistent", func(ch *ParsedClientHello) { ch.recordKeyShare(groupP256, share) }, true},
		{"no share for the selected group", func(ch *ParsedClientHello) { ch.recordKeyShare(groupX25519, make([]byte, 32)) }, false},
		{"no shares at all", func(*ParsedClientHello) {}, false},
		{"two shares", func(ch *ParsedClientHello) {
			ch.recordKeyShare(groupP256, share)
			ch.recordKeyShare(groupX25519, make([]byte, 32))
		}, false},
		{"cipher suites changed", func(ch *ParsedClientHello) {
			ch.recordKeyShare(groupP256, share)
			ch.CipherSuites = []uint16{0x1301}
		}, false},
		{"random changed", func(ch *ParsedClientHello) {
			ch.recordKeyShare(groupP256, share)
			ch.Random[0]++
		}, false},
		{"server name changed", func(ch *ParsedClientHello) {
			ch.recordKeyShare(groupP256, share)
			ch.ServerName = "other.test"
		}, false},
		{"ALPN changed", func(ch *ParsedClientHello) {
			ch.recordKeyShare(groupP256, share)
			ch.ALPNProtos = []string{"http/1.1"}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			second := retryHello()
			tc.mutate(second)
			got, alert, ok := retry.acceptSecondHello(second)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok && alert != alertIllegalParameter {
				t.Fatalf("alert %d, want illegal_parameter", alert)
			}
			if ok && !bytes.Equal(got, share) {
				t.Fatal("accepted hello returned the wrong share")
			}
		})
	}
}

func TestHelloRetryTranscriptPrefix(t *testing.T) {
	cs := NegotiateSuite([]uint16{0x1301})
	firstHello := []byte("client hello one")
	retry, hrr := newHelloRetry(cs, groupX25519, retryHello(), firstHello)
	h := cs.HashFn()
	h.Write(firstHello)
	want := append([]byte{tlsHSMessageHash, 0, 0, byte(cs.HashLen)}, h.Sum(nil)...)
	want = append(want, hrr...)
	if !bytes.Equal(retry.transcriptPrefix, want) {
		t.Fatal("transcript prefix is not message_hash(ClientHello1) || HelloRetryRequest")
	}
	ext := hrr[len(hrr)-6:]
	if !bytes.Equal(ext, []byte{0x00, 0x33, 0x00, 0x02, 0x00, 0x1d}) {
		t.Fatalf("HelloRetryRequest key_share extension %x, want selected_group X25519", ext)
	}
}

func TestBuildServerHelloCarriesGroup(t *testing.T) {
	pub := bytes.Repeat([]byte{0xab}, p256ShareLen)
	sh := BuildServerHello(make([]byte, 32), nil, 0x1301, uint16(groupP256), pub)
	tail := sh[len(sh)-(p256ShareLen+8):]
	want := []byte{0x00, 0x33, 0x00, byte(p256ShareLen + 4), 0x00, 0x17, 0x00, p256ShareLen}
	if !bytes.Equal(tail[:8], want) || !bytes.Equal(tail[8:], pub) {
		t.Fatalf("key_share extension %x", tail[:8])
	}
}
