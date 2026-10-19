//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
	"time"
)

const testTicketLifetime = 48 * time.Hour

func sampleTicket(createdMs int64) *sessionTicket {
	return &sessionTicket{
		tlsVersion: 0x0304,
		suite:      0x1301,
		createdMs:  createdMs,
		ageAdd:     0xdeadbeef,
		secret:     bytes.Repeat([]byte{0x5a}, 32),
		ems:        true,
		sni:        "resume.test",
		alpn:       "h2",
		clientCert: []byte{0x30, 0x82, 0x01, 0x02},
	}
}

func newTestTicketCodec() (*ticketCodec, *fakeClock) {
	clock := newFakeClock(int64(1000 * time.Hour))
	return newTicketCodec(testTicketLifetime, clock.now), clock
}

func TestTicketKeysRoundTrip(t *testing.T) {
	tc, _ := newTestTicketCodec()
	want := sampleTicket(tc.nowMs())
	got, ok := tc.open(tc.seal(want))
	if !ok {
		t.Fatal("fresh ticket did not open")
	}
	if got.tlsVersion != want.tlsVersion || got.suite != want.suite || got.createdMs != want.createdMs || got.ageAdd != want.ageAdd ||
		!bytes.Equal(got.secret, want.secret) || got.ems != want.ems || got.sni != want.sni || got.alpn != want.alpn || !bytes.Equal(got.clientCert, want.clientCert) {
		t.Fatalf("round trip changed the ticket: %+v", got)
	}
}

func TestTicketKeysRotation(t *testing.T) {
	tc, clock := newTestTicketCodec()
	issued := tc.seal(sampleTicket(tc.nowMs()))
	clock.advance(ticketKeyRotation)
	if _, ok := tc.open(issued); !ok {
		t.Fatal("ticket from the previous key was rejected after one rotation")
	}
	fresh := tc.seal(sampleTicket(tc.nowMs()))
	if fresh[0] == issued[0] {
		t.Fatal("rotation did not change the key ID")
	}
	clock.advance(ticketKeyRotation)
	if _, ok := tc.open(issued); ok {
		t.Fatal("ticket opened two rotations after its key was retired")
	}
	if _, ok := tc.open(fresh); !ok {
		t.Fatal("ticket from the previous key was rejected")
	}
}

func TestTicketKeysRejectTampering(t *testing.T) {
	tc, _ := newTestTicketCodec()
	sealed := tc.seal(sampleTicket(tc.nowMs()))
	for _, i := range []int{0, 1, ticketPrefixLen, len(sealed) / 2, len(sealed) - 1} {
		bad := bytes.Clone(sealed)
		bad[i] ^= 0x01
		if _, ok := tc.open(bad); ok {
			t.Fatalf("ticket with byte %d flipped opened", i)
		}
	}
	for _, n := range []int{0, 1, ticketPrefixLen, len(sealed) - 1} {
		if _, ok := tc.open(sealed[:n]); ok {
			t.Fatalf("ticket truncated to %d bytes opened", n)
		}
	}
	other, _ := newTestTicketCodec()
	if _, ok := other.open(sealed); ok {
		t.Fatal("ticket opened under another server's keys")
	}
}

func TestTicketKeysLifetime(t *testing.T) {
	tc, clock := newTestTicketCodec()
	now := tc.nowMs()
	cases := []struct {
		name      string
		createdMs int64
		ok        bool
	}{
		{"just issued", now, true},
		{"at the lifetime", now - testTicketLifetime.Milliseconds(), true},
		{"past the lifetime", now - testTicketLifetime.Milliseconds() - 1, false},
		{"from the future", now + 1, false},
	}
	for _, c := range cases {
		if _, ok := tc.open(tc.seal(sampleTicket(c.createdMs))); ok != c.ok {
			t.Errorf("%s: opened=%v, want %v", c.name, ok, c.ok)
		}
	}
	short := newTicketCodec(time.Hour, clock.now)
	sealed := short.seal(sampleTicket(short.nowMs()))
	clock.advance(time.Hour + time.Millisecond)
	if _, ok := short.open(sealed); ok {
		t.Fatal("ticket outlived a one-hour lifetime")
	}
}

func TestParseTicketPlaintextRejectsMalformed(t *testing.T) {
	good := appendTicketPlaintext(nil, sampleTicket(1))
	if _, ok := parseTicketPlaintext(good); !ok {
		t.Fatal("well-formed plaintext rejected")
	}
	for n := 0; n < len(good); n++ {
		if _, ok := parseTicketPlaintext(good[:n]); ok {
			t.Fatalf("plaintext truncated to %d bytes parsed", n)
		}
	}
	if _, ok := parseTicketPlaintext(append(bytes.Clone(good), 0)); ok {
		t.Fatal("plaintext with trailing bytes parsed")
	}
	wrongVersion := bytes.Clone(good)
	wrongVersion[0] = ticketFormatVersion + 1
	if _, ok := parseTicketPlaintext(wrongVersion); ok {
		t.Fatal("unknown format version parsed")
	}
	noSecret := sampleTicket(1)
	noSecret.secret = nil
	if _, ok := parseTicketPlaintext(appendTicketPlaintext(nil, noSecret)); ok {
		t.Fatal("ticket without a secret parsed")
	}
}

func TestTicketSealRejectsOversizedFields(t *testing.T) {
	tc, _ := newTestTicketCodec()
	big := sampleTicket(tc.nowMs())
	big.secret = make([]byte, maxTicketSecretLen+1)
	if tc.seal(big) != nil {
		t.Fatal("sealed a ticket with an oversized secret")
	}
}

func FuzzTicketOpen(f *testing.F) {
	tc, _ := newTestTicketCodec()
	f.Add(tc.seal(sampleTicket(tc.nowMs())))
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, ticket []byte) {
		tc.open(ticket)
		parseTicketPlaintext(ticket)
	})
}

func TestTicketKeysIdleGapRetiresBothKeys(t *testing.T) {
	tc, clock := newTestTicketCodec()
	issued := tc.seal(sampleTicket(tc.nowMs()))
	clock.advance(2 * ticketKeyRotation)
	if _, ok := tc.open(issued); ok {
		t.Fatal("ticket opened after two rotation periods passed without any traffic")
	}
}
