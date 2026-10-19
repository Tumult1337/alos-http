//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

var statelessResetCID = []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18}

func referenceResetToken(key []byte, cid []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(cid)
	return mac.Sum(nil)[:quicStatelessResetTokenLen]
}

func shortTrigger(cid []byte, size int) []byte {
	pkt := make([]byte, size)
	for i := range pkt {
		pkt[i] = byte(i*7 + 3)
	}
	pkt[0] = quicFixedBit | 0x01
	copy(pkt[1:], cid)
	return pkt
}

func TestQUICStatelessResetToken(t *testing.T) {
	a, b := newQUICStatelessResetter(nil), newQUICStatelessResetter(nil)
	tok := a.token(statelessResetCID)
	if !bytes.Equal(tok[:], referenceResetToken(a.key[:], statelessResetCID)) {
		t.Fatal("token is not HMAC-SHA256(key, cid) truncated to 16 bytes")
	}
	if again := a.token(statelessResetCID); again != tok {
		t.Fatal("token is not deterministic for one connection ID")
	}
	other := append([]byte(nil), statelessResetCID...)
	other[7] ^= 1
	if a.token(other) == tok {
		t.Fatal("two connection IDs share a token")
	}
	if b.token(statelessResetCID) == tok || bytes.Equal(a.key, b.key) {
		t.Fatal("two servers derived the same key")
	}
}

func TestQUICStatelessResetKeySurvivesRestart(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	before := New(Config{QUICStatelessResetKey: key})
	after := New(Config{QUICStatelessResetKey: key})
	if before.quicResets.token(statelessResetCID) != after.quicResets.token(statelessResetCID) {
		t.Fatal("a configured key did not give the same token after a restart")
	}
	key[0] ^= 1
	if before.quicResets.token(statelessResetCID) != after.quicResets.token(statelessResetCID) {
		t.Fatal("mutating the caller's key slice changed the server's tokens")
	}
	got := before.quicResets.token(statelessResetCID)
	if !bytes.Equal(got[:], referenceResetToken(bytes.Repeat([]byte{0x5a}, 32), statelessResetCID)) {
		t.Fatal("configured key not used")
	}
}

func TestQUICStatelessResetPacketShape(t *testing.T) {
	cases := []struct {
		trigger int
		want    int
	}{
		{1200, quicStatelessResetMaxLen},
		{65, quicStatelessResetMaxLen},
		{64, 63},
		{43, 42},
		{30, 29},
		{22, 21},
		{21, 0},
		{10, 0},
	}
	for _, tc := range cases {
		r := newQUICStatelessResetter(nil)
		pkt := r.packet(statelessResetCID, tc.trigger)
		if len(pkt) != tc.want {
			t.Fatalf("trigger %d bytes: reset %d bytes, want %d", tc.trigger, len(pkt), tc.want)
		}
		if tc.want == 0 {
			continue
		}
		if len(pkt) >= tc.trigger || len(pkt) < quicMinShortPacketLen {
			t.Fatalf("reset of %d bytes for a %d-byte trigger breaks the size rules", len(pkt), tc.trigger)
		}
		if pkt[0]&quicLongHeaderBit != 0 || pkt[0]&quicFixedBit == 0 {
			t.Fatalf("first byte %#x is not a short header with the fixed bit", pkt[0])
		}
		if !bytes.Equal(pkt[len(pkt)-quicStatelessResetTokenLen:], referenceResetToken(r.key[:], statelessResetCID)) {
			t.Fatal("reset does not end in the connection's token")
		}
	}
	r := newQUICStatelessResetter(nil)
	first, second := r.packet(statelessResetCID, 1200), r.packet(statelessResetCID, 1200)
	if bytes.Equal(first[:len(first)-quicStatelessResetTokenLen], second[:len(second)-quicStatelessResetTokenLen]) {
		t.Fatal("unpredictable bits repeat between resets")
	}
}

func TestQUICStatelessResetRateLimit(t *testing.T) {
	for attempt := 0; attempt < 3; attempt++ {
		r := newQUICStatelessResetter(nil)
		before := turbo.UnixNano() / int64(time.Second)
		sent := 0
		for i := 0; i < 3*quicStatelessResetsPerSec; i++ {
			if r.packet(statelessResetCID, 1200) != nil {
				sent++
			}
		}
		if turbo.UnixNano()/int64(time.Second) != before {
			continue
		}
		if sent != quicStatelessResetsPerSec {
			t.Fatalf("sent %d resets in one second, want %d", sent, quicStatelessResetsPerSec)
		}
		if r.packet(statelessResetCID, 21) != nil {
			t.Fatal("tiny trigger produced a reset")
		}
		return
	}
	t.Fatal("could not measure inside one second")
}

func TestQUICTransportParamsCarryStatelessResetToken(t *testing.T) {
	srv := New(Config{})
	qc := newTestQUIC(srv)
	tp := quicBuildTransportParams(qc)
	var found []byte
	for i := 0; i < len(tp); {
		id, n := quicParseVarint(tp[i:])
		i += n
		l, n2 := quicParseVarint(tp[i:])
		i += n2
		if id == quicTPStatelessResetToken {
			found = tp[i : i+int(l)]
		}
		i += int(l)
	}
	want := srv.quicResets.token(qc.srcCID())
	if !bytes.Equal(found, want[:]) {
		t.Fatalf("stateless_reset_token parameter %x, want %x", found, want)
	}
	if reset := srv.statelessResetFor(shortTrigger(qc.srcCID(), 1200)); !bytes.Equal(reset[len(reset)-quicStatelessResetTokenLen:], want[:]) {
		t.Fatal("a reset for this connection's CID does not carry the advertised token")
	}
}
