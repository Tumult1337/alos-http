//go:build linux && amd64

package core

import (
	"bytes"
	"testing"

	"github.com/guno1928/alosmap"
)

func newCIDTestPeer(t *testing.T, peerLimit uint64) *quicTestPeer {
	p := newQUICTestPeer(t, nil)
	p.qc.connMap = alosmap.NewTyped[[20]byte, *QUICConn]()
	p.qc.peerCIDLimit = peerLimit
	return p
}

func (p *quicTestPeer) routesTo(cid []byte) bool {
	qc, ok := p.qc.connMap.Load(quicCIDKey(cid))
	return ok && qc == p.qc
}

func TestQUICIssuesConnectionIDsUpToPeerLimit(t *testing.T) {
	for _, tc := range []struct {
		peerLimit uint64
		want      int
	}{{0, 1}, {2, 1}, {3, 2}, {4, 3}, {1000, quicMaxIssuedCIDs - 1}} {
		p := newCIDTestPeer(t, tc.peerLimit)
		p.qc.issueConnectionIDs()
		got := p.awaitSent("NEW_CONNECTION_ID", func(f quicSentFrames) bool { return len(f.newCIDs) >= tc.want })
		if len(got.newCIDs) != tc.want {
			t.Fatalf("peer limit %d: issued %d IDs, want %d", tc.peerLimit, len(got.newCIDs), tc.want)
		}
		seen := map[string]bool{string(p.qc.srcCID()): true}
		for i, f := range got.newCIDs {
			if f.seq != uint64(i+1) || f.retirePT != 0 || len(f.connID) != quicConnIDLen {
				t.Fatalf("NEW_CONNECTION_ID %d = %+v", i, f)
			}
			if seen[string(f.connID)] {
				t.Fatal("issued a duplicate connection ID")
			}
			seen[string(f.connID)] = true
			if tok := p.srv.quicResets.token(f.connID); f.resetToken != tok {
				t.Fatal("NEW_CONNECTION_ID token is not the stateless reset token for that ID")
			}
			if !p.routesTo(f.connID) {
				t.Fatalf("issued ID %x does not route to the connection", f.connID)
			}
		}
		p.qc.issueConnectionIDs()
		if again := p.sent(); len(again.newCIDs) != tc.want {
			t.Fatalf("re-issuing sent %d frames, want none beyond %d", len(again.newCIDs), tc.want)
		}
	}
}

func TestQUICRetireConnectionIDIssuesReplacement(t *testing.T) {
	p := newCIDTestPeer(t, 3)
	p.qc.issueConnectionIDs()
	first := p.awaitSent("NEW_CONNECTION_ID", func(f quicSentFrames) bool { return len(f.newCIDs) == 2 })
	retired := first.newCIDs[0]
	p.send(quicAppendRetireConnIDFrame(nil, retired.seq))
	got := p.awaitSent("replacement", func(f quicSentFrames) bool { return len(f.newCIDs) == 3 })
	if p.routesTo(retired.connID) {
		t.Fatal("retired connection ID still routes to the connection")
	}
	if r := got.newCIDs[2]; r.seq != 3 || !p.routesTo(r.connID) {
		t.Fatalf("replacement = %+v", r)
	}
	p.send(quicAppendRetireConnIDFrame(nil, retired.seq))
	if again := p.pump(); len(again.newCIDs) != 3 || len(again.closes) != 0 {
		t.Fatalf("retiring twice: %d IDs, closes %+v", len(again.newCIDs), again.closes)
	}
	p.send(quicAppendRetireConnIDFrame(nil, 0))
	p.awaitSent("replacement for seq 0", func(f quicSentFrames) bool { return len(f.newCIDs) == 4 })
	p.qc.cidMu.Lock()
	active := append([]quicIssuedCID(nil), p.qc.issued...)
	p.qc.cidMu.Unlock()
	if len(active) != p.qc.issuedLimit() {
		t.Fatalf("%d IDs active after retiring seq 0, want %d", len(active), p.qc.issuedLimit())
	}
	for _, c := range active {
		if c.seq == 0 || c.seq == retired.seq {
			t.Fatalf("retired seq %d is still active", c.seq)
		}
	}

	p.qc.unregisterIssuedCIDs(p.qc.connMap)
	for _, f := range p.sent().newCIDs {
		if p.routesTo(f.connID) {
			t.Fatalf("ID %x still routed after the connection closed", f.connID)
		}
	}
}

func TestQUICRetireConnectionIDErrors(t *testing.T) {
	p := newCIDTestPeer(t, 2)
	p.qc.issueConnectionIDs()
	p.send(quicAppendRetireConnIDFrame(nil, 7))
	p.awaitClose(quicErrProtocolViolation)

	p = newCIDTestPeer(t, 2)
	p.qc.issueConnectionIDs()
	got := p.awaitSent("NEW_CONNECTION_ID", func(f quicSentFrames) bool { return len(f.newCIDs) == 1 })
	copy(p.qc.rxDCID[:], got.newCIDs[0].connID)
	p.send(quicAppendRetireConnIDFrame(nil, got.newCIDs[0].seq))
	p.awaitClose(quicErrProtocolViolation)
}

func peerNewCID(seq, retirePT uint64, fill byte) []byte {
	cid := bytes.Repeat([]byte{fill}, quicConnIDLen)
	var tok [quicStatelessResetTokenLen]byte
	tok[0] = fill
	return quicAppendNewConnIDFrame(nil, seq, retirePT, cid, tok)
}

func TestQUICPeerNewConnectionIDRetirePriorToSwitchesDestination(t *testing.T) {
	p := newCIDTestPeer(t, 2)
	original := append([]byte(nil), p.qc.dstCID()...)
	p.send(peerNewCID(1, 1, 0x77))
	got := p.awaitSent("RETIRE_CONNECTION_ID", func(f quicSentFrames) bool { return len(f.retires) > 0 })
	if got.retires[0] != 0 {
		t.Fatalf("retired seq %d, want 0", got.retires[0])
	}
	if !bytes.Equal(p.qc.dstCID(), bytes.Repeat([]byte{0x77}, quicConnIDLen)) || p.qc.dstCIDSeq != 1 {
		t.Fatalf("destination ID %x seq %d, want the new ID", p.qc.dstCID(), p.qc.dstCIDSeq)
	}
	last := got.dcids[len(got.dcids)-1]
	if !bytes.Equal(last, bytes.Repeat([]byte{0x77}, quicConnIDLen)) || bytes.Equal(last, original) {
		t.Fatalf("packet after the switch went to %x", last)
	}

	p.send(peerNewCID(0, 0, 0x55))
	got = p.awaitSent("RETIRE for a stale sequence", func(f quicSentFrames) bool { return len(f.retires) > 1 })
	if got.retires[1] != 0 || len(p.qc.peerCIDs) != 1 {
		t.Fatalf("stale NEW_CONNECTION_ID: retires %v, stored %d", got.retires, len(p.qc.peerCIDs))
	}
	p.expectOpen()
}

func TestQUICPeerNewConnectionIDRules(t *testing.T) {
	cases := []struct {
		name   string
		frames [][]byte
		code   uint64
	}{
		{"beyond active_connection_id_limit", [][]byte{peerNewCID(1, 0, 1), peerNewCID(2, 0, 2)}, quicErrConnIDLimit},
		{"sequence reused with a different ID", [][]byte{peerNewCID(1, 0, 1), peerNewCID(1, 0, 2)}, quicErrProtocolViolation},
		{"retire prior to beyond sequence", [][]byte{peerNewCID(1, 2, 1)}, quicErrFrameEncoding},
		{"zero-length ID", [][]byte{quicAppendNewConnIDFrame(nil, 1, 0, nil, [16]byte{})}, quicErrFrameEncoding},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newCIDTestPeer(t, 2)
			for _, f := range tc.frames {
				p.send(f)
			}
			p.awaitClose(tc.code)
		})
	}
	p := newCIDTestPeer(t, 2)
	p.send(peerNewCID(1, 0, 1))
	p.send(peerNewCID(1, 0, 1))
	p.expectOpen()
	if len(p.qc.peerCIDs) != 2 {
		t.Fatalf("duplicate NEW_CONNECTION_ID stored %d IDs, want 2", len(p.qc.peerCIDs))
	}
}

func TestQUICActiveConnIDLimitTransportParam(t *testing.T) {
	var ch ParsedClientHello
	tp := quicAppendVarint(nil, quicTPActiveConnIDLimit)
	tp = quicAppendVarint(tp, 1)
	tp = quicAppendVarint(tp, 7)
	parseQUICTransportParams(&ch, tp)
	if ch.ActiveConnIDLimit != 7 {
		t.Fatalf("active_connection_id_limit parsed as %d", ch.ActiveConnIDLimit)
	}
	qc := newTestQUIC(New(Config{}))
	if got, ok := decodeQUICTP(quicBuildTransportParams(qc), quicTPActiveConnIDLimit); !ok || got != quicLocalActiveCIDLimit {
		t.Fatalf("advertised active_connection_id_limit %d (ok=%v)", got, ok)
	}
}
