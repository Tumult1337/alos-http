//go:build linux && amd64

package core

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func pskExtension(identities [][]byte, binders [][]byte) []byte {
	var ids []byte
	for _, id := range identities {
		ids = binary.BigEndian.AppendUint16(ids, uint16(len(id)))
		ids = append(ids, id...)
		ids = append(ids, 0, 0, 0, 0)
	}
	var bs []byte
	for _, b := range binders {
		bs = append(bs, byte(len(b)))
		bs = append(bs, b...)
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(ids)))
	out = append(out, ids...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(bs)))
	return append(out, bs...)
}

func TestParsePreSharedKey(t *testing.T) {
	binder := bytes.Repeat([]byte{7}, 32)
	cases := []struct {
		name       string
		ext        []byte
		identities int
		binders    int
	}{
		{"one identity", pskExtension([][]byte{{1, 2, 3}}, [][]byte{binder}), 1, 1},
		{"two identities", pskExtension([][]byte{{1}, {2}}, [][]byte{binder, binder}), 2, 2},
		{"binder count mismatch", pskExtension([][]byte{{1}, {2}}, [][]byte{binder}), 2, 1},
		{"empty identity", pskExtension([][]byte{{}}, [][]byte{binder}), 0, 0},
		{"short binder", pskExtension([][]byte{{1}}, [][]byte{binder[:31]}), 1, 0},
		{"truncated", pskExtension([][]byte{{1, 2, 3}}, [][]byte{binder})[:9], 0, 0},
		{"empty", nil, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ch ParsedClientHello
			parsePreSharedKey(&ch, tc.ext, 100)
			if ch.pskIdentities != tc.identities || ch.pskBinders != tc.binders {
				t.Fatalf("identities=%d binders=%d, want %d and %d", ch.pskIdentities, ch.pskBinders, tc.identities, tc.binders)
			}
			if tc.identities > 0 && tc.binders > 0 {
				ids := int(binary.BigEndian.Uint16(tc.ext))
				if want := 100 + 2 + ids; ch.pskBindersOffset != want {
					t.Fatalf("binders offset %d, want %d", ch.pskBindersOffset, want)
				}
				if !bytes.Equal(ch.pskBinder, binder) {
					t.Fatal("first binder not recorded")
				}
			}
		})
	}
}

func TestParsePSKModes(t *testing.T) {
	for _, tc := range []struct {
		data []byte
		want bool
	}{
		{[]byte{1, pskModeDHE}, true},
		{[]byte{2, 0, pskModeDHE}, true},
		{[]byte{1, 0}, false},
		{[]byte{2, pskModeDHE}, false},
		{nil, false},
	} {
		if got := parsePSKModes(tc.data); got != tc.want {
			t.Errorf("parsePSKModes(%x) = %v, want %v", tc.data, got, tc.want)
		}
	}
}

type resumeFixture struct {
	srv   *Server
	cs    *CipherSuiteConfig
	hello []byte
	ch    *ParsedClientHello
}

func newResumeFixture(t *testing.T, ticket *sessionTicket) *resumeFixture {
	t.Helper()
	tc, _ := newTestTicketCodec()
	srv := &Server{tickets: tc}
	cs := tls13SuiteByID(0x1301)
	ticket.createdMs = tc.nowMs()
	sealed := tc.seal(ticket)
	hello := []byte("client hello bytes up to the binders")
	ch := &ParsedClientHello{ServerName: "resume.test", pskDHE: true, pskIdentities: 1, pskBinders: 1, pskIdentity: sealed, pskBindersOffset: len(hello)}
	early := TLSExtractTo(cs.HashFn, cs.zeroHashInput, ticket.secret, nil)
	binderKey := cs.DeriveSecretTo(&cs.labelResBinder, early, cs.emptyTranscriptHash, nil)
	h := cs.HashFn()
	h.Write(hello)
	ch.pskBinder = cs.ComputeFinishedTo(binderKey, h.Sum(nil), nil)
	return &resumeFixture{srv: srv, cs: cs, hello: hello, ch: ch}
}

func resumableTicket() *sessionTicket {
	return &sessionTicket{tlsVersion: tlsVersion13, suite: 0x1301, secret: bytes.Repeat([]byte{3}, 32), sni: "resume.test"}
}

func TestAcceptResumption(t *testing.T) {
	cases := []struct {
		name         string
		requiredALPN string
		mutate       func(f *resumeFixture)
		ticket       func(*sessionTicket)
		resume       bool
		ok           bool
		alert        tlsAlert
	}{
		{"valid", "", nil, nil, true, true, 0},
		{"tampered binder", "", func(f *resumeFixture) { f.ch.pskBinder[0] ^= 1 }, nil, false, false, alertDecryptError},
		{"server name differs", "", func(f *resumeFixture) { f.ch.ServerName = "other.test" }, nil, false, true, 0},
		{"no psk_dhe_ke", "", func(f *resumeFixture) { f.ch.pskDHE = false }, nil, false, true, 0},
		{"tickets disabled", "", func(f *resumeFixture) { f.srv.tickets = nil }, nil, false, true, 0},
		{"identity and binder counts differ", "", func(f *resumeFixture) { f.ch.pskBinders = 2 }, nil, false, false, alertIllegalParameter},
		{"pre_shared_key not last", "", func(f *resumeFixture) { f.ch.pskNotLast = true }, nil, false, false, alertIllegalParameter},
		{"garbage identity", "", func(f *resumeFixture) { f.ch.pskIdentity = []byte("not a ticket at all") }, nil, false, true, 0},
		{"TLS 1.2 ticket", "", nil, func(tk *sessionTicket) { tk.tlsVersion = 0x0303 }, false, true, 0},
		{"SHA-384 ticket on a SHA-256 suite", "", nil, func(tk *sessionTicket) { tk.suite = 0x1302; tk.secret = bytes.Repeat([]byte{3}, 48) }, false, true, 0},
		{"different SHA-256 suite", "", nil, func(tk *sessionTicket) { tk.suite = 0x1303 }, true, true, 0},
		{"QUIC requires an h3 ticket", quicALPN, nil, nil, false, true, 0},
		{"QUIC accepts an h3 ticket", quicALPN, nil, func(tk *sessionTicket) { tk.alpn = quicALPN }, true, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ticket := resumableTicket()
			if tc.ticket != nil {
				tc.ticket(ticket)
			}
			f := newResumeFixture(t, ticket)
			if tc.mutate != nil {
				tc.mutate(f)
			}
			session, alert, ok := f.srv.acceptResumption(resumeRequest{ch: f.ch, cs: f.cs, requiredALPN: tc.requiredALPN, hello: f.hello}, nil)
			if ok != tc.ok || (session.early != nil) != tc.resume || (!ok && alert != tc.alert) {
				t.Fatalf("resume=%v ok=%v alert=%d, want resume=%v ok=%v alert=%d", session.early != nil, ok, alert, tc.resume, tc.ok, tc.alert)
			}
		})
	}
}

func TestAcceptResumptionBinderCoversRetryPrefix(t *testing.T) {
	f := newResumeFixture(t, resumableTicket())
	if _, _, ok := f.srv.acceptResumption(resumeRequest{ch: f.ch, cs: f.cs, transcriptPrefix: []byte("message_hash and HelloRetryRequest"), hello: f.hello}, nil); ok {
		t.Fatal("binder computed without the retry prefix verified with one")
	}
}

func TestNewSessionTicketMessage(t *testing.T) {
	tc, _ := newTestTicketCodec()
	srv := &Server{tickets: tc}
	cs := tls13SuiteByID(0x1301)
	p := newPendingTicket(cs, bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{8}, 32), "resume.test", "h2", nil)
	msg := srv.newSessionTicketMessage(p)
	if msg[0] != tlsHSNewSessionTicket || int(msg[1])<<16|int(msg[2])<<8|int(msg[3]) != len(msg)-4 {
		t.Fatalf("bad NewSessionTicket header %x", msg[:4])
	}
	body := msg[4:]
	if lifetime := binary.BigEndian.Uint32(body); lifetime != uint32(defaultTicketLifetime.Seconds()) && lifetime != uint32(testTicketLifetime.Seconds()) {
		t.Fatalf("ticket_lifetime %d", lifetime)
	}
	ageAdd := binary.BigEndian.Uint32(body[4:])
	if body[8] != 0 {
		t.Fatalf("ticket_nonce length %d, want 0", body[8])
	}
	n := int(binary.BigEndian.Uint16(body[9:]))
	ticket, ok := tc.open(body[11 : 11+n])
	if !ok || ticket.sni != "resume.test" || ticket.alpn != "h2" || ticket.ageAdd != ageAdd || ticket.suite != cs.ID || len(ticket.secret) != cs.HashLen {
		t.Fatalf("ticket did not carry the session: ok=%v %+v", ok, ticket)
	}
	if !bytes.Equal(body[11+n:], []byte{0, 0}) {
		t.Fatalf("extensions %x, want none", body[11+n:])
	}
	if p.resMaster != [64]byte{} {
		t.Fatal("resumption master secret not wiped after use")
	}
}
