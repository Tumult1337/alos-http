//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"hash"
	"io"
	"net"
	"strings"
	"testing"
)

const (
	testTLS12Suite  = 0xc02b
	tlsHSServerDone = 0x0e
)

type tls12HelloSpec struct {
	ems          bool
	renegExt     bool
	renegData    []byte
	renegSCSV    bool
	fallbackSCSV bool
	ticketExt    bool
	ticket       []byte
	sessionID    []byte
}

type tls12TestClient struct {
	t           *testing.T
	conn        net.Conn
	random      [32]byte
	transcript  hash.Hash
	reader      *tls12AEAD
	writer      *tls12AEAD
	serverHello []byte
	master      []byte
	ticket      []byte
}

func appendTestExt(dst []byte, typ uint16, data []byte) []byte {
	dst = append(dst, byte(typ>>8), byte(typ), byte(len(data)>>8), byte(len(data)))
	return append(dst, data...)
}

func buildTestTLS12Hello(serverName string, random [32]byte, spec tls12HelloSpec) []byte {
	suites := []uint16{testTLS12Suite}
	if spec.renegSCSV {
		suites = append(suites, tlsSCSVRenegotiation)
	}
	if spec.fallbackSCSV {
		suites = append(suites, tlsSCSVFallback)
	}
	body := []byte{0x03, 0x03}
	body = append(body, random[:]...)
	body = append(body, byte(len(spec.sessionID)))
	body = append(body, spec.sessionID...)
	body = append(body, byte(len(suites)*2>>8), byte(len(suites)*2))
	for _, s := range suites {
		body = append(body, byte(s>>8), byte(s))
	}
	body = append(body, 0x01, 0x00)

	sni := append([]byte{0x00}, appendLenPrefixed(nil, []byte(serverName))...)
	var ext []byte
	ext = appendTestExt(ext, 0x0000, appendLenPrefixed(nil, sni))
	ext = appendTestExt(ext, 0x000a, []byte{0x00, 0x02, 0x00, 0x1d})
	ext = appendTestExt(ext, 0x000b, []byte{0x01, 0x00})
	ext = appendTestExt(ext, 0x000d, []byte{0x00, 0x02, 0x04, 0x03})
	ext = appendTestExt(ext, 0x0010, []byte{0x00, 0x09, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'})
	if spec.ems {
		ext = appendTestExt(ext, tlsExtExtendedMasterSecret, nil)
	}
	if spec.ticketExt {
		ext = appendTestExt(ext, tlsExtSessionTicket, spec.ticket)
	}
	if spec.renegExt {
		ext = appendTestExt(ext, tlsExtRenegotiationInfo, append([]byte{byte(len(spec.renegData))}, spec.renegData...))
	}
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	return tls12Handshake(tlsHSClientHello, body)
}

func readTestRecord(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read record header: %v", err)
	}
	rec := make([]byte, 5+(int(hdr[3])<<8|int(hdr[4])))
	copy(rec, hdr)
	if _, err := io.ReadFull(conn, rec[5:]); err != nil {
		t.Fatalf("read record body: %v", err)
	}
	return hdr[0], rec
}

func dialTLS12Test(t *testing.T, ts *testServer, spec tls12HelloSpec) (*tls12TestClient, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", ts.addr, harnessIOTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(wallDeadline(harnessIOTimeout))
	c := &tls12TestClient{t: t, conn: conn, transcript: sha256.New()}
	if _, err := rand.Read(c.random[:]); err != nil {
		t.Fatal(err)
	}
	hello := buildTestTLS12Hello(ts.domain, c.random, spec)
	c.transcript.Write(hello)
	if _, err := conn.Write(AppendRecord(nil, tlsRecHandshake, hello)); err != nil {
		t.Fatal(err)
	}
	ct, rec := readTestRecord(t, conn)
	if ct != tlsRecHandshake {
		return nil, rec
	}
	c.serverHello = rec[5:]
	return c, nil
}

func (c *tls12TestClient) finish(ems bool) {
	t := c.t
	c.transcript.Write(c.serverHello)
	var serverPub []byte
	for {
		ct, rec := readTestRecord(t, c.conn)
		if ct != tlsRecHandshake {
			t.Fatalf("server flight carried record type %d: %x", ct, rec)
		}
		msg := rec[5:]
		c.transcript.Write(msg)
		if msg[0] == 0x0c {
			serverPub = msg[8 : 8+int(msg[7])]
		}
		if msg[0] == tlsHSServerDone {
			break
		}
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	pms, err := priv.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	cke := tls12Handshake(0x10, append([]byte{byte(len(pub))}, pub...))
	c.transcript.Write(cke)
	serverRandom := c.serverHello[6:38]
	var master []byte
	if ems {
		master = tls12ExtendedMasterSecret(sha256.New, pms, c.transcript.Sum(nil))
	} else {
		master = tls12MasterSecret(sha256.New, pms, c.random[:], serverRandom)
	}
	c.master = master
	c.installKeys()
	fin := tls12Handshake(tlsHSFinished, tls12Finished(sha256.New, master, "client finished", c.transcript.Sum(nil)))
	c.transcript.Write(fin)
	wire := AppendRecord(nil, tlsRecHandshake, cke)
	wire = AppendRecord(wire, tlsRecChangeCipher, []byte{0x01})
	wire = append(wire, c.writer.seal(tlsRecHandshake, fin)...)
	if _, err := c.conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	c.readServerFinish()
}

func (c *tls12TestClient) installKeys() {
	serverRandom := c.serverHello[6:38]
	cwk, swk, civ, siv := tls12KeyBlock(sha256.New, c.master, c.random[:], serverRandom, 16, 4)
	wAead, _ := newGCM(cwk)
	rAead, _ := newGCM(swk)
	c.writer = &tls12AEAD{aead: wAead, iv: civ}
	c.reader = &tls12AEAD{aead: rAead, iv: siv}
}

func (c *tls12TestClient) readServerFinish() {
	t := c.t
	ct, rec := readTestRecord(t, c.conn)
	if ct == tlsRecHandshake && rec[5] == tlsHSNewSessionTicket {
		c.transcript.Write(rec[5:])
		body := rec[9:]
		n := int(body[4])<<8 | int(body[5])
		c.ticket = bytes.Clone(body[6 : 6+n])
		ct, rec = readTestRecord(t, c.conn)
	}
	if ct != tlsRecChangeCipher {
		t.Fatalf("expected change_cipher_spec, got %x", rec)
	}
	_, rec = readTestRecord(t, c.conn)
	typ, pt, ok := c.reader.open(rec)
	want := tls12Handshake(tlsHSFinished, tls12Finished(sha256.New, c.master, "server finished", c.transcript.Sum(nil)))
	if !ok || typ != tlsRecHandshake || !bytes.Equal(pt, want) {
		t.Fatalf("server Finished did not verify (ok=%v type=%d)", ok, typ)
	}
	c.transcript.Write(pt)
}

func (c *tls12TestClient) resumeWith(master []byte) {
	c.master = master
	c.transcript.Write(c.serverHello)
	c.installKeys()
	c.readServerFinish()
	fin := tls12Handshake(tlsHSFinished, tls12Finished(sha256.New, c.master, "client finished", c.transcript.Sum(nil)))
	wire := AppendRecord(nil, tlsRecChangeCipher, []byte{0x01})
	wire = append(wire, c.writer.seal(tlsRecHandshake, fin)...)
	if _, err := c.conn.Write(wire); err != nil {
		c.t.Fatal(err)
	}
}

func (c *tls12TestClient) get() string {
	c.t.Helper()
	if _, err := c.conn.Write(c.writer.seal(tlsRecAppData, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))); err != nil {
		c.t.Fatal(err)
	}
	_, rec := readTestRecord(c.t, c.conn)
	typ, pt, ok := c.reader.open(rec)
	if !ok || typ != tlsRecAppData {
		c.t.Fatalf("response record ok=%v type=%d", ok, typ)
	}
	return string(pt)
}

func serverHelloHasExt(sh []byte, ext uint16) bool {
	exts := sh[4+2+32+1+2+1+2:]
	for len(exts) >= 4 {
		typ := uint16(exts[0])<<8 | uint16(exts[1])
		n := int(exts[2])<<8 | int(exts[3])
		if typ == ext {
			return true
		}
		exts = exts[4+n:]
	}
	return false
}

func TestTLS12EMSAndRenegotiationInfo(t *testing.T) {
	ts := groupsTestServer(t, false)
	cases := []struct {
		name      string
		spec      tls12HelloSpec
		wantEMS   bool
		wantReneg bool
	}{
		{"extended master secret", tls12HelloSpec{ems: true, renegExt: true}, true, true},
		{"classic master secret", tls12HelloSpec{renegExt: true}, false, true},
		{"renegotiation SCSV only", tls12HelloSpec{ems: true, renegSCSV: true}, true, true},
		{"no secure renegotiation signal", tls12HelloSpec{ems: true}, true, false},
		{"bare ClientHello", tls12HelloSpec{}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, alert := dialTLS12Test(t, ts, tc.spec)
			if c == nil {
				t.Fatalf("server answered with %x", alert)
			}
			if got := serverHelloHasExt(c.serverHello, tlsExtExtendedMasterSecret); got != tc.wantEMS {
				t.Fatalf("ServerHello extended_master_secret = %v, want %v", got, tc.wantEMS)
			}
			if got := serverHelloHasExt(c.serverHello, tlsExtRenegotiationInfo); got != tc.wantReneg {
				t.Fatalf("ServerHello renegotiation_info = %v, want %v", got, tc.wantReneg)
			}
			if !bytes.Equal(c.serverHello[6+24:6+32], []byte(tls13DowngradeSentinel)) {
				t.Fatalf("TLS 1.2 ServerHello random ends %x, want the downgrade sentinel", c.serverHello[30:38])
			}
			c.finish(tc.spec.ems)
			if resp := c.get(); !strings.HasPrefix(resp, "HTTP/1.1 200") || !strings.HasSuffix(resp, "ok") {
				t.Fatalf("response %q", resp)
			}
		})
	}
}

func TestTLS12HandshakeRejections(t *testing.T) {
	ts := groupsTestServer(t, false)
	cases := []struct {
		name string
		spec tls12HelloSpec
		want tlsAlert
	}{
		{"fallback SCSV from a TLS 1.2 client", tls12HelloSpec{ems: true, fallbackSCSV: true}, alertInappropriateFallback},
		{"renegotiated_connection in an initial handshake", tls12HelloSpec{renegExt: true, renegData: []byte{1, 2, 3}}, alertHandshakeFailure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := dialTLS12Test(t, ts, tc.spec)
			if c != nil {
				t.Fatal("server sent a ServerHello")
			}
			if want := plainAlertRecord(tc.want); !bytes.Equal(rec, want) {
				t.Fatalf("server sent %x, want %x", rec, want)
			}
		})
	}
}

func TestTLS12RenegotiationAttemptIsRefused(t *testing.T) {
	ts := groupsTestServer(t, false)
	c, _ := dialTLS12Test(t, ts, tls12HelloSpec{ems: true, renegExt: true})
	c.finish(true)
	var random [32]byte
	hello := buildTestTLS12Hello(ts.domain, random, tls12HelloSpec{ems: true, renegExt: true, renegData: make([]byte, 12)})
	if _, err := c.conn.Write(c.writer.seal(tlsRecHandshake, hello)); err != nil {
		t.Fatal(err)
	}
	_, rec := readTestRecord(t, c.conn)
	typ, pt, ok := c.reader.open(rec)
	if !ok || typ != tlsRecAlert || !bytes.Equal(pt, []byte{tlsAlertLevelFatal, byte(alertHandshakeFailure)}) {
		t.Fatalf("got ok=%v type=%d %x, want an encrypted handshake_failure alert", ok, typ, pt)
	}
	if n, err := c.conn.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("connection stayed open after the alert (n=%d err=%v)", n, err)
	}
}

func TestTLSDowngradeSentinelOnlyOnTLS12(t *testing.T) {
	ts := groupsTestServer(t, false)
	for _, tc := range []struct {
		name     string
		max      uint16
		sentinel bool
	}{{"TLS 1.2 client", tls.VersionTLS12, true}, {"TLS 1.3 client", tls.VersionTLS13, false}} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := net.DialTimeout("tcp4", ts.addr, harnessIOTimeout)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			_ = raw.SetDeadline(wallDeadline(harnessIOTimeout))
			rec := &recordingConn{Conn: raw}
			cfg := ts.tlsConfig("http/1.1")
			cfg.MaxVersion = tc.max
			tc2 := tls.Client(rec, cfg)
			if err := tc2.Handshake(); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			sh := rec.received.Bytes()[5:]
			if got := bytes.Equal(sh[6+24:6+32], []byte(tls13DowngradeSentinel)); got != tc.sentinel {
				t.Fatalf("ServerHello random %x: sentinel %v, want %v", sh[6:38], got, tc.sentinel)
			}
		})
	}
}

func TestTLS12TicketResumeGoClient(t *testing.T) {
	ts := groupsTestServer(t, false)
	for _, alpn := range []string{"http/1.1", "h2"} {
		t.Run(alpn, func(t *testing.T) {
			cfg := ts.tlsConfig(alpn)
			cfg.MaxVersion = tls.VersionTLS12
			cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
			if st := connectAndGet(t, ts, cfg); st.DidResume || st.Version != tls.VersionTLS12 {
				t.Fatalf("first connection: version %#x resumed %v", st.Version, st.DidResume)
			}
			for i := 0; i < 3; i++ {
				if st := connectAndGet(t, ts, cfg); !st.DidResume {
					t.Fatalf("connection %d did not resume", i+2)
				}
			}
		})
	}
}

func TestTLS12TicketsDisabled(t *testing.T) {
	ts := resumeTestServer(t, func(c *Config) { c.SessionTicketsDisabled = true }, nil)
	c, _ := dialTLS12Test(t, ts, tls12HelloSpec{ems: true, ticketExt: true})
	if serverHelloHasExt(c.serverHello, tlsExtSessionTicket) {
		t.Fatal("ServerHello promised a ticket with tickets disabled")
	}
	cfg := ts.tlsConfig("http/1.1")
	cfg.MaxVersion = tls.VersionTLS12
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	connectAndGet(t, ts, cfg)
	if st := connectAndGet(t, ts, cfg); st.DidResume {
		t.Fatal("resumed with session tickets disabled")
	}
}

func issueTLS12Session(t *testing.T, ts *testServer, ems bool) (*tls12TestClient, []byte) {
	t.Helper()
	c, _ := dialTLS12Test(t, ts, tls12HelloSpec{ems: ems, renegExt: true, ticketExt: true})
	if !serverHelloHasExt(c.serverHello, tlsExtSessionTicket) {
		t.Fatal("ServerHello did not promise a ticket")
	}
	c.finish(ems)
	if len(c.ticket) == 0 {
		t.Fatal("no NewSessionTicket before the server Finished")
	}
	return c, c.master
}

func TestTLS12TicketAbbreviatedHandshake(t *testing.T) {
	ts := groupsTestServer(t, false)
	first, master := issueTLS12Session(t, ts, true)
	sessionID := bytes.Repeat([]byte{0x42}, 32)
	c, _ := dialTLS12Test(t, ts, tls12HelloSpec{ems: true, renegExt: true, ticketExt: true, ticket: first.ticket, sessionID: sessionID})
	if c == nil {
		t.Fatal("ticket refused")
	}
	if got := c.serverHello[39 : 39+int(c.serverHello[38])]; !bytes.Equal(got, sessionID) {
		t.Fatalf("ServerHello session ID %x, want the client's %x (abbreviated handshake)", got, sessionID)
	}
	c.resumeWith(master)
	if resp := c.get(); !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("response %q after resumption", resp)
	}
	if len(c.ticket) == 0 {
		t.Fatal("abbreviated handshake did not renew the ticket")
	}
}

func TestTLS12TicketEMSMismatch(t *testing.T) {
	ts := groupsTestServer(t, false)
	t.Run("EMS session resumed without EMS is refused", func(t *testing.T) {
		first, _ := issueTLS12Session(t, ts, true)
		c, rec := dialTLS12Test(t, ts, tls12HelloSpec{renegExt: true, ticketExt: true, ticket: first.ticket, sessionID: bytes.Repeat([]byte{1}, 32)})
		if c != nil {
			t.Fatal("server answered with a ServerHello")
		}
		if want := plainAlertRecord(alertHandshakeFailure); !bytes.Equal(rec, want) {
			t.Fatalf("server sent %x, want %x", rec, want)
		}
	})
	t.Run("non-EMS session offered with EMS gets a full handshake", func(t *testing.T) {
		first, _ := issueTLS12Session(t, ts, false)
		sessionID := bytes.Repeat([]byte{2}, 32)
		c, _ := dialTLS12Test(t, ts, tls12HelloSpec{ems: true, renegExt: true, ticketExt: true, ticket: first.ticket, sessionID: sessionID})
		if c == nil {
			t.Fatal("ticket attempt was refused instead of falling back")
		}
		if c.serverHello[38] != 0 {
			t.Fatalf("ServerHello echoed a session ID; want a full handshake")
		}
		c.finish(true)
		if resp := c.get(); !strings.HasPrefix(resp, "HTTP/1.1 200") {
			t.Fatalf("response %q", resp)
		}
	})
	t.Run("forged ticket gets a full handshake", func(t *testing.T) {
		c, _ := dialTLS12Test(t, ts, tls12HelloSpec{ems: true, ticketExt: true, ticket: bytes.Repeat([]byte{9}, 120), sessionID: bytes.Repeat([]byte{3}, 32)})
		if c == nil || c.serverHello[38] != 0 {
			t.Fatal("forged ticket was not ignored")
		}
	})
}

func TestTLS12ConnectionCloseSendsCloseNotify(t *testing.T) {
	ts := groupsTestServer(t, false)
	c, alert := dialTLS12Test(t, ts, tls12HelloSpec{ems: true, renegExt: true})
	if c == nil {
		t.Fatalf("server answered with %x", alert)
	}
	c.finish(true)
	if _, err := c.conn.Write(c.writer.seal(tlsRecAppData, []byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))); err != nil {
		t.Fatal(err)
	}
	_, rec := readTestRecord(t, c.conn)
	if typ, pt, ok := c.reader.open(rec); !ok || typ != tlsRecAppData || !strings.HasPrefix(string(pt), "HTTP/1.1 200") {
		t.Fatalf("response ok=%v type=%d %q", ok, typ, pt)
	}
	ct, rec := readTestRecord(t, c.conn)
	typ, pt, ok := c.reader.open(rec)
	if ct != tlsRecAlert || !ok || typ != tlsRecAlert || !bytes.Equal(pt, []byte{tlsAlertLevelWarning, byte(alertCloseNotify)}) {
		t.Fatalf("after the response: record type %d ok=%v plaintext %x, want a warning close_notify", ct, ok, pt)
	}
	if n, err := c.conn.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("after close_notify: n=%d err=%v, want EOF", n, err)
	}
}
