//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
)

type recordingConn struct {
	net.Conn
	received bytes.Buffer
}

func (r *recordingConn) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.received.Write(p[:n])
	return n, err
}

func groupsTestServer(t *testing.T, preferPQ bool) *testServer {
	return newTestServer(t, testServerOptions{
		TLS:    true,
		Config: func(c *Config) { c.TLSPreferPostQuantum = preferPQ },
		Routes: func(r *Router) {
			r.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
		},
	})
}

func handshakeAndGet(t *testing.T, ts *testServer, curves []tls.CurveID) (tls.CurveID, bool) {
	t.Helper()
	raw, err := net.DialTimeout("tcp4", ts.addr, harnessIOTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(wallDeadline(harnessIOTimeout))
	rec := &recordingConn{Conn: raw}
	cfg := ts.tlsConfig("http/1.1")
	cfg.MinVersion = tls.VersionTLS13
	cfg.CurvePreferences = curves
	tc := tls.Client(rec, cfg)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, body := readH1Response(t, bufio.NewReader(tc), "GET")
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("got %d %q after the handshake", resp.StatusCode, body)
	}
	return tc.ConnectionState().CurveID, bytes.Contains(rec.received.Bytes(), helloRetryRequestRandom[:])
}

func TestTLSGroupsGoClient(t *testing.T) {
	classical := groupsTestServer(t, false)
	pq := groupsTestServer(t, true)
	cases := []struct {
		name      string
		ts        *testServer
		curves    []tls.CurveID
		want      tls.CurveID
		wantRetry bool
	}{
		{"X25519", classical, []tls.CurveID{tls.X25519}, tls.X25519, false},
		{"P-256", classical, []tls.CurveID{tls.CurveP256}, tls.CurveP256, false},
		{"X25519MLKEM768 only", classical, []tls.CurveID{tls.X25519MLKEM768}, tls.X25519MLKEM768, false},
		{"Go defaults get X25519", classical, nil, tls.X25519, false},
		{"Go defaults with PQ preference get the hybrid", pq, nil, tls.X25519MLKEM768, false},
		{"PQ preference takes an offered X25519 share", pq, []tls.CurveID{tls.X25519}, tls.X25519, false},
		{"unsupported share, P-256 supported: retry", classical, []tls.CurveID{tls.SecP384r1MLKEM1024, tls.CurveP256}, tls.CurveP256, true},
		{"unsupported share, X25519 supported: retry", classical, []tls.CurveID{tls.SecP384r1MLKEM1024, tls.X25519}, tls.X25519, true},
		{"unsupported share, X25519 supported, PQ preference: retry", pq, []tls.CurveID{tls.SecP384r1MLKEM1024, tls.X25519}, tls.X25519, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, retried := handshakeAndGet(t, tc.ts, tc.curves)
			if got != tc.want || retried != tc.wantRetry {
				t.Fatalf("negotiated %v (HelloRetryRequest %v), want %v (HelloRetryRequest %v)", got, retried, tc.want, tc.wantRetry)
			}
		})
	}
}

func TestTLSHelloRetryOverH2(t *testing.T) {
	ts := groupsTestServer(t, false)
	cfg := ts.tlsConfig("h2")
	cfg.CurvePreferences = []tls.CurveID{tls.SecP384r1MLKEM1024, tls.CurveP256}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: harnessIOTimeout}, "tcp4", ts.addr, cfg)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()
	if st := conn.ConnectionState(); st.NegotiatedProtocol != "h2" || st.CurveID != tls.CurveP256 {
		t.Fatalf("negotiated %q over %v, want h2 over P-256", st.NegotiatedProtocol, st.CurveID)
	}
}

func TestTLSSecondClientHelloMustMatchFirst(t *testing.T) {
	ts := groupsTestServer(t, false)
	first := captureClientHello(t, &tls.Config{ServerName: ts.domain, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.SecP384r1MLKEM1024, tls.CurveP256}})
	second := captureClientHello(t, &tls.Config{ServerName: ts.domain, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	conn, err := net.DialTimeout("tcp4", ts.addr, harnessIOTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(harnessIOTimeout))
	if _, err := conn.Write(handshakeRecord(first)); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatal(err)
	}
	hrr := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(conn, hrr); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hrr[6:38], helloRetryRequestRandom[:]) {
		t.Fatalf("first reply is not a HelloRetryRequest: %x", hrr[:min(len(hrr), 40)])
	}
	ccs := make([]byte, 6)
	if _, err := io.ReadFull(conn, ccs); err != nil || !bytes.Equal(ccs, []byte{tlsRecChangeCipher, 0x03, 0x03, 0x00, 0x01, 0x01}) {
		t.Fatalf("expected one compatibility change_cipher_spec after the HelloRetryRequest, got %x (%v)", ccs, err)
	}
	wire := append([]byte{tlsRecChangeCipher, 0x03, 0x03, 0x00, 0x01, 0x01}, handshakeRecord(second)...)
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if want := plainAlertRecord(alertIllegalParameter); !bytes.Equal(got, want) {
		t.Fatalf("server sent %x after a different second ClientHello, want %x", got, want)
	}
}

func benchmarkServerFlight(b *testing.B, preferPQ bool, client *tls.Config) {
	ts := newTestServer(b, testServerOptions{TLS: true, Config: func(c *Config) { c.TLSPreferPostQuantum = preferPQ }})
	client.ServerName = ts.domain
	client.MinVersion = tls.VersionTLS13
	record := handshakeRecord(captureClientHello(b, client))
	c := &epollConn{tls: true, plainBuf: acquireIOBuf(), readBuf: make([]byte, len(record))}
	b.ReportAllocs()
	for b.Loop() {
		c.readN = copy(c.readBuf, record)
		c.writeBuf = c.writeBuf[:0]
		c.phase = tlsConnPhaseClientHello
		if act := c.epollTLSClientHello(ts.srv); act != epollActionNeedRead || c.phase != tlsConnPhaseClientFinished {
			b.Fatalf("action %d phase %d", act, c.phase)
		}
		c.settleCipher()
	}
}

func BenchmarkTLS13ServerFlightX25519(b *testing.B) {
	benchmarkServerFlight(b, false, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519}})
}

func BenchmarkTLS13ServerFlightP256(b *testing.B) {
	benchmarkServerFlight(b, false, &tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP256}})
}

func BenchmarkTLS13ServerFlightMLKEM(b *testing.B) {
	benchmarkServerFlight(b, true, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}})
}
