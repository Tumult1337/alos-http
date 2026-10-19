//go:build linux && amd64

package core

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"testing"
)

func resumeTestServer(t testing.TB, mutate func(*Config), setup func(*Server)) *testServer {
	return newTestServer(t, testServerOptions{
		TLS:    true,
		Config: mutate,
		Setup:  setup,
		Routes: func(r *Router) {
			r.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
		},
	})
}

func resumeClientConfig(ts *testServer, cache tls.ClientSessionCache, alpn string, curves []tls.CurveID) *tls.Config {
	cfg := ts.tlsConfig(alpn)
	cfg.MinVersion = tls.VersionTLS13
	cfg.ClientSessionCache = cache
	cfg.CurvePreferences = curves
	return cfg
}

func connectAndGet(t *testing.T, ts *testServer, cfg *tls.Config) tls.ConnectionState {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: harnessIOTimeout}, "tcp4", ts.addr, cfg)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(harnessIOTimeout))
	if cfg.NextProtos[0] == "h2" {
		if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, make([]byte, 9)); err != nil {
			t.Fatalf("no SETTINGS after the handshake: %v", err)
		}
		return conn.ConnectionState()
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, body := readH1Response(t, bufio.NewReader(conn), "GET")
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	return conn.ConnectionState()
}

func TestTLS13ResumeGoClient(t *testing.T) {
	ts := resumeTestServer(t, nil, nil)
	cases := []struct {
		name   string
		alpn   string
		curves []tls.CurveID
	}{
		{"http/1.1", "http/1.1", nil},
		{"h2", "h2", nil},
		{"after a HelloRetryRequest", "http/1.1", []tls.CurveID{tls.SecP384r1MLKEM1024, tls.X25519}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := resumeClientConfig(ts, tls.NewLRUClientSessionCache(4), tc.alpn, tc.curves)
			if st := connectAndGet(t, ts, cfg); st.DidResume {
				t.Fatal("first connection claims resumption")
			}
			for i := 0; i < 3; i++ {
				if st := connectAndGet(t, ts, cfg); !st.DidResume {
					t.Fatalf("connection %d did not resume", i+2)
				}
			}
		})
	}
}

func TestTLS13ResumeDisabled(t *testing.T) {
	ts := resumeTestServer(t, func(c *Config) { c.SessionTicketsDisabled = true }, nil)
	cfg := resumeClientConfig(ts, tls.NewLRUClientSessionCache(4), "http/1.1", nil)
	connectAndGet(t, ts, cfg)
	if st := connectAndGet(t, ts, cfg); st.DidResume {
		t.Fatal("resumed with session tickets disabled")
	}
}

func TestTLS13ResumeAfterKeyRetirementFallsBackToFullHandshake(t *testing.T) {
	clock := newFakeClock(1)
	ts := resumeTestServer(t, nil, func(s *Server) { s.tickets = newTicketCodec(defaultTicketLifetime*4, clock.now) })
	cfg := resumeClientConfig(ts, tls.NewLRUClientSessionCache(4), "http/1.1", nil)
	connectAndGet(t, ts, cfg)
	clock.advance(ticketKeyRotation)
	if st := connectAndGet(t, ts, cfg); !st.DidResume {
		t.Fatal("ticket under the previous key did not resume")
	}
	clock.advance(2 * ticketKeyRotation)
	if st := connectAndGet(t, ts, cfg); st.DidResume {
		t.Fatal("ticket under a retired key resumed")
	}
	if st := connectAndGet(t, ts, cfg); !st.DidResume {
		t.Fatal("the full handshake's fresh ticket did not resume")
	}
}

func BenchmarkTLS13ServerFlightResumed(b *testing.B) {
	ts := resumeTestServer(b, nil, nil)
	cache := tls.NewLRUClientSessionCache(4)
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: ts.domain, MinVersion: tls.VersionTLS13, ClientSessionCache: cache, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"http/1.1"}}
	conn, err := tls.Dial("tcp4", ts.addr, cfg)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n")
	_, _ = conn.Read(make([]byte, 512))
	conn.Close()
	record := handshakeRecord(captureClientHello(b, cfg))
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
