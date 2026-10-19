//go:build linux && amd64

package core

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
)

func captureClientHello(tb testing.TB, cfg *tls.Config) []byte {
	tb.Helper()
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	go func() { _ = tls.Client(clientSide, cfg).Handshake() }()
	_ = serverSide.SetDeadline(wallDeadline(harnessIOTimeout))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(serverSide, hdr); err != nil {
		tb.Fatalf("read record header: %v", err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(serverSide, body); err != nil {
		tb.Fatalf("read record body: %v", err)
	}
	return body
}

func primeSessionCache(tb testing.TB, ts *testServer, cfg *tls.Config) {
	tb.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: harnessIOTimeout}, "tcp4", ts.addr, cfg)
	if err != nil {
		tb.Fatalf("handshake: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(harnessIOTimeout))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n"); err != nil {
		tb.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		tb.Fatal(err)
	}
}

func FuzzParseClientHello(f *testing.F) {
	ts := resumeTestServer(f, nil, nil)
	ts.srv.ensureTLSRuntime()
	resumeCfg := &tls.Config{InsecureSkipVerify: true, ServerName: ts.domain, MinVersion: tls.VersionTLS13, ClientSessionCache: tls.NewLRUClientSessionCache(1), NextProtos: []string{"http/1.1"}}
	primeSessionCache(f, ts, resumeCfg)
	f.Add(captureClientHello(f, resumeCfg))
	f.Add(captureClientHello(f, &tls.Config{ServerName: "a.test", NextProtos: []string{"h2", "http/1.1"}}))
	f.Add(captureClientHello(f, &tls.Config{ServerName: "b.test", MaxVersion: tls.VersionTLS12}))
	f.Add(captureClientHello(f, &tls.Config{ServerName: "c.test", CurvePreferences: []tls.CurveID{tls.CurveP256}}))
	f.Add(captureClientHello(f, &tls.Config{ServerName: "d.test", CurvePreferences: []tls.CurveID{tls.SecP384r1MLKEM1024, tls.X25519}}))
	f.Add([]byte{0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00})
	srv := ts.srv
	f.Fuzz(func(t *testing.T, data []byte) {
		var ch ParsedClientHello
		if err := ParseClientHello(data, &ch); err != nil {
			return
		}
		_ = ch.rejectsProtocolVersion()
		_ = ch.inappropriateFallback()
		for _, preferPQ := range []bool{false, true} {
			choice, ok := selectKeyShare(&ch, preferPQ)
			if !ok || choice.retry {
				continue
			}
			var kx serverKeyShare
			_, _ = srv.completeKeyShare(&kx, choice.group, choice.share)
			kx.wipe()
		}
		if cs := NegotiateSuite(ch.CipherSuites); cs != nil {
			session, _, _ := srv.acceptResumption(resumeRequest{ch: &ch, cs: cs, hello: data}, nil)
			clear(session.early)
			if choice, ok := selectKeyShare(&ch, false); ok {
				retry, _ := newHelloRetry(cs, choice.group, &ch, data)
				var second ParsedClientHello
				if ParseClientHello(data, &second) == nil {
					_, _, _ = retry.acceptSecondHello(&second)
				}
			}
		}
		ch.Reset()
		_ = ParseClientHello(data, &ch)
	})
}

func FuzzTLS12ClientKeyExchange(f *testing.F) {
	f.Add([]byte{0x10, 0x00, 0x00, 0x21, 0x20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	f.Add([]byte{0x10, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, msg []byte) {
		pub, ok := parseTLS12ClientKeyExchange(msg)
		if ok && len(pub) > len(msg) {
			t.Fatalf("public key %d longer than message %d", len(pub), len(msg))
		}
	})
}

func fuzzTrafficAEAD(tb testing.TB) *TrafficAEAD {
	tb.Helper()
	cs := FindSuiteByID(0x1301)
	if cs == nil {
		tb.Fatal("suite 0x1301 missing")
	}
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	a, err := NewTrafficAEAD(nil, secret, cs)
	if err != nil {
		tb.Fatal(err)
	}
	return a
}

func FuzzTLSRecordOpen(f *testing.F) {
	sealed := fuzzTrafficAEAD(f).Encrypt([]byte("hello\x17"))
	f.Add(append([]byte(nil), sealed...))
	f.Add([]byte{})
	f.Add(make([]byte, 15))
	f.Fuzz(func(t *testing.T, data []byte) {
		a := fuzzTrafficAEAD(t)
		pt, err := a.Decrypt(append([]byte(nil), data...))
		if err == nil && len(pt) > len(data) {
			t.Fatalf("plaintext %d longer than ciphertext %d", len(pt), len(data))
		}
	})
}
