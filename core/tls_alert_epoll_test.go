//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
)

func plainAlertRecord(desc tlsAlert) []byte {
	return []byte{tlsRecAlert, 0x03, 0x03, 0x00, 0x02, tlsAlertLevelFatal, byte(desc)}
}

func handshakeRecord(msg []byte) []byte {
	return AppendRecord(nil, tlsRecHandshake, msg)
}

func exchangeRaw(t *testing.T, addr string, wire []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", addr, harnessIOTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(harnessIOTimeout))
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("server did not close cleanly: %v (read %x)", err, got)
	}
	return got
}

func expectRemoteAlert(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want remote %q alert", want)
	}
	if !strings.Contains(err.Error(), "remote error: tls: "+want) {
		t.Fatalf("got %v, want remote %q alert", err, want)
	}
}

func TestTLSHandshakeAlertsGoClient(t *testing.T) {
	ts := newTestServer(t, testServerOptions{TLS: true})
	cases := []struct {
		name   string
		mutate func(*tls.Config)
		want   string
	}{
		{"no common ALPN", func(c *tls.Config) { c.NextProtos = []string{"spdy/3"} }, "no application protocol"},
		{"TLS 1.3 with no supported group", func(c *tls.Config) {
			c.MinVersion = tls.VersionTLS13
			c.CurvePreferences = []tls.CurveID{tls.CurveP384}
		}, "handshake failure"},
		{"TLS 1.2 without a usable suite", func(c *tls.Config) {
			c.MaxVersion = tls.VersionTLS12
			c.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
		}, "handshake failure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ts.tlsConfig("http/1.1")
			tc.mutate(cfg)
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: harnessIOTimeout}, "tcp4", ts.addr, cfg)
			if err == nil {
				conn.Close()
			}
			expectRemoteAlert(t, err, tc.want)
		})
	}
}

func TestTLSClientHelloAlertsRaw(t *testing.T) {
	ts := newTestServer(t, testServerOptions{TLS: true})
	tls11Hello := captureClientHello(t, &tls.Config{ServerName: ts.domain, MaxVersion: tls.VersionTLS12})
	tls11Hello[4], tls11Hello[5] = 0x03, 0x02
	cases := []struct {
		name string
		wire []byte
		want []byte
	}{
		{"oversized record", []byte{tlsRecHandshake, 0x03, 0x01, 0xff, 0xff}, plainAlertRecord(alertRecordOverflow)},
		{"truncated ClientHello body", handshakeRecord([]byte{0x01, 0x00, 0x00, 0x02, 0x03, 0x03}), plainAlertRecord(alertDecodeError)},
		{"not a ClientHello", handshakeRecord([]byte{0x02, 0x00, 0x00, 0x02, 0x03, 0x03}), plainAlertRecord(alertDecodeError)},
		{"TLS 1.1 only", handshakeRecord(tls11Hello), plainAlertRecord(alertProtocolVersion)},
		{"plain HTTP on the TLS port", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), nil},
		{"non-handshake first record", []byte{tlsRecAlert, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exchangeRaw(t, ts.addr, tc.wire); !bytes.Equal(got, tc.want) {
				t.Fatalf("server sent %x, want %x", got, tc.want)
			}
		})
	}
}

func TestTLSRecordAlertsAfterHandshake(t *testing.T) {
	ts := newTestServer(t, testServerOptions{TLS: true})
	forged := append([]byte{0x17, 0x03, 0x03, 0x00, 0x20}, bytes.Repeat([]byte{0xa5}, 0x20)...)
	injections := []struct {
		name   string
		wire   []byte
		want12 string
		want13 string
	}{
		{"forged ciphertext", forged, "bad record MAC", "bad record MAC"},
		{"oversized record", []byte{0x17, 0x03, 0x03, 0xff, 0xff}, "record overflow", "record overflow"},
		{"handshake record after the handshake", handshakeRecord([]byte{0x00, 0x00, 0x00, 0x00}), "handshake failure", "unexpected message"},
	}
	versions := []struct {
		name    string
		version uint16
	}{{"TLS 1.2", tls.VersionTLS12}, {"TLS 1.3", tls.VersionTLS13}}
	for _, v := range versions {
		for _, alpn := range []string{"http/1.1", "h2"} {
			for _, inj := range injections {
				t.Run(v.name+"/"+alpn+"/"+inj.name, func(t *testing.T) {
					raw, err := net.DialTimeout("tcp4", ts.addr, harnessIOTimeout)
					if err != nil {
						t.Fatal(err)
					}
					defer raw.Close()
					_ = raw.SetDeadline(wallDeadline(harnessIOTimeout))
					cfg := ts.tlsConfig(alpn)
					cfg.MinVersion, cfg.MaxVersion = v.version, v.version
					tc := tls.Client(raw, cfg)
					if err := tc.Handshake(); err != nil {
						t.Fatalf("handshake: %v", err)
					}
					if _, err := raw.Write(inj.wire); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 4096)
					for {
						if _, err = tc.Read(buf); err != nil {
							break
						}
					}
					want := inj.want13
					if v.version == tls.VersionTLS12 {
						want = inj.want12
					}
					expectRemoteAlert(t, err, want)
				})
			}
		}
	}
}

func TestCheckFinishedMessage(t *testing.T) {
	expected := bytes.Repeat([]byte{0x42}, 32)
	finished := func(verify []byte) []byte {
		return append([]byte{tlsHSFinished, 0x00, 0x00, byte(len(verify))}, verify...)
	}
	wrongLen := finished(expected)
	wrongLen[3]--
	cases := []struct {
		name string
		msg  []byte
		ok   bool
		want tlsAlert
	}{
		{"valid", finished(expected), true, 0},
		{"short", []byte{tlsHSFinished, 0x00}, false, alertDecodeError},
		{"wrong message type", append([]byte{0x0f}, finished(expected)[1:]...), false, alertUnexpectedMessage},
		{"length mismatch", wrongLen, false, alertDecodeError},
		{"wrong verify data", finished(bytes.Repeat([]byte{0x43}, 32)), false, alertDecryptError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &epollConn{phase: tlsConnPhaseClientHello}
			act, ok := c.checkFinishedMessage(tc.msg, expected)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if tc.ok {
				if len(c.writeBuf) != 0 {
					t.Fatalf("valid Finished wrote %x", c.writeBuf)
				}
				return
			}
			if act != epollActionCloseAfterFlush {
				t.Fatalf("action = %d, want close-after-flush", act)
			}
			if want := plainAlertRecord(tc.want); !bytes.Equal(c.writeBuf, want) {
				t.Fatalf("wrote %x, want %x", c.writeBuf, want)
			}
		})
	}
}

func TestFailTLSEncryptsAfterServerFinished(t *testing.T) {
	cs := NegotiateSuite([]uint16{0x1301})
	secret := bytes.Repeat([]byte{0x11}, cs.HashLen)
	writer, err := NewTrafficAEAD(cs.HashFn, secret, cs)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewTrafficAEAD(cs.HashFn, secret, cs)
	if err != nil {
		t.Fatal(err)
	}
	c := &epollConn{phase: tlsConnPhaseClientFinished, appWriter: writer}
	if act := c.failTLS(alertDecryptError); act != epollActionCloseAfterFlush {
		t.Fatalf("action = %d, want close-after-flush", act)
	}
	ct, payload, _, ok, err := nextTLSRecord(c.writeBuf)
	if err != nil || !ok || ct != 0x17 {
		t.Fatalf("record ct=%#x ok=%v err=%v, want application_data wrapper", ct, ok, err)
	}
	pt, err := reader.Decrypt(payload)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if want := []byte{tlsAlertLevelFatal, byte(alertDecryptError), tlsRecAlert}; !bytes.Equal(pt, want) {
		t.Fatalf("inner plaintext %x, want %x", pt, want)
	}
}
