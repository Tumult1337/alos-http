//go:build linux && amd64

package core

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const fpFixTestTimeout = 2 * time.Second

func fpFixRawTLSBackend(t *testing.T, reply []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hello := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Unix(0, turbo.UnixNano()+int64(fpFixTestTimeout)))
				if _, rerr := c.Read(hello); rerr != nil {
					return
				}
				if _, werr := c.Write(reply); werr != nil {
					return
				}
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func fpFixTLSRecord(contentType byte, body []byte) []byte {
	return append([]byte{contentType, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}, body...)
}

func fpFixHandshakeMsg(msgType byte, body []byte) []byte {
	return append([]byte{msgType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func fpFixServerHello(random [32]byte, suite uint16, exts []byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, random[:]...)
	body = append(body, 0, byte(suite>>8), byte(suite), 0)
	if exts != nil {
		body = append(body, byte(len(exts)>>8), byte(len(exts)))
		body = append(body, exts...)
	}
	return fpFixHandshakeMsg(tlsHSServerHello, body)
}

func fpFixDoTLS(t *testing.T, reply []byte) error {
	t.Helper()
	addr := fpFixRawTLSBackend(t, reply)
	c, err := fpNew(fpConfig{Loops: 1, RequestTimeout: fpFixTestTimeout})
	if err != nil {
		t.Fatalf("fpNew: %v", err)
	}
	defer c.Close()
	_, err = c.Do(&fpRequest{Scheme: "https", Authority: addr, Method: "GET", Path: "/", SkipVerify: true})
	return err
}

func TestFPFixTLS13AppDataBeforeServerHelloFailsCleanly(t *testing.T) {
	reply := fpFixTLSRecord(tlsRecAppData, make([]byte, 16))
	if err := fpFixDoTLS(t, reply); err == nil {
		t.Fatal("an encrypted record before ServerHello was accepted")
	}
}

func TestFPFixTLSServerHelloOf34BytesFailsCleanly(t *testing.T) {
	body := append([]byte{0x03, 0x03}, make([]byte, 32)...)
	reply := fpFixTLSRecord(tlsRecHandshake, fpFixHandshakeMsg(tlsHSServerHello, body))
	if err := fpFixDoTLS(t, reply); err == nil {
		t.Fatal("a 34-byte ServerHello was accepted")
	}
}

func TestFPFixTLS12CipherRecordsBeforeClientFlightFailCleanly(t *testing.T) {
	hello := fpFixTLSRecord(tlsRecHandshake, fpFixServerHello([32]byte{}, suite12RSAAES128, nil))
	for _, tc := range []struct {
		name  string
		after []byte
	}{
		{"ccs then handshake", append(fpFixTLSRecord(tlsRecChangeCipher, []byte{1}), fpFixTLSRecord(tlsRecHandshake, make([]byte, 32))...)},
		{"application data", fpFixTLSRecord(tlsRecAppData, make([]byte, 32))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := fpFixDoTLS(t, append(append([]byte(nil), hello...), tc.after...)); err == nil {
				t.Fatal("a protected record before the key exchange was accepted")
			}
		})
	}
}

func TestFPFixLoopSurvivesStreamCallbackPanic(t *testing.T) {
	addr := rawOrigin(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	c, err := fpNew(fpConfig{Loops: 1, RequestTimeout: fpFixTestTimeout})
	if err != nil {
		t.Fatalf("fpNew: %v", err)
	}
	defer c.Close()
	sink := &UpstreamStream{OnHeaders: func(int, [][2]string) error { panic("fpfix stream callback") }}
	if _, err := c.DoStream(&fpRequest{Scheme: "http", Authority: addr, Method: "GET", Path: "/"}, sink); err == nil {
		t.Fatal("a panicking stream callback reported success")
	}
	resp, err := c.Do(&fpRequest{Scheme: "http", Authority: addr, Method: "GET", Path: "/"})
	if err != nil || resp.Status != 200 || string(resp.Body) != "ok" {
		t.Fatalf("loop unusable after a recovered panic: %v %+v", err, resp)
	}
}

func fpFixTLS13ServerHelloExts(versions []byte, keyShare []byte) []byte {
	ext := appendExt(nil, 0x002b, versions)
	return appendExt(ext, 0x0033, keyShare)
}

func TestFPFixTLSRejectsDowngradeSentinel(t *testing.T) {
	for _, canary := range []string{"DOWNGRD\x01", "DOWNGRD\x00"} {
		var random [32]byte
		copy(random[24:], canary)
		tr := &tlsTransport{}
		if err := tr.handleServerHello(fpFixServerHello(random, suite12ECDSAES128, nil)); err == nil {
			t.Errorf("TLS 1.2 ServerHello carrying %q was accepted", canary)
		}
	}
	tr := &tlsTransport{}
	if err := tr.handleServerHello(fpFixServerHello([32]byte{1}, suite12ECDSAES128, nil)); err != nil {
		t.Fatalf("a plain TLS 1.2 ServerHello was rejected: %v", err)
	}
}

func TestFPFixTLSRejectsLegacyVersionInTLS12Path(t *testing.T) {
	hello := fpFixServerHello([32]byte{1}, suite12ECDSAES128, nil)
	hello[4], hello[5] = 0x03, 0x02
	if err := (&tlsTransport{}).handleServerHello(hello); err == nil {
		t.Fatal("a TLS 1.1 ServerHello was accepted as TLS 1.2")
	}
}

func TestFPFixTLSHelloRetryRequestFailsWithClearError(t *testing.T) {
	random := [32]byte{
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
	}
	exts := fpFixTLS13ServerHelloExts([]byte{0x03, 0x04}, []byte{0x00, 0x17})
	err := (&tlsTransport{}).handleServerHello(fpFixServerHello(random, suiteAES128GCMSHA256, exts))
	if err == nil || !strings.Contains(err.Error(), "HelloRetryRequest") {
		t.Fatalf("HelloRetryRequest err = %v, want a HelloRetryRequest error", err)
	}
}

var (
	fpFixEE13   = fpFixHandshakeMsg(tlsHSEncryptedExts, []byte{0, 0})
	fpFixCert13 = fpFixHandshakeMsg(tlsHSCertificate, []byte{0, 0, 0, 6, 0, 0, 1, 0x30, 0, 0})
	fpFixCV13   = fpFixHandshakeMsg(tlsHSCertVerify, []byte{0x08, 0x04, 0, 0})
)

func TestFPFixTLS13EnforcesHandshakeOrder(t *testing.T) {
	cat := func(msgs ...[]byte) []byte {
		var out []byte
		for _, m := range msgs {
			out = append(out, m...)
		}
		return out
	}
	for _, tc := range []struct {
		name string
		msgs []byte
	}{
		{"second certificate", cat(fpFixEE13, fpFixCert13, fpFixCV13, fpFixCert13)},
		{"certificate before encrypted extensions", cat(fpFixCert13, fpFixEE13)},
		{"certificate verify before certificate", cat(fpFixEE13, fpFixCV13, fpFixCert13)},
		{"unexpected message type", cat(fpFixEE13, fpFixHandshakeMsg(4, []byte{0}))},
	} {
		tr := &tlsTransport{skipVerify: true, version: 0x0304, state: tlsExpectEncrypted}
		if err := tr.handleEncryptedHandshake(nil, tc.msgs); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	tr := &tlsTransport{skipVerify: true, version: 0x0304, state: tlsExpectEncrypted}
	if err := tr.handleEncryptedHandshake(nil, cat(fpFixEE13, fpFixCert13, fpFixCV13)); err != nil {
		t.Fatalf("the legal order was rejected: %v", err)
	}
}

func TestFPFixTLS12EnforcesHandshakeOrder(t *testing.T) {
	cert12 := fpFixHandshakeMsg(tlsHSCertificate, []byte{0, 0, 4, 0, 0, 1, 0x30})
	for _, tc := range []struct {
		name string
		msgs []byte
	}{
		{"second certificate", append(append([]byte(nil), cert12...), cert12...)},
		{"server key exchange before certificate", fpFixHandshakeMsg(12, []byte{3, 0, 0x1d, 0})},
		{"unexpected message type", fpFixHandshakeMsg(4, []byte{0})},
	} {
		tr := &tlsTransport{skipVerify: true, version: 0x0303, state: tls12ExpectHandshake}
		if err := tr.handle12Handshake(nil, tc.msgs); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestFPFixTLS12AES256SuitesInteroperate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		suite uint16
	}{
		{"aes128", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		{"aes256", tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "ok")
			}))
			srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tc.suite}}
			srv.StartTLS()
			defer srv.Close()
			c, err := fpNew(fpConfig{Loops: 1, RequestTimeout: fpFixTestTimeout})
			if err != nil {
				t.Fatalf("fpNew: %v", err)
			}
			defer c.Close()
			resp, err := c.Do(mkReq(srv.URL+"/", "GET", false, nil))
			if err != nil || resp.Status != 200 || string(resp.Body) != "ok" {
				t.Fatalf("suite %#04x: %v %+v", tc.suite, err, resp)
			}
		})
	}
}
