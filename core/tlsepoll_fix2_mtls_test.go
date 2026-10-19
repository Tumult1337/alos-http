//go:build linux && amd64

package core

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
)

const (
	tlsEpollFix2PublicDomain      = "public.test"
	tlsEpollFix2HPACKSchemeHTTPS  = 0x87
	tlsEpollFix2HPACKHostIndex    = 38
	tlsEpollFix2WhoamiPath        = "/whoami"
	tlsEpollFix2MisdirectedStatus = 421
)

func tlsEpollFix2RequireExceptPublicConfig(roots func(*Config)) func(*Config) {
	none := NoClientCert
	return func(c *Config) {
		c.TLSClientAuth = RequireAndVerifyClientCert
		roots(c)
		c.Certs = append(c.Certs, CertConfig{Domain: tlsEpollFix2PublicDomain, Source: CertSelfSigned, ClientAuth: &none})
	}
}

func tlsEpollFix2DialPublic(t *testing.T, ts *testServer, version uint16, alpn string) *tls.Conn {
	t.Helper()
	d := mtlsDial{version: version, alpn: alpn, serverName: tlsEpollFix2PublicDomain}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: harnessIOTimeout}, "tcp4", ts.addr, d.clientConfig(ts))
	if err != nil {
		t.Fatalf("anonymous handshake for %s: %v", tlsEpollFix2PublicDomain, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(wallDeadline(harnessIOTimeout))
	return conn
}

func tlsEpollFix2H2Status(t *testing.T, conn net.Conn, block []byte) int {
	t.Helper()
	if _, err := io.WriteString(conn, tlsEpollFixH2Preface+string(appendH2Frame(nil, H2FrameSettings, 0, 0, nil))); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(appendH2Frame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, block)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	for {
		f := tlsEpollFixReadH2Frame(t, br)
		if f.stream != 1 {
			continue
		}
		if f.typ != H2FrameHeaders {
			t.Fatalf("stream 1 answered with frame type %d, want HEADERS", f.typ)
		}
		return h2RawStatusFromHeaders(t, f.payload)
	}
}

func tlsEpollFix2H2RequestBlock(extra ...byte) []byte {
	block := []byte{tlsEpollFixHPACKMethodGET, tlsEpollFix2HPACKSchemeHTTPS, tlsEpollFixHPACKPathName, byte(len(tlsEpollFix2WhoamiPath))}
	block = append(block, tlsEpollFix2WhoamiPath...)
	return append(block, extra...)
}

func TestTLSEpollFix2HostlessRequestUsesHandshakeClientAuthPolicy(t *testing.T) {
	fx := newClientCertFixture(t)
	ts := mtlsTestServer(t, tlsEpollFix2RequireExceptPublicConfig(func(c *Config) { c.TLSClientCAs = fx.roots }), nil)
	hostHeader := hpackLiteralWithIndexing(tlsEpollFix2HPACKHostIndex, tlsEpollFix2PublicDomain)
	authorityDefault := append([]byte{tlsEpollFixHPACKAuthName, byte(len(harnessDomain))}, harnessDomain...)
	for _, v := range tlsEpollFixVersions() {
		t.Run(tls.VersionName(v), func(t *testing.T) {
			t.Run("HTTP/1.0 without Host", func(t *testing.T) {
				conn := tlsEpollFix2DialPublic(t, ts, v, "http/1.1")
				if _, err := io.WriteString(conn, "GET "+tlsEpollFix2WhoamiPath+" HTTP/1.0\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK || string(body) != "none" {
					t.Fatalf("Host-less HTTP/1.0 request on the %s handshake got %d %q, want 200 none", tlsEpollFix2PublicDomain, resp.StatusCode, body)
				}
			})
			t.Run("h2 without :authority", func(t *testing.T) {
				if status := tlsEpollFix2H2Status(t, tlsEpollFix2DialPublic(t, ts, v, "h2"), tlsEpollFix2H2RequestBlock()); status != http.StatusOK {
					t.Fatalf("h2 request without :authority on the %s handshake got %d, want 200", tlsEpollFix2PublicDomain, status)
				}
			})
			t.Run("h2 with Host but no :authority", func(t *testing.T) {
				if status := tlsEpollFix2H2Status(t, tlsEpollFix2DialPublic(t, ts, v, "h2"), tlsEpollFix2H2RequestBlock(hostHeader...)); status != http.StatusOK {
					t.Fatalf("h2 request with Host %s and no :authority got %d, want 200", tlsEpollFix2PublicDomain, status)
				}
			})
			t.Run("h2 :authority of a cert-requiring host still misdirected", func(t *testing.T) {
				if status := tlsEpollFix2H2Status(t, tlsEpollFix2DialPublic(t, ts, v, "h2"), tlsEpollFix2H2RequestBlock(authorityDefault...)); status != tlsEpollFix2MisdirectedStatus {
					t.Fatalf("h2 :authority %s on the anonymous %s handshake got %d, want 421", harnessDomain, tlsEpollFix2PublicDomain, status)
				}
			})
		})
	}
}

func TestTLSEpollFix2MisdirectsClientAuthIgnoresEmptyHost(t *testing.T) {
	fx := newClientCertFixture(t)
	none := NoClientCert
	tlsEpollFixCheckMisdirects(t, Config{TLSClientAuth: RequireAndVerifyClientCert, TLSClientCAs: fx.roots, Certs: []CertConfig{
		{Domain: harnessDomain, Source: CertSelfSigned},
		{Domain: tlsEpollFix2PublicDomain, Source: CertSelfSigned, ClientAuth: &none},
	}}, []tlsEpollFixMisdirectCase{
		{tlsEpollFix2PublicDomain, "", false},
		{tlsEpollFix2PublicDomain, tlsEpollFix2PublicDomain, false},
		{tlsEpollFix2PublicDomain, harnessDomain, true},
		{tlsEpollFix2PublicDomain, "unknown.test", true},
		{harnessDomain, "", false},
		{harnessDomain, tlsEpollFix2PublicDomain, false},
	})
}
