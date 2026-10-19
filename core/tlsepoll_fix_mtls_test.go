//go:build linux && amd64

package core

import (
	"crypto/tls"
	"io"
	"net/http"
	"testing"
)

func tlsEpollFixGetWithHost(t *testing.T, ts *testServer, d mtlsDial, host string) (int, string) {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: d.clientConfig(ts), ForceAttemptHTTP2: d.alpn == "h2", DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, ts.url("/whoami"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	resp, err := (&http.Client{Transport: tr, Timeout: harnessIOTimeout}).Do(req)
	if err != nil {
		t.Fatalf("request with Host %q: %v", host, err)
	}
	defer resp.Body.Close()
	if wantProto := map[string]int{"h2": 2, "http/1.1": 1}[d.alpn]; resp.ProtoMajor != wantProto {
		t.Fatalf("unexpected protocol %s for ALPN %s", resp.Proto, d.alpn)
	}
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestTLSEpollFixPerHostMTLSRejectsHostOutsideHandshakePolicy(t *testing.T) {
	fx := newClientCertFixture(t)
	require := RequireAndVerifyClientCert
	ts := mtlsTestServer(t, func(c *Config) {
		c.Certs = append(c.Certs, CertConfig{Domain: mtlsDomain, Source: CertSelfSigned, ClientAuth: &require, ClientCAs: fx.roots})
	}, nil)
	for _, v := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		for _, alpn := range []string{"http/1.1", "h2"} {
			t.Run(tls.VersionName(v)+"/"+alpn, func(t *testing.T) {
				anonymous := mtlsDial{version: v, alpn: alpn}
				for _, host := range []string{mtlsDomain, "MTLS.TEST:443", mtlsDomain + "."} {
					if status, body := tlsEpollFixGetWithHost(t, ts, anonymous, host); status != 421 {
						t.Fatalf("SNI %s + Host %q served %d %q without a client certificate, want 421", harnessDomain, host, status, body)
					}
				}
				if status, body := tlsEpollFixGetWithHost(t, ts, anonymous, harnessDomain); status != 200 || body != "none" {
					t.Fatalf("matching Host got %d %q, want 200 none", status, body)
				}
				if status, body := tlsEpollFixGetWithHost(t, ts, anonymous, "unknown.test"); status != 200 {
					t.Fatalf("unknown Host on the default entry got %d %q, want 200", status, body)
				}
				authed := mtlsDial{version: v, alpn: alpn, serverName: mtlsDomain, cert: &fx.valid}
				if status, body := tlsEpollFixGetWithHost(t, ts, authed, mtlsDomain); status != 200 || body != "valid-client" {
					t.Fatalf("mTLS host got %d %q, want 200 valid-client", status, body)
				}
				if status, body := tlsEpollFixGetWithHost(t, ts, authed, harnessDomain); status != 200 || body != "valid-client" {
					t.Fatalf("mTLS handshake reused for the unauthenticated host %s got %d %q, want 200 valid-client", harnessDomain, status, body)
				}
			})
		}
	}
}
