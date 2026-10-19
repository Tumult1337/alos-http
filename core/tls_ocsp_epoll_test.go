//go:build linux && amd64

package core

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ocsp"
)

func ocspTestServer(t *testing.T, f *ocspFixture, mutate func(*Config)) *testServer {
	certFile, keyFile := f.writeFiles(t)
	return newTestServer(t, testServerOptions{
		TLS:    true,
		Domain: ocspTestDomain,
		Config: func(c *Config) {
			c.Certs = []CertConfig{{Domain: ocspTestDomain, Source: CertManual, CertFile: certFile, KeyFile: keyFile}}
			if mutate != nil {
				mutate(c)
			}
		},
		Routes: func(r *Router) {
			r.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
		},
	})
}

func (f *ocspFixture) clientConfig(version uint16, cert *tls.Certificate) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.cert)
	cfg := &tls.Config{RootCAs: roots, ServerName: ocspTestDomain, MinVersion: version, MaxVersion: version, NextProtos: []string{"http/1.1"}}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

func ocspHandshake(t *testing.T, ts *testServer, cfg *tls.Config) tls.ConnectionState {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: harnessIOTimeout}, "tcp4", ts.addr, cfg)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(harnessIOTimeout))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+ocspTestDomain+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatalf("no response after the handshake: %v", err)
	}
	return conn.ConnectionState()
}

func (f *ocspFixture) requireGoodStaple(t *testing.T, st tls.ConnectionState) {
	t.Helper()
	if len(st.OCSPResponse) == 0 {
		t.Fatal("no OCSP staple in the handshake")
	}
	resp, err := ocsp.ParseResponseForCert(st.OCSPResponse, f.leafCert, f.ca.cert)
	if err != nil || resp.Status != ocsp.Good {
		t.Fatalf("staple %+v (%v)", resp, err)
	}
}

func TestOCSPStapleGoClient(t *testing.T) {
	f := newOCSPFixture(t, true)
	clients := newClientCertFixture(t)
	ts := ocspTestServer(t, f, func(c *Config) { c.TLSClientAuth = RequestClientCert })
	entry := ts.srv.certStore.Lookup(ocspTestDomain)
	waitFor(t, ocspStapleDeadline, func() bool { return entry.OCSPStaple() != nil })
	for _, v := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		for _, c := range []struct {
			name string
			cert *tls.Certificate
		}{{"server auth only", nil}, {"with a client certificate", &clients.valid}} {
			t.Run(tls.VersionName(v)+"/"+c.name, func(t *testing.T) {
				f.requireGoodStaple(t, ocspHandshake(t, ts, f.clientConfig(v, c.cert)))
			})
		}
	}
}

func TestOCSPResponderDownStillHandshakes(t *testing.T) {
	f := newOCSPFixture(t, true)
	f.mode.Store(int32(respondServerError))
	ts := ocspTestServer(t, f, nil)
	waitFor(t, ocspStapleDeadline, func() bool { return f.hits.Load() > 0 })
	for _, v := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		if st := ocspHandshake(t, ts, f.clientConfig(v, nil)); len(st.OCSPResponse) != 0 {
			t.Fatalf("%s: staple served while the responder is failing", tls.VersionName(v))
		}
	}
}

func TestOCSPDisabledNeverFetches(t *testing.T) {
	f := newOCSPFixture(t, true)
	ts := ocspTestServer(t, f, func(c *Config) { c.DisableOCSPStapling = true })
	st := ocspHandshake(t, ts, f.clientConfig(tls.VersionTLS13, nil))
	if len(st.OCSPResponse) != 0 || f.hits.Load() != 0 {
		t.Fatalf("staple=%d bytes, %d fetches with stapling disabled", len(st.OCSPResponse), f.hits.Load())
	}
}

func TestOCSPManualStapleFile(t *testing.T) {
	f := newOCSPFixture(t, false)
	staple := filepath.Join(t.TempDir(), "staple.der")
	if err := os.WriteFile(staple, f.goodResponse(t), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := ocspTestServer(t, f, func(c *Config) {
		c.DisableOCSPStapling = true
		c.Certs[0].OCSPStapleFile = staple
	})
	for _, v := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		f.requireGoodStaple(t, ocspHandshake(t, ts, f.clientConfig(v, nil)))
	}
}
