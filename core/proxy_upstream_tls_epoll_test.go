//go:build linux && amd64

package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"
)

const (
	upstreamTLSName   = "origin.test"
	upstreamTLSDomain = "edge.test"
)

type upstreamTLSFixture struct {
	serverRoots  *x509.CertPool
	ipLeaf       tls.Certificate
	nameOnlyLeaf tls.Certificate
	clientRoots  *x509.CertPool
	clients      map[string]tls.Certificate
}

func newUpstreamTLSFixture(t *testing.T) *upstreamTLSFixture {
	t.Helper()
	now := wallNow()
	serverCA := newTestCA(t, "private origin CA")
	clientCA := newTestCA(t, "origin client CA")
	f := &upstreamTLSFixture{serverRoots: x509.NewCertPool(), clientRoots: x509.NewCertPool(), clients: map[string]tls.Certificate{}}
	f.serverRoots.AddCert(serverCA.cert)
	f.clientRoots.AddCert(clientCA.cert)
	serverSpec := leafSpec{cn: upstreamTLSName, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), usage: x509.ExtKeyUsageServerAuth, dnsNames: []string{upstreamTLSName}}
	f.nameOnlyLeaf = serverCA.issue(t, serverSpec)
	serverSpec.ips = []net.IP{net.IPv4(127, 0, 0, 1)}
	f.ipLeaf = serverCA.issue(t, serverSpec)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"ecdsa-client": ecKey, "rsa-client": rsaKey, "ed25519-client": edKey} {
		f.clients[name] = clientCA.issue(t, leafSpec{cn: name, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), usage: x509.ExtKeyUsageClientAuth, key: key})
	}
	return f
}

func startTLSOrigin(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			who := "anonymous"
			if len(r.TLS.PeerCertificates) > 0 {
				who = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			fmt.Fprintf(w, "%s %s", tls.VersionName(r.TLS.Version), who)
		}),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func originTLSConfig(leaf tls.Certificate, version uint16, clientAuth tls.ClientAuthType, clientRoots *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   version,
		MaxVersion:   version,
		ClientAuth:   clientAuth,
		ClientCAs:    clientRoots,
	}
}

func proxyThroughEpoll(t *testing.T, backend BackendConfig) (int, string) {
	t.Helper()
	addr := startInloopProxy(t, DomainConfig{Domain: upstreamTLSDomain, Backends: []BackendConfig{backend}}, nil)
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	req, err := http.NewRequest("GET", "http://"+addr+"/who", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = upstreamTLSDomain
	resp, err := (&http.Client{Transport: tr, Timeout: harnessIOTimeout}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func proxyThroughEngine(t *testing.T, backend BackendConfig) (int, string) {
	t.Helper()
	pe := NewProxyEngine()
	t.Cleanup(pe.Stop)
	pe.AddDomain(DomainConfig{Domain: upstreamTLSDomain, Backends: []BackendConfig{backend}})
	req := &Request{Method: "GET", Host: upstreamTLSDomain, Path: "/who", RemoteAddr: "127.0.0.1:40000"}
	resp := &Response{}
	resp.Reset()
	if !pe.Handle(req, resp) {
		t.Fatal("not handled")
	}
	return resp.StatusCode, string(resp.transmittedBodyBytes())
}

type upstreamTLSCase struct {
	name     string
	leaf     func(*upstreamTLSFixture) tls.Certificate
	auth     tls.ClientAuthType
	backend  func(f *upstreamTLSFixture, addr string) BackendConfig
	wantCode int
	wantWho  string
}

func upstreamTLSCases() []upstreamTLSCase {
	ipLeaf := func(f *upstreamTLSFixture) tls.Certificate { return f.ipLeaf }
	nameOnly := func(f *upstreamTLSFixture) tls.Certificate { return f.nameOnlyLeaf }
	plain := func(_ *upstreamTLSFixture, addr string) BackendConfig { return BackendConfig{Addr: "https://" + addr} }
	trusted := func(f *upstreamTLSFixture, addr string) BackendConfig {
		return BackendConfig{Addr: "https://" + addr, RootCAs: f.serverRoots}
	}
	named := func(name string) func(*upstreamTLSFixture, string) BackendConfig {
		return func(f *upstreamTLSFixture, addr string) BackendConfig {
			return BackendConfig{Addr: "https://" + addr, RootCAs: f.serverRoots, ServerName: name}
		}
	}
	withClient := func(name string) func(*upstreamTLSFixture, string) BackendConfig {
		return func(f *upstreamTLSFixture, addr string) BackendConfig {
			cert := f.clients[name]
			return BackendConfig{Addr: "https://" + addr, RootCAs: f.serverRoots, ClientCert: &cert}
		}
	}
	return []upstreamTLSCase{
		{"private CA without RootCAs", ipLeaf, tls.NoClientCert, plain, 502, ""},
		{"private CA with RootCAs", ipLeaf, tls.NoClientCert, trusted, 200, "anonymous"},
		{"name-only certificate without ServerName", nameOnly, tls.NoClientCert, trusted, 502, ""},
		{"name-only certificate with ServerName", nameOnly, tls.NoClientCert, named(upstreamTLSName), 200, "anonymous"},
		{"ServerName the certificate does not cover", nameOnly, tls.NoClientCert, named("other.test"), 502, ""},
		{"mTLS origin without ClientCert", ipLeaf, tls.RequireAndVerifyClientCert, trusted, 502, ""},
		{"mTLS origin with an ECDSA ClientCert", ipLeaf, tls.RequireAndVerifyClientCert, withClient("ecdsa-client"), 200, "ecdsa-client"},
		{"mTLS origin with an RSA ClientCert", ipLeaf, tls.RequireAndVerifyClientCert, withClient("rsa-client"), 200, "rsa-client"},
		{"mTLS origin with an Ed25519 ClientCert", ipLeaf, tls.RequireAndVerifyClientCert, withClient("ed25519-client"), 200, "ed25519-client"},
		{"optional client certificate not configured", ipLeaf, tls.RequestClientCert, trusted, 200, "anonymous"},
	}
}

func TestProxyUpstreamTLS(t *testing.T) {
	f := newUpstreamTLSFixture(t)
	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		for _, tc := range upstreamTLSCases() {
			t.Run(tls.VersionName(version)+"/"+tc.name, func(t *testing.T) {
				addr := startTLSOrigin(t, originTLSConfig(tc.leaf(f), version, tc.auth, f.clientRoots))
				backend := tc.backend(f, addr)
				for path, through := range map[string]func(*testing.T, BackendConfig) (int, string){"epoll": proxyThroughEpoll, "engine": proxyThroughEngine} {
					code, body := through(t, backend)
					if code != tc.wantCode {
						t.Fatalf("%s: status %d body %q, want %d", path, code, body, tc.wantCode)
					}
					if want := tls.VersionName(version) + " " + tc.wantWho; tc.wantCode == 200 && body != want {
						t.Fatalf("%s: origin answered %q, want %q", path, body, want)
					}
				}
			})
		}
	}
}

func TestProxyUpstreamTLSHealthProbe(t *testing.T) {
	f := newUpstreamTLSFixture(t)
	addr := startTLSOrigin(t, originTLSConfig(f.ipLeaf, tls.VersionTLS13, tls.RequireAndVerifyClientCert, f.clientRoots))
	cfg := HealthCheckConfig{Enabled: true, Path: "/who", Timeout: harnessIOTimeout}
	cert := f.clients["ecdsa-client"]
	if probeBackendHealth(addr, true, false, newUpstreamTrust(BackendConfig{RootCAs: f.serverRoots}), cfg) {
		t.Fatal("health probe passed an mTLS origin without a client certificate")
	}
	if !probeBackendHealth(addr, true, false, newUpstreamTrust(BackendConfig{RootCAs: f.serverRoots, ClientCert: &cert}), cfg) {
		t.Fatal("health probe failed with RootCAs and ClientCert")
	}
}

func TestProxyUpstreamTLSPoolsAreSeparatedByTrust(t *testing.T) {
	f := newUpstreamTLSFixture(t)
	addr := startTLSOrigin(t, originTLSConfig(f.ipLeaf, tls.VersionTLS13, tls.VerifyClientCertIfGiven, f.clientRoots))
	pe := NewProxyEngine()
	t.Cleanup(pe.Stop)
	ecdsaCert, rsaCert := f.clients["ecdsa-client"], f.clients["rsa-client"]
	for domain, cert := range map[string]*tls.Certificate{"a.test": &ecdsaCert, "b.test": &rsaCert, "c.test": nil} {
		pe.AddDomain(DomainConfig{Domain: domain, Backends: []BackendConfig{{Addr: "https://" + addr, RootCAs: f.serverRoots, ClientCert: cert}}})
	}
	for round := 0; round < 3; round++ {
		for domain, want := range map[string]string{"a.test": "ecdsa-client", "b.test": "rsa-client", "c.test": "anonymous"} {
			req := &Request{Method: "GET", Host: domain, Path: "/who", RemoteAddr: "127.0.0.1:40000"}
			resp := &Response{}
			resp.Reset()
			if !pe.Handle(req, resp) {
				t.Fatal("not handled")
			}
			if got := string(resp.transmittedBodyBytes()); resp.StatusCode != 200 || got != "TLS 1.3 "+want {
				t.Fatalf("round %d %s: %d %q, want identity %q", round, domain, resp.StatusCode, got, want)
			}
		}
	}
}

func TestUpstreamSNIHostName(t *testing.T) {
	for name, want := range map[string]bool{
		"origin.test": true,
		"localhost":   true,
		"":            false,
		"127.0.0.1":   false,
		"::1":         false,
		"[::1]":       false,
		"2001:db8::7": false,
	} {
		if got := sniHostName(name); got != want {
			t.Errorf("sniHostName(%q) = %v, want %v", name, got, want)
		}
	}
	tr := &tlsTransport{serverName: "127.0.0.1"}
	if ext := tr.buildExtensions(make([]byte, 32)); len(ext) >= 2 && ext[0] == 0 && ext[1] == 0 {
		t.Fatal("server_name extension sent for an IP literal")
	}
}
