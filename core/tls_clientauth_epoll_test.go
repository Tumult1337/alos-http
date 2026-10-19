//go:build linux && amd64

package core

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

const mtlsDomain = "mtls.test"

func mtlsTestServer(t testing.TB, mutate func(*Config), setup func(*Server)) *testServer {
	return newTestServer(t, testServerOptions{
		TLS:    true,
		Config: mutate,
		Setup:  setup,
		Routes: func(r *Router) {
			r.GET("/whoami", func(req *Request, resp *Response) {
				certs := req.TLSPeerCertificates()
				if len(certs) == 0 {
					resp.Status(200).String("none")
					return
				}
				resp.Status(200).String(certs[0].Subject.CommonName)
			})
		},
	})
}

type mtlsDial struct {
	version    uint16
	alpn       string
	cert       *tls.Certificate
	cache      tls.ClientSessionCache
	serverName string
}

func (d mtlsDial) clientConfig(ts *testServer) *tls.Config {
	cfg := ts.tlsConfig(d.alpn)
	cfg.MinVersion, cfg.MaxVersion = d.version, d.version
	cfg.ClientSessionCache = d.cache
	if d.serverName != "" {
		cfg.ServerName = d.serverName
	}
	if d.cert != nil {
		cfg.Certificates = []tls.Certificate{*d.cert}
	}
	return cfg
}

func mtlsProbeAlert(ts *testServer, d mtlsDial) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: harnessIOTimeout}, "tcp4", ts.addr, d.clientConfig(ts))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(harnessIOTimeout))
	if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); err != nil {
		return err
	}
	_, err = conn.Read(make([]byte, 1))
	return err
}

func mtlsGet(ts *testServer, d mtlsDial) (string, *tls.ConnectionState, error) {
	tr := &http.Transport{TLSClientConfig: d.clientConfig(ts), ForceAttemptHTTP2: d.alpn == "h2", DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: harnessIOTimeout}).Get(ts.url("/whoami"))
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	if wantProto := map[string]int{"h2": 2, "http/1.1": 1}[d.alpn]; resp.ProtoMajor != wantProto {
		return "", nil, fmt.Errorf("unexpected protocol %s", resp.Proto)
	}
	return string(body), resp.TLS, nil
}

type mtlsOutcome struct {
	who   string
	alert string
}

func mtlsPass(cn string) mtlsOutcome    { return mtlsOutcome{who: cn} }
func mtlsFail(alert string) mtlsOutcome { return mtlsOutcome{alert: alert} }

func checkMTLSOutcome(t *testing.T, who string, err error, want mtlsOutcome) {
	t.Helper()
	if want.alert == "" {
		if err != nil || who != want.who {
			t.Fatalf("got %q err=%v, want %q", who, err, want.who)
		}
		return
	}
	if err == nil {
		t.Fatalf("connection succeeded as %q, want alert %q", who, want.alert)
	}
}

func checkMTLSAlert(t *testing.T, ts *testServer, d mtlsDial, want mtlsOutcome) {
	t.Helper()
	if want.alert == "" {
		return
	}
	err := mtlsProbeAlert(ts, d)
	if err == nil || !strings.Contains(err.Error(), "remote error: tls: "+want.alert) {
		t.Fatalf("probe error %v does not carry alert %q", err, want.alert)
	}
}

func TestMTLSModesGoClient(t *testing.T) {
	fx := newClientCertFixture(t)
	creds := []struct {
		name string
		cert *tls.Certificate
	}{
		{"no cert", nil},
		{"valid", &fx.valid},
		{"unknown CA", &fx.unknown},
		{"expired", &fx.expired},
		{"wrong key", &fx.wrongKey},
	}
	const (
		required13 = "certificate required"
		required12 = "bad certificate"
		unknownCA  = "unknown certificate authority"
		expired    = "expired certificate"
		badCV      = "error decrypting message"
	)
	modes := []struct {
		name  string
		mode  ClientAuthType
		tls13 []mtlsOutcome
		tls12 []mtlsOutcome
	}{
		{"NoClientCert", NoClientCert,
			[]mtlsOutcome{mtlsPass("none"), mtlsPass("none"), mtlsPass("none"), mtlsPass("none"), mtlsPass("none")},
			[]mtlsOutcome{mtlsPass("none"), mtlsPass("none"), mtlsPass("none"), mtlsPass("none"), mtlsPass("none")}},
		{"RequestClientCert", RequestClientCert,
			[]mtlsOutcome{mtlsPass("none"), mtlsPass("valid-client"), mtlsPass("unknown-client"), mtlsPass("expired-client"), mtlsFail(badCV)},
			[]mtlsOutcome{mtlsPass("none"), mtlsPass("valid-client"), mtlsPass("unknown-client"), mtlsPass("expired-client"), mtlsFail(badCV)}},
		{"RequireAnyClientCert", RequireAnyClientCert,
			[]mtlsOutcome{mtlsFail(required13), mtlsPass("valid-client"), mtlsPass("unknown-client"), mtlsPass("expired-client"), mtlsFail(badCV)},
			[]mtlsOutcome{mtlsFail(required12), mtlsPass("valid-client"), mtlsPass("unknown-client"), mtlsPass("expired-client"), mtlsFail(badCV)}},
		{"VerifyClientCertIfGiven", VerifyClientCertIfGiven,
			[]mtlsOutcome{mtlsPass("none"), mtlsPass("valid-client"), mtlsFail(unknownCA), mtlsFail(expired), mtlsFail(badCV)},
			[]mtlsOutcome{mtlsPass("none"), mtlsPass("valid-client"), mtlsFail(unknownCA), mtlsFail(expired), mtlsFail(badCV)}},
		{"RequireAndVerifyClientCert", RequireAndVerifyClientCert,
			[]mtlsOutcome{mtlsFail(required13), mtlsPass("valid-client"), mtlsFail(unknownCA), mtlsFail(expired), mtlsFail(badCV)},
			[]mtlsOutcome{mtlsFail(required12), mtlsPass("valid-client"), mtlsFail(unknownCA), mtlsFail(expired), mtlsFail(badCV)}},
	}
	versions := []struct {
		name    string
		version uint16
	}{{"TLS1.3", tls.VersionTLS13}, {"TLS1.2", tls.VersionTLS12}}
	for _, m := range modes {
		ts := mtlsTestServer(t, func(c *Config) {
			c.TLSClientAuth = m.mode
			c.TLSClientCAs = fx.roots
		}, nil)
		for _, v := range versions {
			want := m.tls13
			if v.version == tls.VersionTLS12 {
				want = m.tls12
			}
			for _, alpn := range []string{"http/1.1", "h2"} {
				for i, c := range creds {
					t.Run(m.name+"/"+v.name+"/"+alpn+"/"+c.name, func(t *testing.T) {
						d := mtlsDial{version: v.version, alpn: alpn, cert: c.cert}
						who, _, err := mtlsGet(ts, d)
						checkMTLSOutcome(t, who, err, want[i])
						checkMTLSAlert(t, ts, d, want[i])
					})
				}
			}
		}
	}
}

func TestMTLSEd25519ClientCertTLS13(t *testing.T) {
	fx := newClientCertFixture(t)
	ts := mtlsTestServer(t, func(c *Config) {
		c.TLSClientAuth = RequireAndVerifyClientCert
		c.TLSClientCAs = fx.roots
	}, nil)
	who, _, err := mtlsGet(ts, mtlsDial{version: tls.VersionTLS13, alpn: "http/1.1", cert: &fx.ed25519})
	checkMTLSOutcome(t, who, err, mtlsPass("ed25519-client"))
}

func TestMTLSResumptionKeepsPeerCertificate(t *testing.T) {
	fx := newClientCertFixture(t)
	ts := mtlsTestServer(t, func(c *Config) {
		c.TLSClientAuth = RequireAndVerifyClientCert
		c.TLSClientCAs = fx.roots
	}, nil)
	for _, v := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		for _, alpn := range []string{"http/1.1", "h2"} {
			t.Run(tls.VersionName(v)+"/"+alpn, func(t *testing.T) {
				d := mtlsDial{version: v, alpn: alpn, cert: &fx.valid, cache: tls.NewLRUClientSessionCache(4)}
				who, st, err := mtlsGet(ts, d)
				checkMTLSOutcome(t, who, err, mtlsPass("valid-client"))
				if st.DidResume {
					t.Fatal("first connection claims resumption")
				}
				for i := 0; i < 2; i++ {
					who, st, err = mtlsGet(ts, d)
					checkMTLSOutcome(t, who, err, mtlsPass("valid-client"))
					if !st.DidResume {
						t.Fatalf("connection %d did not resume", i+2)
					}
				}
			})
		}
	}
}

func TestMTLSTicketFromAnonymousSessionDoesNotBypassClientAuth(t *testing.T) {
	fx := newClientCertFixture(t)
	shared, _ := newTestTicketCodec()
	useShared := func(s *Server) { s.tickets = shared }
	open := mtlsTestServer(t, nil, useShared)
	strict := mtlsTestServer(t, func(c *Config) {
		c.TLSClientAuth = RequireAndVerifyClientCert
		c.TLSClientCAs = fx.roots
	}, useShared)
	for _, v := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		t.Run(tls.VersionName(v), func(t *testing.T) {
			cache := tls.NewLRUClientSessionCache(4)
			who, _, err := mtlsGet(open, mtlsDial{version: v, alpn: "http/1.1", cache: cache})
			checkMTLSOutcome(t, who, err, mtlsPass("none"))
			who, _, err = mtlsGet(strict, mtlsDial{version: v, alpn: "http/1.1", cache: cache})
			if err == nil {
				t.Fatalf("anonymous ticket resumed into a RequireAndVerify server as %q", who)
			}
			who, st, err := mtlsGet(strict, mtlsDial{version: v, alpn: "http/1.1", cache: cache, cert: &fx.valid})
			checkMTLSOutcome(t, who, err, mtlsPass("valid-client"))
			if st.DidResume {
				t.Fatal("anonymous ticket resumed instead of a full handshake with a certificate")
			}
		})
	}
}

func TestMTLSPerHostOverride(t *testing.T) {
	fx := newClientCertFixture(t)
	require := RequireAndVerifyClientCert
	ts := mtlsTestServer(t, func(c *Config) {
		c.Certs = append(c.Certs, CertConfig{Domain: mtlsDomain, Source: CertSelfSigned, ClientAuth: &require, ClientCAs: fx.roots})
	}, nil)
	for _, v := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		t.Run(tls.VersionName(v), func(t *testing.T) {
			who, _, err := mtlsGet(ts, mtlsDial{version: v, alpn: "http/1.1"})
			checkMTLSOutcome(t, who, err, mtlsPass("none"))
			_, _, err = mtlsGet(ts, mtlsDial{version: v, alpn: "http/1.1", serverName: mtlsDomain})
			if err == nil {
				t.Fatal("override host accepted a connection without a certificate")
			}
			who, _, err = mtlsGet(ts, mtlsDial{version: v, alpn: "http/1.1", serverName: mtlsDomain, cert: &fx.valid})
			checkMTLSOutcome(t, who, err, mtlsPass("valid-client"))
		})
	}
}

func TestMTLSPeerCertificatesClearedBetweenConnections(t *testing.T) {
	fx := newClientCertFixture(t)
	ts := mtlsTestServer(t, func(c *Config) {
		c.TLSClientAuth = VerifyClientCertIfGiven
		c.TLSClientCAs = fx.roots
	}, nil)
	for i := 0; i < 4; i++ {
		who, _, err := mtlsGet(ts, mtlsDial{version: tls.VersionTLS13, alpn: "http/1.1", cert: &fx.valid})
		checkMTLSOutcome(t, who, err, mtlsPass("valid-client"))
		who, _, err = mtlsGet(ts, mtlsDial{version: tls.VersionTLS13, alpn: "http/1.1"})
		checkMTLSOutcome(t, who, err, mtlsPass("none"))
	}
}

func BenchmarkTLS13ServerFlightMTLS(b *testing.B) {
	fx := newClientCertFixture(b)
	ts := mtlsTestServer(b, func(c *Config) {
		c.TLSClientAuth = RequireAndVerifyClientCert
		c.TLSClientCAs = fx.roots
	}, nil)
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: ts.domain, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{fx.valid}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := tls.Dial("tcp4", ts.addr, cfg)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.WriteString(conn, "GET /whoami HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			b.Fatal(err)
		}
		if _, err := conn.Read(make([]byte, 512)); err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}

func TestMTLSRootHandlerSeesPeerCertificate(t *testing.T) {
	fx := newClientCertFixture(t)
	require := RequestClientCert
	whoami := func(req *Request, resp *Response) {
		if certs := req.TLSPeerCertificates(); len(certs) > 0 {
			resp.Status(200).String(certs[0].Subject.CommonName)
			return
		}
		resp.Status(200).String("none")
	}
	configs := map[string]func(*Config){
		"global client auth": func(c *Config) { c.TLSClientAuth = RequestClientCert },
		"per-host client auth": func(c *Config) {
			c.Certs = append(c.Certs, CertConfig{Domain: mtlsDomain, Source: CertSelfSigned, ClientAuth: &require})
		},
	}
	for name, mutate := range configs {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, testServerOptions{TLS: true, Config: mutate, Routes: func(r *Router) { r.GET("/", whoami) }})
			if ts.srv.plainRootFast.Load() != nil || ts.srv.h2RootFast.Load() != nil {
				t.Fatal("root response memoized although it can depend on the client certificate")
			}
			for _, alpn := range []string{"http/1.1", "h2"} {
				cfg := ts.tlsConfig(alpn)
				cfg.ServerName = mtlsDomain
				cfg.Certificates = []tls.Certificate{fx.valid}
				tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: alpn == "h2", DisableKeepAlives: true}
				resp, err := (&http.Client{Transport: tr, Timeout: harnessIOTimeout}).Get(ts.url("/"))
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				tr.CloseIdleConnections()
				if string(body) != "valid-client" {
					t.Fatalf("%s: GET / saw %q, want the client certificate", alpn, body)
				}
			}
		})
	}
	ts := newTestServer(t, testServerOptions{TLS: true, Routes: func(r *Router) { r.GET("/", whoami) }})
	if ts.srv.plainRootFast.Load() == nil {
		t.Fatal("root response no longer memoized without client auth")
	}
}
