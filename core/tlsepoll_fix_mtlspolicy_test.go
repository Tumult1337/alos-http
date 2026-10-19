//go:build linux && amd64

package core

import "testing"

type tlsEpollFixMisdirectCase struct {
	sni  string
	host string
	want bool
}

func tlsEpollFixCheckMisdirects(t *testing.T, cfg Config, cases []tlsEpollFixMisdirectCase) {
	t.Helper()
	srv := New(cfg)
	if err := srv.loadCerts(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if got := srv.misdirectsClientAuth(srv.certStore.Lookup(tc.sni), tc.host); got != tc.want {
			t.Errorf("SNI %q Host %q: misdirectsClientAuth = %v, want %v", tc.sni, tc.host, got, tc.want)
		}
	}
	if srv.misdirectsClientAuth(nil, mtlsDomain) {
		t.Error("a connection without a TLS handshake entry was treated as misdirected")
	}
}

func TestTLSEpollFixMisdirectsClientAuthPolicyComparison(t *testing.T) {
	fx := newClientCertFixture(t)
	require := RequireAndVerifyClientCert
	t.Run("override on one host", func(t *testing.T) {
		tlsEpollFixCheckMisdirects(t, Config{Certs: []CertConfig{
			{Domain: harnessDomain, Source: CertSelfSigned},
			{Domain: mtlsDomain, Source: CertSelfSigned, ClientAuth: &require, ClientCAs: fx.roots},
		}}, []tlsEpollFixMisdirectCase{
			{harnessDomain, harnessDomain, false},
			{harnessDomain, "", false},
			{harnessDomain, "unknown.test", false},
			{harnessDomain, mtlsDomain, true},
			{harnessDomain, "Mtls.Test:8443", true},
			{harnessDomain, "mtls.test.", true},
			{"", mtlsDomain, true},
			{mtlsDomain, mtlsDomain, false},
			{mtlsDomain, "MTLS.test", false},
			{mtlsDomain, harnessDomain, false},
		})
	})
	t.Run("roots-only override under a global mode", func(t *testing.T) {
		tlsEpollFixCheckMisdirects(t, Config{TLSClientAuth: VerifyClientCertIfGiven, Certs: []CertConfig{
			{Domain: harnessDomain, Source: CertSelfSigned},
			{Domain: mtlsDomain, Source: CertSelfSigned, ClientCAs: fx.roots},
		}}, []tlsEpollFixMisdirectCase{
			{harnessDomain, harnessDomain, false},
			{harnessDomain, mtlsDomain, true},
			{mtlsDomain, harnessDomain, true},
			{mtlsDomain, mtlsDomain, false},
		})
	})
	t.Run("no per-host override", func(t *testing.T) {
		tlsEpollFixCheckMisdirects(t, Config{TLSClientAuth: RequireAndVerifyClientCert, TLSClientCAs: fx.roots, Certs: []CertConfig{
			{Domain: harnessDomain, Source: CertSelfSigned},
			{Domain: mtlsDomain, Source: CertSelfSigned},
		}}, []tlsEpollFixMisdirectCase{
			{harnessDomain, mtlsDomain, false},
			{mtlsDomain, harnessDomain, false},
		})
	})
}
