package h3interop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/guno1928/alos-http/core"
	"github.com/guno1928/turbo"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	mtlsH3Domain             = "mtls.h3.test"
	alertUnknownCA           = 48
	alertCertificateRequired = 116
)

type h3ClientCerts struct {
	roots   *x509.CertPool
	valid   tls.Certificate
	unknown tls.Certificate
}

func issueTestCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, serial int64) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(0, turbo.UnixNano())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, der
}

func newH3ClientCerts(t *testing.T) *h3ClientCerts {
	ca, caKey, _ := issueTestCert(t, "h3 client CA", true, nil, nil, 1)
	other, otherKey, _ := issueTestCert(t, "untrusted CA", true, nil, nil, 2)
	_, validKey, validDER := issueTestCert(t, "valid-client", false, ca, caKey, 3)
	_, unknownKey, unknownDER := issueTestCert(t, "unknown-client", false, other, otherKey, 4)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &h3ClientCerts{
		roots:   roots,
		valid:   tls.Certificate{Certificate: [][]byte{validDER}, PrivateKey: validKey},
		unknown: tls.Certificate{Certificate: [][]byte{unknownDER}, PrivateKey: unknownKey},
	}
}

func startMTLSH3(t *testing.T, certs *h3ClientCerts) *h3Server {
	require := core.RequireAndVerifyClientCert
	return startH3(t, core.Config{Certs: []core.CertConfig{{
		Domain:     mtlsH3Domain,
		Source:     core.CertSelfSigned,
		ClientAuth: &require,
		ClientCAs:  certs.roots,
	}}})
}

func mtlsClientTLS(cert *tls.Certificate) *tls.Config {
	cfg := clientTLS()
	cfg.ServerName = mtlsH3Domain
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

func h3HandshakeCloseCode(t *testing.T, addr string, cfg *tls.Config) quic.TransportErrorCode {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), alertDialTimeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, cfg, &quic.Config{HandshakeIdleTimeout: alertDialTimeout})
	if err == nil {
		select {
		case <-conn.Context().Done():
			err = context.Cause(conn.Context())
		case <-turbo.After(alertDialTimeout):
			_ = conn.CloseWithError(0, "")
			t.Fatal("server accepted the connection")
		}
	}
	var te *quic.TransportError
	if !errors.As(err, &te) || !te.Remote {
		t.Fatalf("got %v (%T), want a remote transport error", err, err)
	}
	return te.ErrorCode
}

func h3Whoami(t *testing.T, cfg *tls.Config, addr string) (string, bool) {
	t.Helper()
	tr := &http3.Transport{TLSClientConfig: cfg, QUICConfig: &quic.Config{HandshakeIdleTimeout: alertDialTimeout}}
	defer tr.Close()
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = cfg.ServerName
	resp, err := (&http.Client{Transport: tr, Timeout: clientTimeout}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("got %d %q (%v)", resp.StatusCode, body, err)
	}
	return string(body), resp.TLS.DidResume
}

func TestH3ClientAuthRejectsMissingOrUntrustedCertificate(t *testing.T) {
	certs := newH3ClientCerts(t)
	hs := startMTLSH3(t, certs)
	cases := []struct {
		name  string
		cert  *tls.Certificate
		alert uint64
	}{
		{"no certificate", nil, alertCertificateRequired},
		{"untrusted issuer", &certs.unknown, alertUnknownCA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h3HandshakeCloseCode(t, hs.addr, mtlsClientTLS(tc.cert))
			if want := quic.TransportErrorCode(quicCryptoErrorBase + tc.alert); got != want {
				t.Fatalf("CONNECTION_CLOSE %#x, want %#x", uint64(got), uint64(want))
			}
		})
	}
}

func TestH3ClientAuthExposesPeerCertificate(t *testing.T) {
	certs := newH3ClientCerts(t)
	hs := startMTLSH3(t, certs)
	if who, _ := h3Whoami(t, clientTLS(), hs.addr); who != "none" {
		t.Fatalf("host without client auth reported %q", who)
	}
	cfg := mtlsClientTLS(&certs.valid)
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	who, resumed := h3Whoami(t, cfg, hs.addr)
	if who != "valid-client" || resumed {
		t.Fatalf("first connection: %q resumed=%v", who, resumed)
	}
	for i := 0; i < 2; i++ {
		who, resumed = h3Whoami(t, cfg, hs.addr)
		if who != "valid-client" || !resumed {
			t.Fatalf("connection %d: %q resumed=%v, want a resumed session that keeps the certificate", i+2, who, resumed)
		}
	}
}
