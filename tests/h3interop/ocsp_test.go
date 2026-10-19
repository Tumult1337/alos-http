package h3interop

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guno1928/alos-http/core"
	"github.com/guno1928/turbo"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/ocsp"
)

const ocspH3Domain = "ocsp.h3.test"

func writeStapledCert(t *testing.T) (core.CertConfig, []byte) {
	ca, caKey, _ := issueTestCert(t, "h3 ocsp CA", true, nil, nil, 10)
	leaf, leafKey, leafDER := issueTestCert(t, ocspH3Domain, false, ca, caKey, 11)
	now := time.Unix(0, turbo.UnixNano())
	staple, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   now.Add(-time.Minute),
		NextUpdate:   now.Add(time.Hour),
	}, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cc := core.CertConfig{
		Domain:         ocspH3Domain,
		Source:         core.CertManual,
		CertFile:       filepath.Join(dir, "cert.pem"),
		KeyFile:        filepath.Join(dir, "key.pem"),
		OCSPStapleFile: filepath.Join(dir, "staple.der"),
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	for path, data := range map[string][]byte{
		cc.CertFile:       chain,
		cc.KeyFile:        pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		cc.OCSPStapleFile: staple,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cc, staple
}

func TestH3OCSPStaple(t *testing.T) {
	cc, staple := writeStapledCert(t)
	hs := startH3(t, core.Config{DisableOCSPStapling: true, Certs: []core.CertConfig{cc}})
	cfg := clientTLS()
	cfg.ServerName = ocspH3Domain
	ctx, cancel := context.WithTimeout(context.Background(), alertDialTimeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, hs.addr, cfg, &quic.Config{HandshakeIdleTimeout: alertDialTimeout})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if got := conn.ConnectionState().TLS.OCSPResponse; !bytes.Equal(got, staple) {
		t.Fatalf("OCSP staple %d bytes, want the configured %d bytes", len(got), len(staple))
	}
}
