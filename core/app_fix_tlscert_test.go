//go:build linux && amd64

package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestAppFixOCSPStapleFromTheFutureRejected(t *testing.T) {
	f := newOCSPFixture(t, true)
	now := wallNow()
	future := f.template(ocsp.Good, now.Add(2*time.Hour))
	future.ThisUpdate = now.Add(time.Hour)
	if _, err := validateOCSPStaple(f.sign(t, future), f.leafCert, f.ca.cert, now); !errors.Is(err, errOCSPNotYetValid) {
		t.Fatalf("OCSP response dated one hour ahead: err=%v, want errOCSPNotYetValid", err)
	}
	withinSkew := f.template(ocsp.Good, now.Add(2*time.Hour))
	withinSkew.ThisUpdate = now.Add(ocspClockSkew / 2)
	if _, err := validateOCSPStaple(f.sign(t, withinSkew), f.leafCert, f.ca.cert, now); err != nil {
		t.Fatalf("OCSP response within the clock skew rejected: %v", err)
	}
}

func TestAppFixTLSCertFileKeyMismatchIsAnErrorAndFilesKept(t *testing.T) {
	f := newOCSPFixture(t, false)
	certFile, keyFile := f.writeFiles(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyFile, wrongKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrGenerateCert(certFile, keyFile); !errors.Is(err, errCertKeyMismatch) {
		t.Fatalf("TLSCertFile with a mismatched key: err=%v, want errCertKeyMismatch", err)
	}
	if got, _ := os.ReadFile(keyFile); string(got) != string(wrongKeyPEM) {
		t.Fatal("the operator's key file was overwritten after a mismatch")
	}
	if err := os.WriteFile(keyFile, f.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrGenerateCert(certFile, keyFile); err != nil {
		t.Fatalf("matching pair rejected: %v", err)
	}
}
