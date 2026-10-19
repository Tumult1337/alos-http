//go:build linux && amd64

package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const fpTLS12SchemeChildEnv = "ALOS_FP_TLS12_SCHEME_CHILD"

type tls12SchemeCase struct {
	name   string
	scheme uint16
	key    func(t *testing.T) crypto.Signer
}

func rsaTestKey(t *testing.T) crypto.Signer {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ecdsaTestKey(curve elliptic.Curve) func(t *testing.T) crypto.Signer {
	return func(t *testing.T) crypto.Signer {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
}

func ed25519TestKey(t *testing.T) crypto.Signer {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var tls12SchemeCases = []tls12SchemeCase{
	{"rsa_pkcs1_sha256", 0x0401, rsaTestKey},
	{"rsa_pkcs1_sha384", 0x0501, rsaTestKey},
	{"rsa_pkcs1_sha512", 0x0601, rsaTestKey},
	{"ecdsa_secp256r1_sha256", 0x0403, ecdsaTestKey(elliptic.P256())},
	{"ecdsa_secp384r1_sha384", 0x0503, ecdsaTestKey(elliptic.P384())},
	{"ecdsa_secp521r1_sha512", 0x0603, ecdsaTestKey(elliptic.P521())},
	{"rsa_pss_rsae_sha256", 0x0804, rsaTestKey},
	{"rsa_pss_rsae_sha384", 0x0805, rsaTestKey},
	{"rsa_pss_rsae_sha512", 0x0806, rsaTestKey},
	{"ed25519", 0x0807, ed25519TestKey},
}

func signTLS12(t *testing.T, key crypto.Signer, scheme uint16, msg []byte) []byte {
	t.Helper()
	var digest []byte
	var opts crypto.SignerOpts
	switch scheme {
	case 0x0401, 0x0403, 0x0804:
		d := sha256.Sum256(msg)
		digest, opts = d[:], crypto.SHA256
	case 0x0501, 0x0503, 0x0805:
		d := sha512.Sum384(msg)
		digest, opts = d[:], crypto.SHA384
	case 0x0601, 0x0603, 0x0806:
		d := sha512.Sum512(msg)
		digest, opts = d[:], crypto.SHA512
	case 0x0807:
		digest, opts = msg, crypto.Hash(0)
	}
	if scheme>>8 == 0x08 && scheme != 0x0807 {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: opts.HashFunc()}
	}
	sig, err := key.Sign(rand.Reader, digest, opts)
	if err != nil {
		t.Fatalf("sign scheme %#04x: %v", scheme, err)
	}
	return sig
}

func TestFPTLS12SchemeVerifiesEverySupportedScheme(t *testing.T) {
	msg := []byte("client_random || server_random || server_params")
	for _, c := range tls12SchemeCases {
		t.Run(c.name, func(t *testing.T) {
			key := c.key(t)
			sig := signTLS12(t, key, c.scheme, msg)
			if err := verifyTLS12Signature(key.Public(), c.scheme, msg, sig); err != nil {
				t.Fatalf("valid signature rejected: %v", err)
			}
			tampered := append([]byte(nil), sig...)
			tampered[len(tampered)/2] ^= 0x01
			if verifyTLS12Signature(key.Public(), c.scheme, msg, tampered) == nil {
				t.Fatal("tampered signature accepted")
			}
			if verifyTLS12Signature(key.Public(), c.scheme, append([]byte("x"), msg...), sig) == nil {
				t.Fatal("signature over different params accepted")
			}
		})
	}
}

func TestFPTLS12SchemeRejectsMismatchedKeyAndScheme(t *testing.T) {
	msg := []byte("params")
	rsaKey := rsaTestKey(t)
	ecKey := ecdsaTestKey(elliptic.P256())(t)
	pssSig := signTLS12(t, rsaKey, 0x0804, msg)
	if verifyTLS12Signature(rsaKey.Public(), 0x0401, msg, pssSig) == nil {
		t.Error("PSS signature accepted as PKCS#1 v1.5")
	}
	pkcsSig := signTLS12(t, rsaKey, 0x0401, msg)
	if verifyTLS12Signature(rsaKey.Public(), 0x0804, msg, pkcsSig) == nil {
		t.Error("PKCS#1 v1.5 signature accepted as PSS")
	}
	sha384Sig := signTLS12(t, rsaKey, 0x0501, msg)
	if verifyTLS12Signature(rsaKey.Public(), 0x0401, msg, sha384Sig) == nil {
		t.Error("SHA-384 signature accepted under a SHA-256 scheme")
	}
	ecSig := signTLS12(t, ecKey, 0x0403, msg)
	if verifyTLS12Signature(rsaKey.Public(), 0x0403, msg, ecSig) == nil {
		t.Error("ECDSA scheme accepted with an RSA key")
	}
	if verifyTLS12Signature(ecKey.Public(), 0x0401, msg, pkcsSig) == nil {
		t.Error("RSA scheme accepted with an ECDSA key")
	}
	for _, unknown := range []uint16{0x0201, 0x0203, 0x0808, 0x0809, 0x080a, 0x080b, 0x0000, 0xffff} {
		if verifyTLS12Signature(rsaKey.Public(), unknown, msg, pkcsSig) == nil {
			t.Errorf("unsupported scheme %#04x accepted", unknown)
		}
	}
}

func selfSignedTLS12Cert(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(4102444800, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestFPTLS12SchemeInterop(t *testing.T) {
	if os.Getenv(fpTLS12SchemeChildEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFPTLS12SchemeInterop$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), fpTLS12SchemeChildEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child run failed: %v\n%s", err, out)
		}
		return
	}

	type server struct {
		c       tls12SchemeCase
		version uint16
		srv     *httptest.Server
	}
	var servers []server
	var bundle []byte
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, c := range tls12SchemeCases {
			if version == tls.VersionTLS13 && c.scheme&0xff == 0x01 {
				continue
			}
			servers = append(servers, server{c: c, version: version})
		}
	}
	for i := range servers {
		c, version := servers[i].c, servers[i].version
		key := c.key(t)
		der := selfSignedTLS12Cert(t, key)
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))
		srv.TLS = &tls.Config{
			MinVersion: version,
			MaxVersion: version,
			NextProtos: []string{"http/1.1"},
			Certificates: []tls.Certificate{{
				Certificate:                  [][]byte{der},
				PrivateKey:                   key,
				SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.SignatureScheme(c.scheme)},
			}},
		}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		servers[i].srv = srv
	}
	certFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(certFile, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", certFile)
	t.Setenv("SSL_CERT_DIR", "")

	client := newTestClient(t)
	defer client.Close()
	for _, s := range servers {
		u, _ := url.Parse(s.srv.URL)
		resp, err := client.Do(&fpRequest{Scheme: "https", Authority: u.Host, Method: "GET", Path: "/"})
		if err != nil {
			t.Errorf("%s (%#04x) over %s: handshake with verification failed: %v", s.c.name, s.c.scheme, tls.VersionName(s.version), err)
			continue
		}
		if resp.Status != 200 || string(resp.Body) != "ok" {
			t.Errorf("%s: status %d body %q", s.c.name, resp.Status, resp.Body)
		}
	}
}
