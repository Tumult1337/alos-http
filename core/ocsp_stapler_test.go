//go:build linux && amd64

package core

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/crypto/ocsp"
)

const (
	ocspTestDomain     = "ocsp.test"
	ocspAbsenceWindow  = 150 * time.Millisecond
	ocspStapleDeadline = 3 * time.Second
	ocspPollInterval   = 15 * time.Millisecond
)

type ocspResponderMode int32

const (
	respondGood ocspResponderMode = iota
	respondRevoked
	respondServerError
)

type ocspFixture struct {
	ca       testCA
	leafCert *x509.Certificate
	chainPEM []byte
	keyPEM   []byte
	server   *httptest.Server
	hits     atomic.Int64
	mode     atomic.Int32
}

func newOCSPFixture(t testing.TB, withURL bool) *ocspFixture {
	t.Helper()
	f := &ocspFixture{ca: newTestCA(t, "ocsp test CA")}
	f.server = httptest.NewServer(http.HandlerFunc(f.respond))
	t.Cleanup(f.server.Close)
	now := wallNow()
	spec := leafSpec{
		cn:        ocspTestDomain,
		dnsNames:  []string{ocspTestDomain},
		usage:     x509.ExtKeyUsageServerAuth,
		notBefore: now.Add(-time.Hour),
		notAfter:  now.Add(24 * time.Hour),
	}
	if withURL {
		spec.ocspURLs = []string{f.server.URL}
	}
	leaf := f.ca.issue(t, spec)
	var err error
	if f.leafCert, err = x509.ParseCertificate(leaf.Certificate[0]); err != nil {
		t.Fatal(err)
	}
	f.chainPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.cert.Raw})...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	f.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return f
}

func (f *ocspFixture) template(status int, nextUpdate time.Time) ocsp.Response {
	now := wallNow()
	tmpl := ocsp.Response{
		Status:       status,
		SerialNumber: f.leafCert.SerialNumber,
		ThisUpdate:   now.Add(-time.Minute),
		NextUpdate:   nextUpdate,
	}
	if status == ocsp.Revoked {
		tmpl.RevokedAt = now.Add(-time.Minute)
		tmpl.RevocationReason = ocsp.KeyCompromise
	}
	return tmpl
}

func (f *ocspFixture) sign(t testing.TB, tmpl ocsp.Response) []byte {
	t.Helper()
	der, err := ocsp.CreateResponse(f.ca.cert, f.ca.cert, tmpl, f.ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (f *ocspFixture) goodResponse(t testing.TB) []byte {
	return f.sign(t, f.template(ocsp.Good, wallNow().Add(time.Hour)))
}

func (f *ocspFixture) respond(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := ocsp.ParseRequest(body); err != nil || r.Header.Get("Content-Type") != ocspRequestContentType {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	status := ocsp.Good
	switch ocspResponderMode(f.mode.Load()) {
	case respondServerError:
		w.WriteHeader(http.StatusInternalServerError)
		return
	case respondRevoked:
		status = ocsp.Revoked
	}
	der, err := ocsp.CreateResponse(f.ca.cert, f.ca.cert, f.template(status, wallNow().Add(time.Hour)), f.ca.key)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(der)
}

func (f *ocspFixture) entry(t testing.TB) *CertEntry {
	t.Helper()
	entry, err := NewCertEntryFromPEM(ocspTestDomain, f.chainPEM, f.keyPEM, CertManual)
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func (f *ocspFixture) writeFiles(t testing.TB) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, f.chainPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, f.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func (f *ocspFixture) delegatedResponse(t testing.TB, usage x509.ExtKeyUsage) []byte {
	t.Helper()
	now := wallNow()
	responder := f.ca.issue(t, leafSpec{cn: "ocsp responder", usage: usage, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)})
	cert, err := x509.ParseCertificate(responder.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	tmpl := f.template(ocsp.Good, now.Add(time.Hour))
	tmpl.Certificate = cert
	der, err := ocsp.CreateResponse(f.ca.cert, cert, tmpl, responder.PrivateKey.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func waitForOCSP(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := turbo.Deadline(ocspStapleDeadline)
	for !cond() {
		if turbo.Until(deadline) <= 0 {
			t.Fatalf("timed out waiting for %s", what)
		}
		turbo.Sleep(ocspPollInterval)
	}
}

func TestOCSPValidateStaple(t *testing.T) {
	f := newOCSPFixture(t, true)
	now := wallNow()
	other := newTestCA(t, "other CA")
	foreign, err := ocsp.CreateResponse(other.cert, other.cert, f.template(ocsp.Good, now.Add(time.Hour)), other.key)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		der  []byte
		want error
	}{
		{"good", f.goodResponse(t), nil},
		{"delegated responder with OCSP signing", f.delegatedResponse(t, x509.ExtKeyUsageOCSPSigning), nil},
		{"delegated responder without OCSP signing", f.delegatedResponse(t, x509.ExtKeyUsageServerAuth), errOCSPResponder},
		{"revoked", f.sign(t, f.template(ocsp.Revoked, now.Add(time.Hour))), errOCSPNotGood},
		{"unknown", f.sign(t, f.template(ocsp.Unknown, now.Add(time.Hour))), errOCSPNotGood},
		{"expired", f.sign(t, f.template(ocsp.Good, now.Add(-time.Second))), errOCSPExpired},
		{"no nextUpdate", f.sign(t, f.template(ocsp.Good, time.Time{})), errOCSPExpired},
		{"oversized", make([]byte, maxOCSPResponseLen+1), errOCSPTooLarge},
	}
	for _, c := range cases {
		_, err := validateOCSPStaple(c.der, f.leafCert, f.ca.cert, now)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err=%v, want %v", c.name, err, c.want)
		}
	}
	for name, der := range map[string][]byte{"signed by another CA": foreign, "garbage": {0x30, 0x03, 0x02, 0x01, 0x00}} {
		if _, err := validateOCSPStaple(der, f.leafCert, f.ca.cert, now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSetOCSPStaple(t *testing.T) {
	f := newOCSPFixture(t, false)
	entry := f.entry(t)
	der := f.goodResponse(t)
	if err := entry.SetOCSPStaple(der); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entry.OCSPStaple(), der) {
		t.Fatal("staple not stored")
	}
	der[len(der)-1] ^= 1
	if bytes.Equal(entry.OCSPStaple(), der) {
		t.Fatal("staple aliases the caller's buffer")
	}
	requested := &ParsedClientHello{statusRequest: true}
	if entry.stapleFor(&ParsedClientHello{}) != nil || entry.stapleFor(requested) == nil {
		t.Fatal("staple must be served exactly when the client asks for it")
	}
	if err := entry.SetOCSPStaple(f.sign(t, f.template(ocsp.Revoked, wallNow().Add(time.Hour)))); !errors.Is(err, errOCSPNotGood) {
		t.Fatalf("revoked staple: %v", err)
	}
	if entry.OCSPStaple() == nil {
		t.Fatal("a rejected staple replaced the valid one")
	}

	stale := *entry.staple.Load()
	stale.nextUpdateNs = turbo.UnixNano() - 1
	entry.staple.Store(&stale)
	if entry.OCSPStaple() != nil || entry.stapleFor(requested) != nil {
		t.Fatal("expired staple still served")
	}

	selfSigned := NewCertEntryFromDER("self.test", f.ca.cert.Raw, f.ca.key, CertSelfSigned)
	if err := selfSigned.SetOCSPStaple(der); !errors.Is(err, errOCSPNoIssuer) {
		t.Fatalf("single-certificate chain: %v", err)
	}
}

func TestBuildCertificate13Staple(t *testing.T) {
	chain := [][]byte{bytes.Repeat([]byte{1}, 40), bytes.Repeat([]byte{2}, 30)}
	if plain := BuildCertificate(chain); !bytes.Equal(plain[tlsHandshakeHeaderLen:], certificate13Body(chain, 0, nil)) {
		t.Fatal("BuildCertificate changed its encoding")
	}
	status := appendOCSPStatus(nil, []byte("ocsp-der"))
	if !bytes.Equal(status, []byte{ocspStatusTypeOCSP, 0, 0, 8, 'o', 'c', 's', 'p', '-', 'd', 'e', 'r'}) {
		t.Fatalf("CertificateStatus body %x", status)
	}
	msg := buildCertificate13(chain, status)
	if msg[0] != tlsHSCertificate || readU24(msg[1:]) != len(msg)-tlsHandshakeHeaderLen {
		t.Fatalf("bad header %x", msg[:4])
	}
	leafExt := []byte{byte(tlsExtStatusRequest >> 8), byte(tlsExtStatusRequest), 0, byte(len(status))}
	leafExt = append(leafExt, status...)
	list := append([]byte{0, 0, 40}, chain[0]...)
	list = append(list, 0, byte(len(leafExt)))
	list = append(list, leafExt...)
	list = append(list, 0, 0, 30)
	list = append(list, chain[1]...)
	list = append(list, 0, 0)
	want := []byte{0, byte(len(list) >> 16), byte(len(list) >> 8), byte(len(list))}
	want = append(want, list...)
	if !bytes.Equal(msg[tlsHandshakeHeaderLen:], want) {
		t.Fatalf("stapled Certificate body\n got %x\nwant %x", msg[tlsHandshakeHeaderLen:], want)
	}
	parsed, _, ok := parseClientCertificate(msg[tlsHandshakeHeaderLen:], true)
	if !ok || len(parsed) != 2 {
		t.Fatal("stapled Certificate does not parse as a TLS 1.3 Certificate")
	}
}

func TestOCSPRefreshDelay(t *testing.T) {
	base := wallNow()
	resp := &ocsp.Response{ThisUpdate: base, NextUpdate: base.Add(4 * time.Hour)}
	if got := ocspRefreshDelay(resp, base.Add(time.Hour)); got != time.Hour {
		t.Fatalf("delay %v, want 1h (midpoint)", got)
	}
	if got := ocspRefreshDelay(resp, base.Add(3*time.Hour)); got != ocspRetryMin {
		t.Fatalf("past the midpoint: delay %v, want %v", got, ocspRetryMin)
	}
}

func newTrackedStore(t testing.TB) (*CertStore, *ocspStapler) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	store := NewCertStore()
	stapler := newOCSPStapler(store, done)
	store.onAdd = stapler.track
	return store, stapler
}

func TestOCSPStaplerFetches(t *testing.T) {
	f := newOCSPFixture(t, true)
	store, _ := newTrackedStore(t)
	entry := f.entry(t)
	store.AddCert(entry)
	waitForOCSP(t, "a fetched staple", func() bool { return entry.OCSPStaple() != nil })
	resp, err := ocsp.ParseResponse(entry.OCSPStaple(), f.ca.cert)
	if err != nil || resp.Status != ocsp.Good || resp.SerialNumber.Cmp(f.leafCert.SerialNumber) != 0 {
		t.Fatalf("stapled response %+v (%v)", resp, err)
	}
}

func TestOCSPStaplerKeepsNoStapleOnFailure(t *testing.T) {
	for _, mode := range []ocspResponderMode{respondServerError, respondRevoked} {
		f := newOCSPFixture(t, true)
		f.mode.Store(int32(mode))
		store, _ := newTrackedStore(t)
		entry := f.entry(t)
		store.AddCert(entry)
		waitForOCSP(t, "a fetch attempt", func() bool { return f.hits.Load() > 0 })
		turbo.Sleep(ocspAbsenceWindow)
		if entry.OCSPStaple() != nil {
			t.Fatalf("mode %d: staple stored from a failed fetch", mode)
		}
	}
}

func TestOCSPStaplerSkipsCertificatesWithoutResponder(t *testing.T) {
	f := newOCSPFixture(t, false)
	store, _ := newTrackedStore(t)
	entry := f.entry(t)
	store.AddCert(entry)
	store.AddCert(NewCertEntryFromDER("self.test", f.ca.cert.Raw, f.ca.key, CertSelfSigned))
	turbo.Sleep(ocspAbsenceWindow)
	if f.hits.Load() != 0 || entry.OCSPStaple() != nil {
		t.Fatalf("%d fetches for a certificate without an OCSP URL", f.hits.Load())
	}
}

func TestOCSPStaplerStopsForReplacedCertificate(t *testing.T) {
	f := newOCSPFixture(t, true)
	store, stapler := newTrackedStore(t)
	old := f.entry(t)
	store.AddCert(old)
	if !stapler.current(old) {
		t.Fatal("tracked entry not current")
	}
	store.AddCert(f.entry(t))
	if stapler.current(old) {
		t.Fatal("replaced entry still current")
	}
}

func TestOCSPStapleFileConfig(t *testing.T) {
	f := newOCSPFixture(t, false)
	certFile, keyFile := f.writeFiles(t)
	stapleFile := filepath.Join(t.TempDir(), "staple.der")
	certConfig := func(staple string) Config {
		return Config{DisableOCSPStapling: true, Certs: []CertConfig{{Domain: ocspTestDomain, Source: CertManual, CertFile: certFile, KeyFile: keyFile, OCSPStapleFile: staple}}}
	}
	cases := []struct {
		name    string
		content []byte
		wantErr bool
	}{
		{"valid staple", f.goodResponse(t), false},
		{"revoked staple", f.sign(t, f.template(ocsp.Revoked, wallNow().Add(time.Hour))), true},
		{"garbage", []byte("not an OCSP response"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(stapleFile, c.content, 0o600); err != nil {
				t.Fatal(err)
			}
			s := New(certConfig(stapleFile))
			err := s.loadCerts()
			if (err != nil) != c.wantErr {
				t.Fatalf("loadCerts: %v", err)
			}
			if err != nil {
				if !strings.Contains(err.Error(), stapleFile) {
					t.Fatalf("error %q does not name the staple file", err)
				}
				return
			}
			if !bytes.Equal(s.certStore.Lookup(ocspTestDomain).OCSPStaple(), c.content) {
				t.Fatal("configured staple not served")
			}
		})
	}
	if err := New(certConfig(filepath.Join(t.TempDir(), "missing.der"))).loadCerts(); err == nil {
		t.Fatal("missing staple file accepted")
	}
}

func TestOCSPStaplingDisabledInstallsNoHook(t *testing.T) {
	if New(Config{DisableOCSPStapling: true}).certStore.onAdd != nil {
		t.Fatal("DisableOCSPStapling still tracks certificates")
	}
	if New(Config{}).certStore.onAdd == nil {
		t.Fatal("OCSP stapling is not on by default")
	}
}
