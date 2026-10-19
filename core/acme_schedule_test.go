//go:build linux && amd64

package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func rateLimitedError(retryAfter string) error {
	return &acme.Error{
		StatusCode:  http.StatusTooManyRequests,
		ProblemType: "urn:ietf:params:acme:error:rateLimited",
		Header:      http.Header{"Retry-After": {retryAfter}},
	}
}

func TestACMEBackoff(t *testing.T) {
	generic := errors.New("connection refused")
	for failures := 1; failures <= 14; failures++ {
		base := min(acmeBackoffBase<<(failures-1), acmeBackoffMax)
		lo, hi := base-base/10, base+base/10
		for i := 0; i < 50; i++ {
			if d := acmeRetryDelay(generic, failures); d < lo || d > hi {
				t.Fatalf("failure %d: delay %v outside [%v, %v]", failures, d, lo, hi)
			}
		}
	}
	if d := acmeRetryDelay(rateLimitedError("2"), 1); d != 2*time.Second {
		t.Fatalf("rate limited with Retry-After 2: %v, want 2s", d)
	}
	if d := acmeRetryDelay(rateLimitedError("259200"), 1); d != acmeBackoffMax {
		t.Fatalf("rate limited with Retry-After of three days: %v, want the 24h cap", d)
	}
	if d := acmeRetryDelay(rateLimitedError(""), 3); d < 18*time.Minute || d > 22*time.Minute {
		t.Fatalf("rate limited without Retry-After: %v, want the regular backoff", d)
	}
	plain429 := &acme.Error{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"2"}}}
	if d := acmeRetryDelay(plain429, 1); d < 4*time.Minute {
		t.Fatalf("429 without the rateLimited problem type: %v, want the regular backoff", d)
	}
}

func TestARICertID(t *testing.T) {
	aki := []byte{0x69, 0x88, 0x5B, 0x6B, 0x87, 0x46, 0x40, 0x41, 0xE1, 0xB3, 0x7B, 0x84, 0x7B, 0xA0, 0xAE, 0x2C, 0xDE, 0x01, 0xC8, 0xD4}
	for _, tc := range []struct {
		serial *big.Int
		want   string
	}{
		{big.NewInt(0x87654321), "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"},
		{big.NewInt(0x7f), "aYhba4dGQEHhs3uEe6CuLN4ByNQ.fw"},
		{big.NewInt(0), "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AA"},
	} {
		if got, ok := ariCertID(&x509.Certificate{AuthorityKeyId: aki, SerialNumber: tc.serial}); !ok || got != tc.want {
			t.Errorf("serial %x: %q, want %q", tc.serial, got, tc.want)
		}
	}
	if _, ok := ariCertID(&x509.Certificate{SerialNumber: big.NewInt(1)}); ok {
		t.Error("certificate without an AKI produced an ID")
	}
	if _, ok := ariCertID(&x509.Certificate{AuthorityKeyId: aki, SerialNumber: big.NewInt(-1)}); ok {
		t.Error("negative serial produced an ID")
	}
}

func TestARIPollInterval(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{
		"21600":  6 * time.Hour,
		"30":     time.Minute,
		"0":      time.Minute,
		"999999": 24 * time.Hour,
		"":       6 * time.Hour,
		"soon":   6 * time.Hour,
		"-5":     6 * time.Hour,
		now.Add(2 * time.Hour).Format(http.TimeFormat): 2 * time.Hour,
		now.Add(-time.Hour).Format(http.TimeFormat):    time.Minute,
	} {
		if got := ariPollInterval(in, now); got != want {
			t.Errorf("Retry-After %q: %v, want %v", in, got, want)
		}
	}
}

type ariStub struct {
	srv        *httptest.Server
	mu         sync.Mutex
	withARI    bool
	start, end time.Time
	retryAfter string
	certID     string
	polls      atomic.Int32
}

func newARIStub(t *testing.T, withARI bool) *ariStub {
	s := &ariStub{withARI: withARI, retryAfter: "21600"}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case r.URL.Path == "/dir":
			if s.withARI {
				fmt.Fprintf(w, `{"newNonce":"%[1]s/nonce","renewalInfo":"%[1]s/ari"}`, s.srv.URL)
				return
			}
			fmt.Fprintf(w, `{"newNonce":"%s/nonce"}`, s.srv.URL)
		case strings.HasPrefix(r.URL.Path, "/ari/"):
			s.polls.Add(1)
			if strings.TrimPrefix(r.URL.Path, "/ari/") != s.certID {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Retry-After", s.retryAfter)
			fmt.Fprintf(w, `{"suggestedWindow":{"start":%q,"end":%q},"explanationURL":"https://ca.test/why"}`,
				s.start.Format(time.RFC3339), s.end.Format(time.RFC3339))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *ariStub) setWindow(start, end time.Time) {
	s.mu.Lock()
	s.start, s.end = start, end
	s.mu.Unlock()
}

type acmeScheduleFixture struct {
	ai       *acmeIntegration
	leaf     *x509.Certificate
	clock    time.Time
	obtained atomic.Int32
	obtainFn func() error
}

func newACMEScheduleFixture(t *testing.T, stub *ariStub) *acmeScheduleFixture {
	t.Helper()
	srv := New(Config{Addr: "127.0.0.1:0", HTTPAddr: "-", LogRequests: false, DisableOCSPStapling: true})
	ai := newACMEIntegration(ACMEConfig{CacheDir: t.TempDir(), ACMENode: stub.srv.URL + "/dir"}, srv)
	if ai == nil {
		t.Fatal("no integration")
	}
	f := &acmeScheduleFixture{ai: ai, clock: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	ai.now = func() time.Time { return f.clock }
	ai.httpClient = stub.srv.Client()
	ai.obtainCert = func(string) error {
		f.obtained.Add(1)
		if f.obtainFn != nil {
			return f.obtainFn()
		}
		return nil
	}

	ca := newTestCA(t, "ari CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := ca.issue(t, leafSpec{cn: "ari.test", dnsNames: []string{"ari.test"}, notBefore: f.clock.Add(-time.Hour), notAfter: f.clock.Add(60 * 24 * time.Hour), usage: x509.ExtKeyUsageServerAuth, key: key})
	f.leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := NewCertEntryFromPEM("ari.test",
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), CertACME)
	if err != nil {
		t.Fatal(err)
	}
	srv.certStore.AddCert(entry)
	id, ok := ariCertID(f.leaf)
	if !ok {
		t.Fatal("test leaf has no ARI ID")
	}
	stub.certID = id
	return f
}

func TestACMEARI(t *testing.T) {
	t.Run("renewal is scheduled inside the suggested window", func(t *testing.T) {
		stub := newARIStub(t, true)
		f := newACMEScheduleFixture(t, stub)
		start, end := f.clock.Add(time.Hour), f.clock.Add(2*time.Hour)
		stub.setWindow(start, end)
		_, renewAt, nextPoll := f.ai.renewalTime(context.Background(), "ari.test", f.leaf)
		if renewAt.Before(start) || !renewAt.Before(end) {
			t.Fatalf("renewal at %v outside [%v, %v)", renewAt, start, end)
		}
		if want := f.clock.Add(6 * time.Hour); !nextPoll.Equal(want) {
			t.Fatalf("next poll %v, want %v from Retry-After", nextPoll, want)
		}
		wake := f.ai.renewAll()
		if f.obtained.Load() != 0 {
			t.Fatal("renewed before the chosen time")
		}
		if wake != renewAt.Sub(f.clock) {
			t.Fatalf("loop sleeps %v, want %v (until the chosen time)", wake, renewAt.Sub(f.clock))
		}
		if polls := stub.polls.Load(); polls != 1 {
			t.Fatalf("renewalInfo fetched %d times before Retry-After elapsed, want 1", polls)
		}
		f.clock = renewAt
		f.ai.renewAll()
		if f.obtained.Load() != 1 {
			t.Fatalf("renewed %d times at the chosen time, want 1", f.obtained.Load())
		}
	})

	t.Run("a window in the past renews immediately", func(t *testing.T) {
		stub := newARIStub(t, true)
		f := newACMEScheduleFixture(t, stub)
		stub.setWindow(f.clock.Add(-2*time.Hour), f.clock.Add(-time.Hour))
		f.ai.renewAll()
		if f.obtained.Load() != 1 {
			t.Fatalf("renewed %d times, want 1", f.obtained.Load())
		}
	})

	t.Run("a moved window is followed after Retry-After", func(t *testing.T) {
		stub := newARIStub(t, true)
		f := newACMEScheduleFixture(t, stub)
		stub.retryAfter = "3600"
		stub.setWindow(f.clock.Add(20*24*time.Hour), f.clock.Add(21*24*time.Hour))
		f.ai.renewAll()
		newStart, newEnd := f.clock.Add(90*time.Minute), f.clock.Add(100*time.Minute)
		stub.setWindow(newStart, newEnd)
		f.clock = f.clock.Add(30 * time.Minute)
		_, renewAt, _ := f.ai.renewalTime(context.Background(), "ari.test", f.leaf)
		if renewAt.Before(f.clock.Add(-30 * time.Minute).Add(20 * 24 * time.Hour)) {
			t.Fatal("window re-read before Retry-After elapsed")
		}
		f.clock = f.clock.Add(31 * time.Minute)
		_, renewAt, _ = f.ai.renewalTime(context.Background(), "ari.test", f.leaf)
		if renewAt.Before(newStart) || !renewAt.Before(newEnd) {
			t.Fatalf("renewal at %v after the window moved to [%v, %v)", renewAt, newStart, newEnd)
		}
	})

	t.Run("without renewalInfo the 30-day rule applies", func(t *testing.T) {
		stub := newARIStub(t, false)
		f := newACMEScheduleFixture(t, stub)
		_, renewAt, nextPoll := f.ai.renewalTime(context.Background(), "ari.test", f.leaf)
		if want := f.leaf.NotAfter.Add(-30 * 24 * time.Hour); !renewAt.Equal(want) || !nextPoll.IsZero() {
			t.Fatalf("renewal at %v poll %v, want %v and no polling", renewAt, nextPoll, want)
		}
		if wake := f.ai.renewAll(); wake != 6*time.Hour || f.obtained.Load() != 0 {
			t.Fatalf("wake %v renewals %d, want the 6h check and none", wake, f.obtained.Load())
		}
	})

	t.Run("a failing renewalInfo endpoint falls back and retries in 6h", func(t *testing.T) {
		stub := newARIStub(t, true)
		f := newACMEScheduleFixture(t, stub)
		stub.certID = "not-this-certificate"
		_, renewAt, nextPoll := f.ai.renewalTime(context.Background(), "ari.test", f.leaf)
		if want := f.leaf.NotAfter.Add(-30 * 24 * time.Hour); !renewAt.Equal(want) {
			t.Fatalf("renewal at %v, want the 30-day fallback %v", renewAt, want)
		}
		if want := f.clock.Add(6 * time.Hour); !nextPoll.Equal(want) {
			t.Fatalf("next poll %v, want %v", nextPoll, want)
		}
	})
}

func TestACMERenewalBackoff(t *testing.T) {
	stub := newARIStub(t, true)
	f := newACMEScheduleFixture(t, stub)
	stub.setWindow(f.clock.Add(-2*time.Hour), f.clock.Add(-time.Hour))
	f.obtainFn = func() error { return rateLimitedError("2") }
	f.ai.renewAll()
	if f.obtained.Load() != 1 {
		t.Fatalf("attempts %d, want 1", f.obtained.Load())
	}
	f.clock = f.clock.Add(time.Second)
	f.ai.renewAll()
	if f.obtained.Load() != 1 {
		t.Fatal("retried before Retry-After elapsed")
	}
	f.clock = f.clock.Add(time.Second)
	f.obtainFn = func() error { return errors.New("validation failed") }
	f.ai.renewAll()
	if f.obtained.Load() != 2 {
		t.Fatalf("attempts %d after Retry-After, want 2", f.obtained.Load())
	}
	f.clock = f.clock.Add(4 * time.Minute)
	f.ai.renewAll()
	if f.obtained.Load() != 2 {
		t.Fatal("retried before the backoff elapsed")
	}
	f.clock = f.clock.Add(10 * time.Minute)
	f.obtainFn = nil
	f.ai.renewAll()
	if f.obtained.Load() != 3 {
		t.Fatalf("attempts %d after the backoff, want 3", f.obtained.Load())
	}
	f.ai.schedule.mu.Lock()
	st := f.ai.schedule.states["ari.test"]
	f.ai.schedule.mu.Unlock()
	if st.failures != 0 || !st.retryAt.IsZero() {
		t.Fatalf("success did not clear the backoff: %+v", st)
	}
}
