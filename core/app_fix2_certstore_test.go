//go:build linux && amd64

package core

import (
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	appFix2SetDefaultSettle = 150 * time.Millisecond
	appFix2SetDefaultFinish = 2 * time.Second
)

func TestAppFix2CertStoreSetDefaultSerializesWithRenewal(t *testing.T) {
	cs := NewCertStore()
	original := &CertEntry{Domain: "a.example"}
	explicit := &CertEntry{Domain: "b.example"}
	cs.AddCert(original)
	cs.AddCert(explicit)

	cs.mu.Lock()
	renewalSawDefault := cs.defEntry.Load()
	done := make(chan struct{})
	go func() {
		cs.SetDefault("b.example")
		close(done)
	}()
	select {
	case <-done:
	case <-turbo.After(appFix2SetDefaultSettle):
	}
	renewed := &CertEntry{Domain: "a.example"}
	cs.certs.Store(renewed.Domain, renewed)
	if renewalSawDefault == nil || renewalSawDefault.Domain == renewed.Domain {
		cs.defEntry.Store(renewed)
	}
	cs.mu.Unlock()

	select {
	case <-done:
	case <-turbo.After(appFix2SetDefaultFinish):
		t.Fatal("SetDefault never returned after the renewal released cs.mu")
	}
	if got := cs.Lookup(""); got != explicit {
		t.Fatalf("default after concurrent renewal+SetDefault is %q %p, want the explicit default %p", got.Domain, got, explicit)
	}
}
