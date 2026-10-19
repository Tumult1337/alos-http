//go:build linux && amd64

package core

import "testing"

func TestAppFixCertStoreRenewalReplacesDefault(t *testing.T) {
	cs := NewCertStore()
	original := &CertEntry{Domain: "a.example"}
	other := &CertEntry{Domain: "b.example"}
	renewed := &CertEntry{Domain: "A.example."}
	cs.AddCert(original)
	cs.AddCert(other)
	cs.AddCert(renewed)
	for _, sni := range []string{"", "1.2.3.4", "unknown.example", "a.example"} {
		if got := cs.Lookup(sni); got != renewed {
			t.Fatalf("Lookup(%q) after renewal returned %q entry %p, want the renewed entry %p", sni, got.Domain, got, renewed)
		}
	}
	if got := cs.Lookup("b.example"); got != other {
		t.Fatalf("Lookup(b.example) = %p, want %p", got, other)
	}
	cs.SetDefault("b.example")
	cs.AddCert(&CertEntry{Domain: "a.example"})
	if got := cs.Lookup(""); got != other {
		t.Fatal("renewing a non-default domain replaced an explicitly chosen default")
	}
}
