//go:build linux && amd64

package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guno1928/alosmap"
)

func appFixACMEWithChallengeDir(t *testing.T) (*acmeIntegration, string) {
	t.Helper()
	root := t.TempDir()
	challengeDir := filepath.Join(root, "challenges")
	if err := os.MkdirAll(challengeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return &acmeIntegration{challengeDir: challengeDir, challenges: alosmap.NewTyped[string, *acmeChallenge]()}, root
}

func TestAppFixACMECleanupRefusesTraversalToken(t *testing.T) {
	ai, root := appFixACMEWithChallengeDir(t)
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	ai.cleanupChallenge("example.com", "../victim")
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("a CA-supplied token ../victim deleted a file outside the challenge dir: %v", err)
	}
}

func TestAppFixACMETokenAlphabet(t *testing.T) {
	for _, ok := range []string{"evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA", "A", "a_b-c09"} {
		if !validACMEToken(ok) {
			t.Errorf("valid base64url token %q rejected", ok)
		}
	}
	for _, bad := range []string{"", "../../etc/cron.d/x", "a/b", "a\\b", "a.b", "a\x00b", "a=b", "a+b", "tok en"} {
		if validACMEToken(bad) {
			t.Errorf("token %q accepted", bad)
		}
	}
}

func TestAppFixACMEServeRejectsNonBase64URLToken(t *testing.T) {
	ai, _ := appFixACMEWithChallengeDir(t)
	ai.challenges.Store("example.com", &acmeChallenge{token: "a=b", auth: "a=b.thumb"})
	if _, ok := ai.HandleHTTP01("/.well-known/acme-challenge/a=b"); ok {
		t.Fatal("HTTP-01 served a token outside the base64url alphabet")
	}
	ai.challenges.Store("example.com", &acmeChallenge{token: "good_Token-1", auth: "good_Token-1.thumb"})
	if body, ok := ai.HandleHTTP01("/.well-known/acme-challenge/good_Token-1"); !ok || string(body) != "good_Token-1.thumb" {
		t.Fatalf("valid token served %q ok=%v", body, ok)
	}
}
