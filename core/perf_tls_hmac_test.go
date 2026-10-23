//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
)

func perfTLSHMACPattern(n, seed int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + seed*7 + 3)
	}
	return b
}

func perfTLSHMACRef(h func() hash.Hash, key []byte, msgs ...[]byte) []byte {
	mac := hmac.New(h, key)
	for _, m := range msgs {
		mac.Write(m)
	}
	return mac.Sum(nil)
}

func TestPerfTLSHMACMatchesStdlib(t *testing.T) {
	hashes := []struct {
		name string
		fn   func() hash.Hash
	}{{"sha256", sha256.New}, {"sha384", sha512.New384}}
	keyLens := []int{0, 1, 32, 48, 63, 64, 65, 127, 128, 129, 300}
	msgLens := []int{0, 1, 55, 64, 255, 256, 257, 700}
	for _, hs := range hashes {
		for _, kl := range keyLens {
			for _, ml := range msgLens {
				key := perfTLSHMACPattern(kl, kl)
				msg := perfTLSHMACPattern(ml, ml+1)
				want := perfTLSHMACRef(hs.fn, key, msg)
				m := acquireTLSHMAC(hs.fn, key)
				if m == nil {
					t.Fatalf("%s: no pooled HMAC", hs.name)
				}
				m.write(msg)
				got := m.sumTo(nil)
				m.restart()
				m.write(msg[:ml/2])
				m.write(msg[ml/2:])
				again := m.sumTo(nil)
				m.release()
				if !bytes.Equal(got, want) || !bytes.Equal(again, want) {
					t.Fatalf("%s key=%d msg=%d: pooled HMAC mismatch", hs.name, kl, ml)
				}
			}
		}
	}
}

func TestPerfTLSHMACUnknownHashFallsBack(t *testing.T) {
	if acquireTLSHMAC(sha512.New, []byte("k")) != nil {
		t.Fatal("sha512 must not use a pooled sha256/sha384 HMAC")
	}
	key := []byte("secret")
	want := perfTLSHMACRef(sha512.New, key, []byte("salt-ikm"))
	if got := TLSExtractTo(sha512.New, key, []byte("salt-ikm"), nil); !bytes.Equal(got, want) {
		t.Fatal("fallback TLSExtractTo mismatch")
	}
}

func TestPerfTLSHKDFMatchesStdlib(t *testing.T) {
	for i := range SupportedSuites {
		cs := &SupportedSuites[i]
		secret := perfTLSHMACPattern(cs.HashLen, i)
		ctx := perfTLSHMACPattern(cs.HashLen, i+9)
		for _, tc := range []struct {
			tmpl  *hkdfLabelTemplate
			label string
			ctx   []byte
			n     int
		}{
			{&cs.labelClientHSTraffic, "c hs traffic", ctx, cs.HashLen},
			{&cs.labelKey, "key", nil, cs.KeyLen},
			{&cs.labelIV, "iv", nil, cs.IVLen},
			{&cs.labelFinished, "finished", nil, cs.HashLen},
		} {
			want := TLSExpandLabel(cs.HashFn, secret, tc.label, tc.ctx, tc.n)
			var buf [64]byte
			if got := tc.tmpl.ExpandTo(cs.HashFn, secret, tc.ctx, buf[:0]); !bytes.Equal(got, want) {
				t.Fatalf("suite %#x %q: ExpandTo mismatch", cs.ID, tc.label)
			}
		}
		salt := perfTLSHMACPattern(cs.HashLen, i+3)
		ikm := perfTLSHMACPattern(64, i+4)
		if got, want := TLSExtractTo(cs.HashFn, salt, ikm, nil), perfTLSHMACRef(cs.HashFn, salt, ikm); !bytes.Equal(got, want) {
			t.Fatalf("suite %#x: TLSExtractTo mismatch", cs.ID)
		}
		if got, want := cs.ComputeFinishedTo(secret, ctx, nil), ComputeFinished(cs.HashFn, cs.HashLen, secret, ctx); !bytes.Equal(got, want) {
			t.Fatalf("suite %#x: ComputeFinishedTo mismatch", cs.ID)
		}
	}
}

func TestPerfTLS12PRFMatchesStdlib(t *testing.T) {
	for _, h := range []func() hash.Hash{sha256.New, sha512.New384} {
		for _, n := range []int{12, 32, 48, 64, 72, 104, 136} {
			secret := perfTLSHMACPattern(48, n)
			seed := perfTLSHMACPattern(64, n+1)
			want := tls12PRFGeneric(h, secret, []byte("key expansion"), seed, n)
			if got := tls12PRF(h, secret, []byte("key expansion"), seed, n); !bytes.Equal(got, want) {
				t.Fatalf("tls12PRF len=%d mismatch", n)
			}
		}
	}
}

func TestPerfTLSHKDFZeroAlloc(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops items at random under -race")
	}
	cs := &SupportedSuites[0]
	secret := perfTLSHMACPattern(cs.HashLen, 1)
	ctx := perfTLSHMACPattern(cs.HashLen, 2)
	var out [64]byte
	allocs := testing.AllocsPerRun(200, func() {
		cs.DeriveSecretTo(&cs.labelServerHSTraffic, secret, ctx, out[:0])
		TLSExtractTo(cs.HashFn, secret, ctx, out[:0])
		cs.ComputeFinishedTo(secret, ctx, out[:0])
	})
	if allocs > 0 {
		t.Fatalf("HKDF derive/extract/finished allocated %.1f per run, want 0", allocs)
	}
}

func BenchmarkPerfTLSHKDFDerive(b *testing.B) {
	cs := &SupportedSuites[0]
	secret := perfTLSHMACPattern(cs.HashLen, 1)
	ctx := perfTLSHMACPattern(cs.HashLen, 2)
	var out [64]byte
	b.ReportAllocs()
	for b.Loop() {
		cs.DeriveSecretTo(&cs.labelServerHSTraffic, secret, ctx, out[:0])
	}
}
