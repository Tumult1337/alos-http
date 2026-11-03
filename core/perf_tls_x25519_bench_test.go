//go:build linux && amd64

package core

import "testing"

func BenchmarkPerfTLSX25519Keygen(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		kp, err := generateX25519Keypair()
		if err != nil {
			b.Fatal(err)
		}
		kp.zero()
	}
}

func BenchmarkPerfTLSX25519Shared(b *testing.B) {
	kp, err := generateX25519Keypair()
	if err != nil {
		b.Fatal(err)
	}
	peer, err := generateX25519Keypair()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := kp.sharedSecret(peer.pub[:]); !ok {
			b.Fatal("shared secret rejected")
		}
	}
}
