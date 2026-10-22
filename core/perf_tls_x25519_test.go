//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

const perfTLSX25519RandomCases = 2000

func perfTLSX25519Hex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func perfTLSX25519Stdlib(t testing.TB, priv, peer []byte) ([]byte, error) {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		t.Fatal(err)
	}
	return k.ECDH(p)
}

func TestPerfTLSX25519RFC7748Vector(t *testing.T) {
	var kp x25519Keypair
	copy(kp.priv[:], perfTLSX25519Hex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	peer := perfTLSX25519Hex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	want := perfTLSX25519Hex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
	got, ok := kp.sharedSecret(peer)
	if !ok || !bytes.Equal(got[:], want) {
		t.Fatalf("shared %x ok=%v, want %x", got, ok, want)
	}
	var base [x25519KeyLen]byte
	base[0] = 9
	pub, ok := kp.sharedSecret(base[:])
	if !ok || !bytes.Equal(pub[:], perfTLSX25519Hex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")) {
		t.Fatalf("public %x ok=%v", pub, ok)
	}
}

func TestPerfTLSX25519MatchesStdlib(t *testing.T) {
	for i := 0; i < perfTLSX25519RandomCases; i++ {
		kp, err := generateX25519Keypair()
		if err != nil {
			t.Fatal(err)
		}
		std, err := ecdh.X25519().NewPrivateKey(kp.priv[:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(kp.pub[:], std.PublicKey().Bytes()) {
			t.Fatalf("case %d: public key %x, stdlib %x", i, kp.pub, std.PublicKey().Bytes())
		}
		var peer [x25519KeyLen]byte
		if _, err := rand.Read(peer[:]); err != nil {
			t.Fatal(err)
		}
		got, ok := kp.sharedSecret(peer[:])
		want, werr := perfTLSX25519Stdlib(t, kp.priv[:], peer[:])
		if ok != (werr == nil) || (ok && !bytes.Equal(got[:], want)) {
			t.Fatalf("case %d: shared %x ok=%v, stdlib %x err=%v", i, got, ok, want, werr)
		}
	}
}

func TestPerfTLSX25519EdgeInputsMatchStdlib(t *testing.T) {
	kp, err := generateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	peers := [][]byte{
		make([]byte, x25519KeyLen),
		perfTLSX25519Hex(t, "0100000000000000000000000000000000000000000000000000000000000000"),
		perfTLSX25519Hex(t, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
		perfTLSX25519Hex(t, "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
		perfTLSX25519Hex(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		perfTLSX25519Hex(t, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		perfTLSX25519Hex(t, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		perfTLSX25519Hex(t, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		perfTLSX25519Hex(t, "0900000000000000000000000000000000000000000000000000000000000080"),
	}
	for i, peer := range peers {
		got, ok := kp.sharedSecret(peer)
		want, werr := perfTLSX25519Stdlib(t, kp.priv[:], peer)
		if ok != (werr == nil) || (ok && !bytes.Equal(got[:], want)) {
			t.Fatalf("peer %d %x: shared %x ok=%v, stdlib %x err=%v", i, peer, got, ok, want, werr)
		}
	}
	for _, n := range []int{0, 31, 33} {
		if _, ok := kp.sharedSecret(make([]byte, n)); ok {
			t.Fatalf("peer of %d bytes accepted", n)
		}
	}
}

func TestPerfTLSX25519ZeroAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	kp, err := generateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	peer := kp.pub
	if n := testing.AllocsPerRun(20, func() { _, _ = kp.sharedSecret(peer[:]) }); n != 0 {
		t.Fatalf("sharedSecret allocs = %v", n)
	}
	if n := testing.AllocsPerRun(20, func() { _, _ = generateX25519Keypair() }); n != 0 {
		t.Fatalf("generateX25519Keypair allocs = %v", n)
	}
}
