//go:build linux && amd64

package core

import "testing"

const (
	tlsEpollFixIANAAEGIS256SHA512 = 0x1306
	tlsEpollFixAES128GCMSHA256    = 0x1301
)

func TestTLSEpollFixAEGISUsesRegisteredCodePoint(t *testing.T) {
	if s := NegotiateSuite([]uint16{tlsEpollFixIANAAEGIS256SHA512}); s != nil {
		t.Fatalf("0x1306 (IANA TLS_AEGIS_256_SHA512) negotiated as suite %#04x with a different construction", s.ID)
	}
	if s := NegotiateSuite([]uint16{tlsEpollFixIANAAEGIS256SHA512, tlsEpollFixAES128GCMSHA256}); s == nil || s.ID != tlsEpollFixAES128GCMSHA256 {
		t.Fatalf("client offering 0x1306 then 0x1301 got %v, want 0x1301", s)
	}
	s := NegotiateSuite([]uint16{tlsAEGIS128LSHA256})
	if s == nil || s.KeyLen != 16 || s.HashLen != 32 {
		t.Fatalf("TLS_AEGIS_128L_SHA256 (0x1307) not negotiated as AEGIS-128L/SHA-256: %+v", s)
	}
	aead, err := s.MakeAEAD(make([]byte, s.KeyLen))
	if err != nil || aead.NonceSize() != s.IVLen || aead.Overhead() != 16 {
		t.Fatalf("0x1307 AEAD: err=%v nonce=%d tag=%d, want 16-byte nonce and 128-bit tag", err, aead.NonceSize(), aead.Overhead())
	}
	if q := negotiateQUICSuite([]uint16{tlsAEGIS128LSHA256, tlsEpollFixAES128GCMSHA256}); q == nil || q.ID != tlsEpollFixAES128GCMSHA256 {
		t.Fatalf("QUIC negotiated %v; AEGIS has no AEGIS-based QUIC header protection here, want 0x1301", q)
	}
	for i := range SupportedSuites {
		if SupportedSuites[i].HashLen > maxTrafficSecretLen {
			t.Fatalf("suite %#04x traffic secret (%d bytes) does not fit TrafficAEAD", SupportedSuites[i].ID, SupportedSuites[i].HashLen)
		}
	}
}
