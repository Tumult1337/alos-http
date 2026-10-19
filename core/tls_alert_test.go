//go:build linux && amd64

package core

import (
	"errors"
	"testing"
)

func TestCertMissAlert(t *testing.T) {
	if got := certMissAlert("unknown.test"); got != alertUnrecognizedName {
		t.Fatalf("named miss: got %d, want unrecognized_name", got)
	}
	if got := certMissAlert(""); got != alertHandshakeFailure {
		t.Fatalf("SNI-less miss: got %d, want handshake_failure", got)
	}
}

func TestSignFailureAlert(t *testing.T) {
	if got := signFailureAlert(errNoCommonSignatureScheme); got != alertHandshakeFailure {
		t.Fatalf("no common scheme: got %d, want handshake_failure", got)
	}
	for _, err := range []error{errUnsupportedSignatureKey, errors.New("signer exploded")} {
		if got := signFailureAlert(err); got != alertInternalError {
			t.Fatalf("%v: got %d, want internal_error", err, got)
		}
	}
}

func TestRejectsProtocolVersion(t *testing.T) {
	cases := []struct {
		name     string
		legacy   uint16
		versions []uint16
		reject   bool
	}{
		{"TLS 1.0 only", 0x0301, nil, true},
		{"TLS 1.1 only", 0x0302, nil, true},
		{"TLS 1.2 legacy field", 0x0303, nil, false},
		{"TLS 1.3 via supported_versions", 0x0301, []uint16{0x0304}, false},
		{"supported_versions without 1.3", 0x0302, []uint16{0x0302}, true},
	}
	for _, tc := range cases {
		ch := ParsedClientHello{LegacyVersion: tc.legacy, SupportedVersions: tc.versions}
		if got := ch.rejectsProtocolVersion(); got != tc.reject {
			t.Errorf("%s: rejectsProtocolVersion = %v, want %v", tc.name, got, tc.reject)
		}
	}
}

func TestOffersALPN(t *testing.T) {
	ch := ParsedClientHello{ALPNProtos: []string{"h3-29", "h3"}}
	if !ch.offersALPN("h3") {
		t.Fatal("h3 offered but not found")
	}
	if ch.offersALPN("h2") {
		t.Fatal("h2 not offered but found")
	}
	if (&ParsedClientHello{}).offersALPN("h3") {
		t.Fatal("ALPN-less hello reported h3")
	}
}

func TestParseClientHelloLegacyVersion(t *testing.T) {
	body := make([]byte, 35)
	body[0], body[1] = 0x03, 0x02
	body = append(body, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00)
	msg := append([]byte{0x01, 0x00, 0x00, byte(len(body))}, body...)
	var ch ParsedClientHello
	if err := ParseClientHello(msg, &ch); err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if ch.LegacyVersion != 0x0302 {
		t.Fatalf("LegacyVersion = %#04x, want 0x0302", ch.LegacyVersion)
	}
}
