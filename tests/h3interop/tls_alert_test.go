package h3interop

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/guno1928/alos-http/core"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	quicCryptoErrorBase        = 0x0100
	alertHandshakeFailure      = 40
	alertNoApplicationProtocol = 120
	alertDialTimeout           = 2 * time.Second
)

func TestH3HandshakeFailuresCloseWithCryptoError(t *testing.T) {
	hs := startH3(t, core.Config{})
	cases := []struct {
		name   string
		mutate func(*tls.Config)
		alert  uint64
	}{
		{"client does not offer h3", func(c *tls.Config) { c.NextProtos = []string{"h2"} }, alertNoApplicationProtocol},
		{"client offers no supported group", func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP384} }, alertHandshakeFailure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := clientTLS()
			tc.mutate(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), alertDialTimeout)
			defer cancel()
			conn, err := quic.DialAddr(ctx, hs.addr, cfg, &quic.Config{HandshakeIdleTimeout: alertDialTimeout})
			if err == nil {
				_ = conn.CloseWithError(0, "")
				t.Fatal("handshake succeeded")
			}
			var te *quic.TransportError
			if !errors.As(err, &te) {
				t.Fatalf("got %v (%T), want a transport error", err, err)
			}
			if want := quic.TransportErrorCode(quicCryptoErrorBase + tc.alert); !te.Remote || te.ErrorCode != want {
				t.Fatalf("got remote=%v code=%#x, want remote CONNECTION_CLOSE %#x", te.Remote, uint64(te.ErrorCode), uint64(want))
			}
		})
	}
}

func TestH3KeyExchangeGroups(t *testing.T) {
	classical := startH3(t, core.Config{})
	pq := startH3(t, core.Config{TLSPreferPostQuantum: true})
	cases := []struct {
		name   string
		hs     *h3Server
		curves []tls.CurveID
		want   tls.CurveID
	}{
		{"Go defaults get X25519", classical, nil, tls.X25519},
		{"Go defaults with PQ preference get the hybrid", pq, nil, tls.X25519MLKEM768},
		{"P-256 share", classical, []tls.CurveID{tls.CurveP256}, tls.CurveP256},
		{"hybrid only", classical, []tls.CurveID{tls.X25519MLKEM768}, tls.X25519MLKEM768},
		{"unsupported share forces a HelloRetryRequest to X25519", classical, []tls.CurveID{tls.SecP384r1MLKEM1024, tls.X25519}, tls.X25519},
		{"unsupported share forces a HelloRetryRequest to P-256", classical, []tls.CurveID{tls.SecP384r1MLKEM1024, tls.CurveP256}, tls.CurveP256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := clientTLS()
			cfg.CurvePreferences = tc.curves
			tr := &http3.Transport{TLSClientConfig: cfg, QUICConfig: &quic.Config{HandshakeIdleTimeout: alertDialTimeout}}
			defer tr.Close()
			resp, err := (&http.Client{Transport: tr, Timeout: clientTimeout}).Get("https://" + tc.hs.addr + "/ping")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != 200 || string(body) != "pong" {
				t.Fatalf("got %d %q (%v)", resp.StatusCode, body, err)
			}
			if resp.TLS == nil || resp.TLS.CurveID != tc.want {
				t.Fatalf("negotiated %v, want %v", resp.TLS, tc.want)
			}
		})
	}
}

func h3GetWith(t *testing.T, cfg *tls.Config, store quic.TokenStore, addr string) *http.Response {
	t.Helper()
	tr := &http3.Transport{TLSClientConfig: cfg, QUICConfig: &quic.Config{HandshakeIdleTimeout: alertDialTimeout, TokenStore: store}}
	defer tr.Close()
	resp, err := (&http.Client{Transport: tr, Timeout: clientTimeout}).Get("https://" + addr + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if body, err := io.ReadAll(resp.Body); err != nil || resp.StatusCode != 200 || string(body) != "pong" {
		t.Fatalf("got %d %q (%v)", resp.StatusCode, body, err)
	}
	return resp
}

func TestH3SessionResumption(t *testing.T) {
	cases := []struct {
		name   string
		cfg    core.Config
		resume bool
	}{
		{"tickets enabled", core.Config{}, true},
		{"tickets disabled", core.Config{SessionTicketsDisabled: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hs := startH3(t, tc.cfg)
			cfg := clientTLS()
			cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
			store := quic.NewLRUTokenStore(tokenStoreOrigins, tokenStorePerOrigin)
			if resp := h3GetWith(t, cfg, store, hs.addr); resp.TLS.DidResume {
				t.Fatal("first connection claims resumption")
			}
			for i := 0; i < 3; i++ {
				if resp := h3GetWith(t, cfg, store, hs.addr); resp.TLS.DidResume != tc.resume {
					t.Fatalf("connection %d: DidResume %v, want %v", i+2, resp.TLS.DidResume, tc.resume)
				}
			}
		})
	}
}
