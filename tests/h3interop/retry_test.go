package h3interop

import (
	"net/http"
	"testing"
	"time"

	"github.com/guno1928/alos-http/core"
	"github.com/guno1928/turbo"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	tokenStoreOrigins   = 4
	tokenStorePerOrigin = 4
	tokenArrivalCeiling = 2 * time.Second
	tokenArrivalPoll    = 15 * time.Millisecond
)

func newTokenClient(t *testing.T, store quic.TokenStore) (*http.Client, *http3.Transport) {
	tr := &http3.Transport{
		TLSClientConfig: clientTLS(),
		QUICConfig:      &quic.Config{MaxIdleTimeout: 10 * time.Second, HandshakeIdleTimeout: 3 * time.Second, TokenStore: store},
	}
	t.Cleanup(func() { tr.Close() })
	return &http.Client{Transport: tr, Timeout: clientTimeout}, tr
}

func awaitToken(t *testing.T, store quic.TokenStore) {
	t.Helper()
	deadline := turbo.Deadline(tokenArrivalCeiling)
	for turbo.Until(deadline) > 0 {
		if tok := store.Pop(h3Domain); tok != nil {
			store.Put(h3Domain, tok)
			return
		}
		turbo.Sleep(tokenArrivalPoll)
	}
	t.Fatal("server never sent a NEW_TOKEN")
}

func pingThrough(t *testing.T, c *http.Client, addr string) {
	t.Helper()
	status, body, err := doGet(c, addr, "/ping")
	if err != nil || status != 200 || string(body) != "pong" {
		t.Fatalf("GET /ping: %d %q %v", status, body, err)
	}
}

func TestH3RetryThenNewTokenSkipsRetry(t *testing.T) {
	hs := startH3(t, core.Config{})
	relay := newNATRelay(t, hs.addr)
	store := quic.NewLRUTokenStore(tokenStoreOrigins, tokenStorePerOrigin)

	first, firstTr := newTokenClient(t, store)
	pingThrough(t, first, relay.addr())
	afterFirst := relay.retries.Load()
	if afterFirst == 0 {
		t.Fatal("first connection was admitted without a Retry")
	}
	awaitToken(t, store)
	firstTr.Close()

	second, _ := newTokenClient(t, store)
	pingThrough(t, second, relay.addr())
	if n := relay.retries.Load(); n != afterFirst {
		t.Fatalf("reconnect with a NEW_TOKEN drew %d more Retry packets, want 0", n-afterFirst)
	}

	pingThrough(t, newClient(t), relay.addr())
	if n := relay.retries.Load(); n == afterFirst {
		t.Fatal("tokenless client was admitted without a Retry")
	}
}
