//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	proxyFixVictimDomain = "victim.test"
	proxyFixEvilDomain   = "evil.test"
	proxyFixSeedRounds   = 8
	proxyFixSeedPathLen  = 300
)

type proxyFixLabelOrigin struct {
	*inloopOrigin
	hits atomic.Int64
}

func newProxyFixLabelOrigin(t *testing.T, label string) *proxyFixLabelOrigin {
	t.Helper()
	o := &proxyFixLabelOrigin{}
	o.inloopOrigin = newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		o.hits.Add(1)
		body := label + ":" + req.RequestURI
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s", len(body), body)
	})
	return o
}

func proxyFixCachingTwoDomains(t *testing.T) (victim, evil *proxyFixLabelOrigin, addr string) {
	t.Helper()
	victim = newProxyFixLabelOrigin(t, "VICTIM")
	evil = newProxyFixLabelOrigin(t, "EVIL")
	_, addr = proxyFixStart(t, Config{}, []DomainConfig{
		{Domain: proxyFixVictimDomain, Backends: []BackendConfig{{Addr: victim.addr()}}},
		{Domain: proxyFixEvilDomain, Backends: []BackendConfig{{Addr: evil.addr()}}},
	}, func(s *Server) { s.SetProxyCache(DefaultProxyCacheConfig()) })
	return victim, evil, addr
}

func proxyFixSeedH1Slots(t *testing.T, addr string) {
	t.Helper()
	seedPath := "/" + strings.Repeat("s", proxyFixSeedPathLen)
	for i := 0; i < proxyFixSeedRounds; i++ {
		proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixVictimDomain, seedPath))
	}
}

func proxyFixH2Fetch(t *testing.T, addr, authority, path string) string {
	t.Helper()
	c := proxyFixH2cDial(t, addr)
	defer c.Close()
	if _, err := c.Write(proxyFixH2Request(1, "GET", authority, path)); err != nil {
		t.Fatalf("write h2 request: %v", err)
	}
	return c.readBody(t, 1)
}

func TestProxyFixH2CacheStoreUsesStreamHost(t *testing.T) {
	_, evil, addr := proxyFixCachingTwoDomains(t)
	proxyFixSeedH1Slots(t, addr)

	if body := proxyFixH2Fetch(t, addr, proxyFixEvilDomain, "/index.html"); body != "EVIL:/index.html" {
		t.Fatalf("h2 evil fetch body = %q", body)
	}
	_, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixVictimDomain, "/index.html"))
	if body != "VICTIM:/index.html" {
		t.Fatalf("h1 %s /index.html served %q: an HTTP/2 response for %s was cached under the recycled connection's stale host",
			proxyFixVictimDomain, body, proxyFixEvilDomain)
	}
	if body := proxyFixH2Fetch(t, addr, proxyFixEvilDomain, "/index.html"); body != "EVIL:/index.html" {
		t.Fatalf("second h2 evil fetch body = %q", body)
	}
	if n := evil.hits.Load(); n != 1 {
		t.Fatalf("evil origin hits = %d, want 1: the HTTP/2 response was not stored under its own host", n)
	}
}

func TestProxyFixH2CacheStoreKeepsStreamQuery(t *testing.T) {
	_, _, addr := proxyFixCachingTwoDomains(t)
	proxyFixSeedH1Slots(t, addr)

	const injected = "/page?inject=PAYLOAD"
	if body := proxyFixH2Fetch(t, addr, proxyFixVictimDomain, injected); body != "VICTIM:"+injected {
		t.Fatalf("h2 fetch body = %q", body)
	}
	_, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixVictimDomain, "/page"))
	if body != "VICTIM:/page" {
		t.Fatalf("h1 /page served %q: an HTTP/2 response was cached without its query", body)
	}
}

type proxyFixXFFOrigin struct {
	*inloopOrigin
	lastXFF atomic.Value
}

func newProxyFixXFFOrigin(t *testing.T) *proxyFixXFFOrigin {
	t.Helper()
	o := &proxyFixXFFOrigin{}
	o.inloopOrigin = newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		o.lastXFF.Store(req.Header.Get("X-Forwarded-For"))
		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	return o
}

func (o *proxyFixXFFOrigin) xff() string {
	v, _ := o.lastXFF.Load().(string)
	return v
}

const (
	proxyFixTrustedPeer = "127.0.0.2"
	proxyFixSpoofedIP   = "6.6.6.6"
)

func proxyFixDialFrom(t *testing.T, local, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: proxyFixIOTimeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(local)}}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial from %s: %v", local, err)
	}
	return c
}

func proxyFixRoundTripOn(t *testing.T, c net.Conn, raw string) string {
	t.Helper()
	defer c.Close()
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, body := proxyFixReadResponse(t, bufio.NewReader(c))
	return body
}

func TestProxyFixStalePeerAddrNotReusedAcrossConns(t *testing.T) {
	o := newProxyFixXFFOrigin(t)
	_, addr := proxyFixStart(t, Config{TrustedProxies: []string{proxyFixTrustedPeer}},
		proxyFixSingleBackend(o.addr()), nil)

	for i := 0; i < proxyFixSeedRounds; i++ {
		proxyFixRoundTripOn(t, proxyFixDialFrom(t, proxyFixTrustedPeer, addr),
			proxyFixGet(proxyFixDomain, "/trusted", "X-Forwarded-For: 203.0.113.9"))
	}
	if got := o.xff(); !strings.Contains(got, proxyFixTrustedPeer) {
		t.Fatalf("trusted control: backend X-Forwarded-For = %q, want it to carry the trusted hop", got)
	}

	proxyFixRoundTripOn(t, proxyFixDialFrom(t, "127.0.0.1", addr),
		proxyFixGet(proxyFixDomain, "/untrusted", "X-Forwarded-For: "+proxyFixSpoofedIP))
	if got := o.xff(); strings.Contains(got, proxyFixSpoofedIP) || got != "127.0.0.1" {
		t.Fatalf("untrusted peer: backend X-Forwarded-For = %q, want %q (stale trusted peerAddr reused)", got, "127.0.0.1")
	}
}

func TestProxyFixPeerAddrClearedBetweenKeepAliveRequests(t *testing.T) {
	o := newProxyFixXFFOrigin(t)
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.Router.Use(RealIP())
		s.Router.GET("/realip", func(req *Request, resp *Response) { resp.String("seen") })
	})
	c := proxyFixDial(t, addr)
	defer c.Close()
	br := bufio.NewReader(c)
	if _, err := io.WriteString(c, "GET /realip HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n"); err != nil {
		t.Fatalf("write routed request: %v", err)
	}
	if _, body := proxyFixReadResponse(t, br); body != "seen" {
		t.Fatalf("routed request body = %q", body)
	}
	if _, err := io.WriteString(c, "GET /proxied HTTP/1.1\r\nHost: "+proxyFixDomain+"\r\nX-Forwarded-For: "+proxyFixSpoofedIP+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write proxied request: %v", err)
	}
	proxyFixReadResponse(t, br)
	if got := o.xff(); got != "127.0.0.1" {
		t.Fatalf("proxied request after a RealIP-routed one on the same connection: backend X-Forwarded-For = %q, want %q", got, "127.0.0.1")
	}
}
