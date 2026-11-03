//go:build linux && amd64

package core

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const proxyG2HeldLen = "1048576"

func proxyG2CacheServer(t *testing.T) (*Server, string, func()) {
	t.Helper()
	release := make(chan struct{})
	o := proxyFixShapedOrigin(t, release)
	srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.SetProxyCache(DefaultProxyCacheConfig())
	})
	var released bool
	releaseAll := func() {
		if !released {
			released = true
			close(release)
		}
	}
	t.Cleanup(releaseAll)
	return srv, addr, releaseAll
}

func proxyG2HeadArrives(t *testing.T, addr string, extra ...string) (net.Conn, bool) {
	t.Helper()
	c := proxyFixDial(t, addr)
	if _, err := c.Write([]byte(proxyFixGet(proxyFixDomain, "/hold/"+proxyG2HeldLen, extra...))); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	return c, err == nil && strings.HasPrefix(line, "HTTP/1.1 200")
}

func TestProxyH1UncacheableRequestIsNotBufferedForCache(t *testing.T) {
	srv, addr, _ := proxyG2CacheServer(t)
	c, streamed := proxyG2HeadArrives(t, addr, "Authorization: Bearer x")
	defer c.Close()
	if !streamed {
		t.Fatalf("a request the cache refuses was held for a cache store")
	}
	if got := proxyFixH2Buffered(srv); got != 0 {
		t.Fatalf("an uncacheable response charged %d bytes to the buffer budget", got)
	}
}

func TestProxyH1CacheBufferChargesAndReleasesBudget(t *testing.T) {
	srv, addr, release := proxyG2CacheServer(t)
	c, streamed := proxyG2HeadArrives(t, addr)
	if streamed {
		t.Fatalf("a cacheable response under the entry limit was streamed, so the cache cannot store it")
	}
	if got := proxyFixH2Buffered(srv); got != 1048576 {
		t.Fatalf("buffered cacheable response charged %d bytes, want %s", got, proxyG2HeldLen)
	}
	_ = c.Close()
	release()
	proxyFixEventually(t, "budget released after the client left", func() bool { return proxyFixH2Buffered(srv) == 0 })
	proxyFixAssertConnsDrain(t, srv, "h1 client left with a reserved cache body")
}

func TestProxyH1CacheBufferOverBudgetStreams(t *testing.T) {
	proxyFixSetH2Budgets(t, proxyH2ConnBufferBudget, 64<<10)
	srv, addr, _ := proxyG2CacheServer(t)
	c, streamed := proxyG2HeadArrives(t, addr)
	defer c.Close()
	if !streamed {
		t.Fatalf("a response over the server buffer budget was held in memory")
	}
	if got := proxyFixH2Buffered(srv); got != 0 {
		t.Fatalf("a streamed response kept %d bytes reserved", got)
	}
}

func TestProxyBufferReservationReleasesChargedConnAfterDetach(t *testing.T) {
	pe := &ProxyEngine{}
	conn := &epollConn{}
	px := &proxyExchange{c: conn, pe: pe}
	if !px.reserveResponseBuffer(1 << 20) {
		t.Fatalf("reservation refused")
	}
	px.c = nil
	px.discardH2Buffer()
	if conn.h2ProxyBuffered != 0 || pe.h2Buffered.Load() != 0 {
		t.Fatalf("after detach the connection holds %d and the server %d reserved bytes", conn.h2ProxyBuffered, pe.h2Buffered.Load())
	}
	detached := &proxyExchange{pe: pe}
	if detached.reserveResponseBuffer(1) {
		t.Fatalf("an exchange without a client connection reserved budget")
	}
}

func TestProxyH2AuthorizedRequestIsNotCached(t *testing.T) {
	var served atomic.Int64
	addr := proxyG2CacheStart(t, proxyG2CachePath{name: "h2 loop", h2: true}, proxyG2CacheOrigin(t, &served), func(*ProxyRequest) bool { return true })
	c := proxyFixH2cDial(t, addr)
	defer c.Close()
	block := proxyFixAppendHPACKLiteral(nil, proxyFixHpackStaticMethod, "GET")
	block = append(block, proxyFixHpackStaticSchemeHTTP)
	block = proxyFixAppendHPACKLiteral(block, proxyFixHpackStaticPath, "/c")
	block = proxyFixAppendHPACKLiteral(block, proxyFixHpackStaticAuthority, proxyFixDomain)
	block = append(block, 0x00, byte(len("authorization")))
	block = append(block, "authorization"...)
	block = append(block, byte(len("Bearer secret")))
	block = append(block, "Bearer secret"...)
	if _, err := c.Write(proxyFixAppendH2Frame(nil, h2FrameHeaders, h2FlagEndStream|h2FlagEndHeaders, 1, block)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if r := c.collect(t, 1)[1]; r.status != "200" {
		t.Fatalf("authorized request: status %q", r.status)
	}
	if r := proxyG2Get(t, proxyG2CachePath{name: "h2 loop", h2: true}, addr, "/c"); r.status != http.StatusOK || served.Load() != 2 {
		t.Fatalf("an anonymous request was answered from the response to an authorized request: %+v, origin served %d", r, served.Load())
	}
}
