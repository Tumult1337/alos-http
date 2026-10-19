//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const proxyFixHookRounds = 4

type proxyFixRetained struct {
	mu        sync.Mutex
	requests  []*ProxyRequest
	responses []*ProxyResponse
	snapshots [][][2]string
}

func (r *proxyFixRetained) keepRequest(pr *ProxyRequest) {
	r.mu.Lock()
	r.requests = append(r.requests, pr)
	r.mu.Unlock()
}

func (r *proxyFixRetained) keepResponse(pr *ProxyResponse) {
	r.mu.Lock()
	r.responses = append(r.responses, pr)
	r.snapshots = append(r.snapshots, proxyFixDeepCopyHeaders(pr.Headers))
	r.mu.Unlock()
}

func proxyFixDeepCopyHeaders(h [][2]string) [][2]string {
	out := make([][2]string, len(h))
	for i, kv := range h {
		out[i] = [2]string{strings.Clone(kv[0]), strings.Clone(kv[1])}
	}
	return out
}

func proxyFixRoundPath(i int) string   { return "/round-" + strconv.Itoa(i) + "-path" }
func proxyFixRoundHeader(i int) string { return "value-" + strconv.Itoa(i) + "-probe" }

func proxyFixDriveRounds(t *testing.T, addr string) {
	t.Helper()
	c := proxyFixDial(t, addr)
	defer c.Close()
	br := bufio.NewReader(c)
	for i := 0; i < proxyFixHookRounds; i++ {
		raw := "GET " + proxyFixRoundPath(i) + " HTTP/1.1\r\nHost: " + proxyFixDomain + "\r\nX-Probe: " + proxyFixRoundHeader(i) + "\r\n\r\n"
		if _, err := io.WriteString(c, raw); err != nil {
			t.Fatalf("write round %d: %v", i, err)
		}
		if resp, _ := proxyFixReadResponse(t, br); resp.StatusCode != http.StatusOK {
			t.Fatalf("round %d: status %d", i, resp.StatusCode)
		}
	}
}

func proxyFixHeaderValue(headers [][2]string, name string) string {
	for _, kv := range headers {
		if http.CanonicalHeaderKey(kv[0]) == http.CanonicalHeaderKey(name) {
			return kv[1]
		}
	}
	return ""
}

func TestProxyFixRetainedProxyRequestIsStable(t *testing.T) {
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	var kept proxyFixRetained
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.proxy.Load().OnRequest = func(pr *ProxyRequest) bool { kept.keepRequest(pr); return true }
	})
	proxyFixDriveRounds(t, addr)
	kept.mu.Lock()
	defer kept.mu.Unlock()
	if len(kept.requests) != proxyFixHookRounds {
		t.Fatalf("hook saw %d requests", len(kept.requests))
	}
	for i, pr := range kept.requests {
		if pr.Path != proxyFixRoundPath(i) {
			t.Errorf("retained ProxyRequest %d: Path changed to %q after later requests, want %q", i, pr.Path, proxyFixRoundPath(i))
		}
		if got := proxyFixHeaderValue(pr.Headers, "X-Probe"); got != proxyFixRoundHeader(i) {
			t.Errorf("retained ProxyRequest %d: X-Probe changed to %q after later requests, want %q", i, got, proxyFixRoundHeader(i))
		}
	}
}

func TestProxyFixRetainedProxyResponseIsStable(t *testing.T) {
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	var kept proxyFixRetained
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.proxy.Load().OnResponse = func(pr *ProxyResponse) { kept.keepResponse(pr) }
	})
	proxyFixDriveRounds(t, addr)
	kept.mu.Lock()
	defer kept.mu.Unlock()
	for i, pr := range kept.responses {
		if pr.Path != proxyFixRoundPath(i) {
			t.Errorf("retained ProxyResponse %d: Path changed to %q after later requests, want %q", i, pr.Path, proxyFixRoundPath(i))
		}
	}
}

func TestProxyFixRetainedCacheHitHeadersAreStable(t *testing.T) {
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	var kept proxyFixRetained
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.SetProxyCache(DefaultProxyCacheConfig())
		s.proxy.Load().OnResponse = func(pr *ProxyResponse) {
			if pr.Backend == "cache" {
				kept.keepResponse(pr)
			}
		}
	})
	c := proxyFixDial(t, addr)
	defer c.Close()
	br := bufio.NewReader(c)
	paths := []string{"/a", "/a", "/bb", "/bb", "/a"}
	for _, p := range paths {
		if _, err := io.WriteString(c, "GET "+p+" HTTP/1.1\r\nHost: "+proxyFixDomain+"\r\n\r\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		if resp, _ := proxyFixReadResponse(t, br); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", p, resp.StatusCode)
		}
	}
	kept.mu.Lock()
	defer kept.mu.Unlock()
	if len(kept.responses) < 2 {
		t.Fatalf("only %d cache hits observed", len(kept.responses))
	}
	for i, pr := range kept.responses {
		if !reflect.DeepEqual(pr.Headers, kept.snapshots[i]) {
			t.Fatalf("retained cache-hit %d headers changed after later requests: %v, at hook time %v", i, pr.Headers, kept.snapshots[i])
		}
	}
}
