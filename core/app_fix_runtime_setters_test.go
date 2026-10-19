//go:build linux && amd64

package core

import (
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

const (
	appFixSetterRounds   = 40
	appFixTrafficRounds  = 120
	appFixProxiedDomain  = "origin.test"
	appFixConcurrentRuns = 20
)

func appFixGetWithHost(t *testing.T, cl *http.Client, url, host string) int {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Error(err)
		return 0
	}
	req.Host = host
	resp, err := cl.Do(req)
	if err != nil {
		t.Error(err)
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func appFixExerciseRuntimeSetters(s *Server, backend string, round int) {
	s.OnProxyRequest(func(*ProxyRequest) bool { return true })
	s.OnProxyResponse(func(*ProxyResponse) {})
	s.OnProxyError(func(ProxyError) {})
	s.SetProxyCache(ProxyCacheConfig{MaxEntrySize: 1 << 10, DefaultMaxAge: time.Duration(round+1) * time.Millisecond})
	s.SetCORS(CORSConfig{AllowOrigins: []string{"https://app.test"}})
	s.AddRateLimitRule(RateLimitRule{Path: "/never-hit", MaxReqs: 1, Window: time.Minute})
	s.OnRateLimit(func(RateLimitEvent, *Request, *Response) bool { return false })
	s.AddHTTPRoute(HTTPRoute{PathPrefix: "/port80-only/", Backend: backend})
	s.RemoveHTTPRoute("/port80-only/")
	s.AddProxyDomain(DomainConfig{Domain: appFixProxiedDomain, Backends: []BackendConfig{{Addr: backend}}})
}

func TestAppFixRuntimeSettersRaceFreeUnderTraffic(t *testing.T) {
	origin := newInloopOrigin(t, echoBodyOrigin("ok"))
	ts := newTestServer(t, testServerOptions{
		Config: func(cfg *Config) { cfg.PlainHTTP = true },
		Routes: func(r *Router) {
			r.GET("/local", func(req *Request, resp *Response) { resp.String("local") })
		},
		Setup: func(s *Server) {
			s.AddProxyDomain(DomainConfig{Domain: appFixProxiedDomain, Backends: []BackendConfig{{Addr: origin.addr()}}})
		},
	})
	cl := ts.client(t, "")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < appFixSetterRounds; i++ {
			appFixExerciseRuntimeSetters(ts.srv, origin.addr(), i)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < appFixTrafficRounds; i++ {
			if code := appFixGetWithHost(t, cl, ts.url("/p"), appFixProxiedDomain); code != http.StatusOK {
				t.Errorf("proxied request %d status %d", i, code)
			}
			if code := appFixGetWithHost(t, cl, ts.url("/local"), ts.domain); code != http.StatusOK {
				t.Errorf("local request %d status %d", i, code)
			}
		}
	}()
	wg.Wait()
}

func TestAppFixConcurrentFirstProxySetupKeepsEveryDomain(t *testing.T) {
	domains := [...]string{"a.test", "b.test", "c.test", "d.test"}
	for run := 0; run < appFixConcurrentRuns; run++ {
		s := New(Config{})
		var wg sync.WaitGroup
		for _, d := range domains {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.AddProxyDomain(DomainConfig{Domain: d, Backends: []BackendConfig{{Addr: "127.0.0.1:9"}}})
			}()
		}
		wg.Wait()
		pe := s.Proxy()
		for _, d := range domains {
			if pe.Lookup(d) == nil {
				t.Fatalf("run %d: domain %s lost by a concurrent first AddProxyDomain", run, d)
			}
		}
		pe.Stop()
		s.perIPConnLimiter.Load().Stop()
	}
}
