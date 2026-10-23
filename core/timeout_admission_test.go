//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	timeoutAdmissionDeadline = 20 * time.Millisecond
	timeoutAdmissionRequests = 8
	timeoutAdmissionBody     = 3000
)

type timeoutAdmissionProbe struct {
	release chan struct{}
	running atomic.Int32
	once    sync.Once
}

func (p *timeoutAdmissionProbe) unblock() { p.once.Do(func() { close(p.release) }) }

func timeoutAdmissionServer(t *testing.T, cfgFn func(*Config)) (*testServer, *timeoutAdmissionProbe) {
	t.Helper()
	probe := &timeoutAdmissionProbe{release: make(chan struct{})}
	blocking := func(req *Request, resp *Response) {
		probe.running.Add(1)
		defer probe.running.Add(-1)
		<-probe.release
	}
	ts := newTestServer(t, testServerOptions{
		Config: func(cfg *Config) {
			cfg.PlainHTTP = true
			cfgFn(cfg)
		},
		Routes: func(r *Router) {
			timeout := Timeout(timeoutAdmissionDeadline)
			r.GET("/stuck", timeout(blocking))
			r.POST("/stuck", timeout(blocking))
		},
	})
	t.Cleanup(probe.unblock)
	return ts, probe
}

func timeoutAdmissionStatuses(t *testing.T, ts *testServer, method string, body int, extra string) []int {
	t.Helper()
	c := ts.dial(t)
	br := bufio.NewReader(c)
	var statuses []int
	for range timeoutAdmissionRequests {
		req := method + " /stuck HTTP/1.1\r\nHost: " + ts.domain + "\r\n" + extra
		if body > 0 {
			req += "Content-Length: " + strconv.Itoa(body) + "\r\n\r\n" + strings.Repeat("b", body)
		} else {
			req += "\r\n"
		}
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatalf("write: %v", err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("read after %v: %v", statuses, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		statuses = append(statuses, resp.StatusCode)
		if resp.Close {
			break
		}
	}
	return statuses
}

func TestTimeoutDetachedHandlerHoldsAdmission(t *testing.T) {
	cases := []struct {
		name   string
		cfg    func(*Config)
		method string
		body   int
		extra  string
		limit  int32
		refuse int
	}{
		{name: "max-conns", limit: 3, refuse: http.StatusServiceUnavailable, method: "GET",
			cfg: func(cfg *Config) { cfg.MaxConns = 3 }},
		{name: "max-concurrent-reqs", limit: 3, refuse: http.StatusServiceUnavailable, method: "GET",
			cfg: func(cfg *Config) { cfg.MaxConcurrentReqs = 3 }},
		{name: "per-ip-conns", limit: 3, refuse: http.StatusTooManyRequests, method: "GET",
			cfg: func(cfg *Config) { cfg.MaxConnsPerIP = 3 }},
		{name: "per-ip-trusted-proxy", limit: 3, refuse: http.StatusTooManyRequests, method: "GET", extra: "X-Forwarded-For: 203.0.113.5\r\n",
			cfg: func(cfg *Config) {
				cfg.MaxConnsPerIP = 3
				cfg.TrustedProxies = []string{"127.0.0.1"}
			}},
		{name: "body-bytes", limit: 1, method: "POST", body: timeoutAdmissionBody,
			cfg: func(cfg *Config) { cfg.MaxInFlightBodyBytes = 2*timeoutAdmissionBody + timeoutAdmissionBody/2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, probe := timeoutAdmissionServer(t, tc.cfg)
			statuses := timeoutAdmissionStatuses(t, ts, tc.method, tc.body, tc.extra)
			timedOut, refused := 0, 0
			for _, status := range statuses {
				switch {
				case status == http.StatusGatewayTimeout:
					timedOut++
				case tc.refuse == 0 && status >= 400, status == tc.refuse:
					refused++
				default:
					t.Fatalf("unexpected status %d in %v", status, statuses)
				}
			}
			if refused == 0 {
				t.Fatalf("statuses %v: no request was refused while detached handlers held their admission", statuses)
			}
			if running := probe.running.Load(); running != tc.limit || int(running) != timedOut {
				t.Fatalf("statuses %v: %d detached handlers run, %d timed out, limit %d", statuses, running, timedOut, tc.limit)
			}
			probe.unblock()
			waitFor(t, harnessIOTimeout, func() bool {
				return probe.running.Load() == 0 && ts.srv.inFlightBodyBytes.Load() == 0 && ts.srv.activeReqs.Load() == 0
			})
			if again := timeoutAdmissionStatuses(t, ts, tc.method, tc.body, tc.extra); again[0] != http.StatusOK {
				t.Fatalf("after the detached handlers exit: statuses %v, want 200 first", again)
			}
		})
	}
}
