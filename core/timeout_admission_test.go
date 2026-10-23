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
			r.GET("/ping", func(req *Request, resp *Response) { resp.String("pong") })
		},
	})
	t.Cleanup(probe.unblock)
	awaitIdleAfterReadinessProbe(t, ts, "/ping")
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
		pingIP string
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
		{name: "max-requests-per-ip-trusted-proxy", limit: 3, refuse: http.StatusTooManyRequests, method: "GET", extra: "X-Forwarded-For: 203.0.113.6\r\n",
			pingIP: "203.0.113.6",
			cfg: func(cfg *Config) {
				cfg.MaxRequestsPerIP = 3
				cfg.MaxConnsPerIP = -1
				cfg.TrustedProxies = []string{"127.0.0.1"}
			}},
		{name: "max-requests-per-ip-wins-trusted-proxy", limit: 5, refuse: http.StatusTooManyRequests, method: "GET", extra: "X-Forwarded-For: 203.0.113.7\r\n",
			cfg: func(cfg *Config) {
				cfg.MaxRequestsPerIP = 5
				cfg.MaxConnsPerIP = 2
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
			if tc.pingIP != "" {
				if status := timeoutAdmissionPing(t, ts, tc.pingIP); status != http.StatusTooManyRequests {
					t.Fatalf("plain request from %s while its detached handlers fill MaxRequestsPerIP: status %d, want 429", tc.pingIP, status)
				}
			}
			probe.unblock()
			waitFor(t, harnessIOTimeout, func() bool {
				return probe.running.Load() == 0 && ts.srv.inFlightBodyBytes.Load() == 0 && ts.srv.activeReqs.Load() == 0 && ts.srv.timeoutHandlers.Load() == 0
			})
			if again := timeoutAdmissionStatuses(t, ts, tc.method, tc.body, tc.extra); again[0] != http.StatusOK {
				t.Fatalf("after the detached handlers exit: statuses %v, want 200 first", again)
			}
		})
	}
}

func TestPerIPLimiterHoldAliveSkipsFreeAndDeadCounters(t *testing.T) {
	l := newPerIPLimiter(1)
	defer l.Stop()
	if slot := l.holdAlive("198.51.100.1"); slot != nil {
		t.Fatal("holdAlive created a slot for an IP with no holder")
	}
	held, ok := l.hold("198.51.100.1", 1)
	if !ok || held == nil {
		t.Fatal("hold below the limit failed")
	}
	extra := l.holdAlive("198.51.100.1")
	if extra == nil || l.count("198.51.100.1") != 2 {
		t.Fatalf("holdAlive on a held IP: slot %v count %d, want count 2", extra, l.count("198.51.100.1"))
	}
	extra.release()
	held.release()
	if slot := l.holdAlive("198.51.100.1"); slot != nil || l.count("198.51.100.1") != 0 {
		t.Fatalf("holdAlive revived a free counter: count %d", l.count("198.51.100.1"))
	}
	l.sweep()
	if slot := l.holdAlive("198.51.100.1"); slot != nil {
		t.Fatal("holdAlive revived a swept counter")
	}
}

const timeoutAdmissionStreams = 20

func TestTimeoutConcurrentH2StreamsRespectAdmission(t *testing.T) {
	cases := []struct {
		name   string
		cfg    func(*Config)
		refuse int
	}{
		{name: "max-conns", refuse: http.StatusServiceUnavailable, cfg: func(cfg *Config) { cfg.MaxConns = 3 }},
		{name: "per-ip-conns", refuse: http.StatusTooManyRequests, cfg: func(cfg *Config) { cfg.MaxConnsPerIP = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, probe := timeoutAdmissionServer(t, tc.cfg)
			rc, _ := h2DialCaptureSettings(t, ts.addr)
			for i := range timeoutAdmissionStreams {
				rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, uint32(2*i+1), hpackBlock(
					[2]string{":method", "GET"}, [2]string{":scheme", "http"}, [2]string{":path", "/stuck"}, [2]string{":authority", harnessDomain}))
			}
			statuses := map[int]int{}
			for answered := 0; answered < timeoutAdmissionStreams; {
				f, err := rc.tryRead()
				if err != nil {
					t.Fatalf("after %d answers %v: %v", answered, statuses, err)
				}
				if f.typ == H2FrameRSTStream || f.typ == H2FrameGoAway {
					t.Fatalf("stream %d got frame type %d", f.streamID, f.typ)
				}
				if f.typ == H2FrameHeaders {
					statuses[f.status(t)]++
					answered++
				}
			}
			if statuses[http.StatusGatewayTimeout] != 3 || statuses[tc.refuse] != timeoutAdmissionStreams-3 {
				t.Fatalf("statuses %v, want 3 x 504 and %d x %d", statuses, timeoutAdmissionStreams-3, tc.refuse)
			}
			if running := probe.running.Load(); running != 3 {
				t.Fatalf("%d Timeout handlers run, want 3", running)
			}
		})
	}
}

func timeoutAdmissionPing(t *testing.T, ts *testServer, ip string) int {
	t.Helper()
	c := ts.dial(t)
	defer c.Close()
	if _, err := io.WriteString(c, "GET /ping HTTP/1.1\r\nHost: "+ts.domain+"\r\nX-Forwarded-For: "+ip+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return resp.StatusCode
}
