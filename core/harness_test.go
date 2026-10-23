//go:build linux && amd64

package core

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	harnessDomain       = "harness.test"
	harnessIOTimeout    = 2 * time.Second
	harnessPollInterval = 15 * time.Millisecond
	plateauPoll         = 25 * time.Millisecond
	plateauQuietPolls   = 6
	plateauWithin       = 5 * time.Second
)

type testServerOptions struct {
	TLS    bool
	Domain string
	Config func(*Config)
	Routes func(*Router)
	Setup  func(*Server)
}

type testServer struct {
	srv    *Server
	addr   string
	domain string
	tls    bool
}

func newTestServer(t testing.TB, opts testServerOptions) *testServer {
	t.Helper()
	ts := &testServer{addr: freeLoopbackAddr(t), domain: opts.Domain, tls: opts.TLS}
	if ts.domain == "" {
		ts.domain = harnessDomain
	}
	cfg := Config{Addr: ts.addr, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1, Listeners: 1}
	if ts.tls {
		cfg.Certs = []CertConfig{{Domain: ts.domain, Source: CertSelfSigned}}
	}
	if opts.Config != nil {
		opts.Config(&cfg)
	}
	ts.srv = New(cfg)
	if opts.Routes != nil {
		opts.Routes(ts.srv.Router)
	}
	if opts.Setup != nil {
		opts.Setup(ts.srv)
	}
	go func() {
		if ts.tls {
			_ = ts.srv.ListenAndServeTLS()
			return
		}
		_ = ts.srv.ListenAndServe()
	}()
	t.Cleanup(func() { stopServer(ts.srv) })
	waitForProxy(t, ts.addr)
	return ts
}

func (ts *testServer) url(path string) string {
	if ts.tls {
		return "https://" + ts.addr + path
	}
	return "http://" + ts.addr + path
}

func (ts *testServer) tlsConfig(alpn ...string) *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, ServerName: ts.domain, NextProtos: alpn}
}

func (ts *testServer) client(t *testing.T, alpn string) *http.Client {
	t.Helper()
	tr := &http.Transport{MaxConnsPerHost: 1}
	if ts.tls {
		tr.TLSClientConfig = ts.tlsConfig(alpn)
		tr.ForceAttemptHTTP2 = alpn == "h2"
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: harnessIOTimeout}
}

func recvBufDialer(timeout time.Duration, recvBuf int) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: func(_, _ string, raw syscall.RawConn) error {
		var setErr error
		if err := raw.Control(func(fd uintptr) {
			setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, recvBuf)
		}); err != nil {
			return err
		}
		return setErr
	}}
}

func dialTCPRecvBuf(tb testing.TB, addr string, timeout time.Duration, recvBuf int) net.Conn {
	tb.Helper()
	conn, err := recvBufDialer(timeout, recvBuf).Dial("tcp4", addr)
	if err != nil {
		tb.Fatalf("dial %s: %v", addr, err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	return conn
}

func (ts *testServer) dial(t *testing.T) net.Conn {
	t.Helper()
	return ts.dialWith(t, &net.Dialer{Timeout: harnessIOTimeout})
}

func (ts *testServer) dialRecvBuf(t *testing.T, recvBuf int) net.Conn {
	t.Helper()
	return ts.dialWith(t, recvBufDialer(harnessIOTimeout, recvBuf))
}

func (ts *testServer) dialWith(t *testing.T, dialer *net.Dialer) net.Conn {
	t.Helper()
	var (
		c   net.Conn
		err error
	)
	if ts.tls {
		c, err = tls.DialWithDialer(dialer, "tcp4", ts.addr, ts.tlsConfig("http/1.1"))
	} else {
		c, err = dialer.Dial("tcp4", ts.addr)
	}
	if err != nil {
		t.Fatalf("dial %s: %v", ts.addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(wallDeadline(harnessIOTimeout))
	return c
}

func (ts *testServer) rawH1(t *testing.T, raw string) (*http.Response, []byte) {
	t.Helper()
	c := ts.dial(t)
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	return readH1Response(t, bufio.NewReader(c), "GET")
}

func readH1Response(t *testing.T, br *bufio.Reader, method string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, body
}

func wallDeadline(d time.Duration) time.Time {
	return time.Unix(0, turbo.UnixNano()+int64(d))
}

func waitFor(t *testing.T, limit time.Duration, cond func() bool) {
	t.Helper()
	deadline := turbo.Deadline(limit)
	for turbo.Until(deadline) > 0 {
		if cond() {
			return
		}
		turbo.Sleep(harnessPollInterval)
	}
	t.Fatalf("condition not met within %v", limit)
}

func plateauOf(sample func() int64, overflow int64) int64 {
	deadline := turbo.Deadline(plateauWithin)
	last, quiet := sample(), 0
	for quiet < plateauQuietPolls && last <= overflow && turbo.Until(deadline) > 0 {
		turbo.Sleep(plateauPoll)
		current := sample()
		if current == last && current > 0 {
			quiet++
		} else {
			quiet = 0
		}
		last = current
	}
	return last
}

func TestHarnessSmoke(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		ts := newTestServer(t, testServerOptions{TLS: useTLS, Routes: func(r *Router) {
			r.GET("/ping", func(req *Request, resp *Response) { resp.Status(200).String("pong") })
		}})
		resp, body := ts.rawH1(t, "GET /ping HTTP/1.1\r\nHost: "+ts.domain+"\r\n\r\n")
		if resp.StatusCode != 200 || string(body) != "pong" {
			t.Fatalf("tls=%v raw: status=%d body=%q", useTLS, resp.StatusCode, body)
		}
		alpn := "http/1.1"
		if useTLS {
			alpn = "h2"
		}
		got, err := ts.client(t, alpn).Get(ts.url("/ping"))
		if err != nil {
			t.Fatalf("tls=%v client: %v", useTLS, err)
		}
		b, _ := io.ReadAll(got.Body)
		_ = got.Body.Close()
		if got.StatusCode != 200 || string(b) != "pong" {
			t.Fatalf("tls=%v client: status=%d body=%q", useTLS, got.StatusCode, b)
		}
		polls := 0
		waitFor(t, harnessIOTimeout, func() bool { polls++; return polls == 2 })
	}
}
