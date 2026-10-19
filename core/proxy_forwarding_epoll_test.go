//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

const fwdTestDomain = "fwd.test"

var fwdEchoedHeaders = []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "Forwarded", "X-Real-Ip", "X-Secret", "X-Also", "X-Keep"}

func startForwardingEchoOrigin(t *testing.T) DomainConfig {
	t.Helper()
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.Copy(io.Discard, req.Body)
		var b strings.Builder
		for _, name := range fwdEchoedHeaders {
			fmt.Fprintf(&b, "%s=%s\n", name, strings.Join(req.Header.Values(name), "|"))
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", b.Len(), b.String())
	})
	return DomainConfig{Domain: fwdTestDomain, PreserveHost: true, Backends: []BackendConfig{{Addr: o.addr()}}}
}

func parseForwardingEcho(t *testing.T, body string) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("origin echo %q", body)
		}
		got[name] = value
	}
	return got
}

func spoofedForwardingRequest(t *testing.T, client *http.Client, url string) map[string]string {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = fwdTestDomain
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	req.Header.Set("X-Forwarded-Proto", "gopher")
	req.Header.Set("X-Forwarded-Host", "evil.test")
	req.Header.Set("Forwarded", "for=6.6.6.6")
	req.Header.Set("X-Real-IP", "6.6.6.6")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("status %d body %q (%v)", resp.StatusCode, body, err)
	}
	return parseForwardingEcho(t, string(body))
}

func checkForwardedToOrigin(t *testing.T, got map[string]string, proto string) {
	t.Helper()
	want := map[string]string{
		"X-Forwarded-For":   "127.0.0.1",
		"X-Forwarded-Proto": proto,
		"X-Forwarded-Host":  fwdTestDomain,
		"Forwarded":         `for=127.0.0.1;proto=` + proto + `;host="` + fwdTestDomain + `"`,
		"X-Real-Ip":         "",
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("origin saw %s=%q, want %q", name, got[name], v)
		}
	}
}

func TestProxyForwardHeadersEpoll(t *testing.T) {
	t.Run("plain HTTP/1.1", func(t *testing.T) {
		addr := startInloopProxy(t, startForwardingEchoOrigin(t), nil)
		tr := &http.Transport{}
		t.Cleanup(tr.CloseIdleConnections)
		checkForwardedToOrigin(t, spoofedForwardingRequest(t, &http.Client{Transport: tr, Timeout: harnessIOTimeout}, "http://"+addr+"/f"), "http")
	})
	for _, alpn := range []string{"http/1.1", "h2"} {
		t.Run("TLS "+alpn, func(t *testing.T) {
			cfg := startForwardingEchoOrigin(t)
			ts := newTestServer(t, testServerOptions{TLS: true, Domain: fwdTestDomain, Setup: func(s *Server) { s.AddProxyDomain(cfg) }})
			checkForwardedToOrigin(t, spoofedForwardingRequest(t, ts.client(t, alpn), ts.url("/f")), "https")
		})
	}
}

func TestProxyForwardHeadersEngine(t *testing.T) {
	for _, tc := range []struct {
		tls   bool
		proto string
	}{{false, "http"}, {true, "https"}} {
		t.Run(tc.proto, func(t *testing.T) {
			pe := NewProxyEngine()
			pe.AddDomain(startForwardingEchoOrigin(t))
			t.Cleanup(pe.Stop)
			req := &Request{
				Method: "GET", Host: fwdTestDomain, Path: "/f", RemoteAddr: "127.0.0.1:40000", IsTLS: tc.tls,
				Headers: [][2]string{{"X-Forwarded-For", "6.6.6.6"}, {"X-Forwarded-Proto", "gopher"}, {"X-Forwarded-Host", "evil.test"}, {"Forwarded", "for=6.6.6.6"}, {"X-Real-IP", "6.6.6.6"}},
			}
			resp := &Response{}
			resp.Reset()
			if !pe.Handle(req, resp) || resp.StatusCode != 200 {
				t.Fatalf("Handle status %d", resp.StatusCode)
			}
			checkForwardedToOrigin(t, parseForwardingEcho(t, string(resp.transmittedBodyBytes())), tc.proto)
		})
	}
}

func TestProxyForwardHeadersTrustedChain(t *testing.T) {
	cfg := startForwardingEchoOrigin(t)
	ts := newTestServer(t, testServerOptions{
		Domain: fwdTestDomain,
		Config: func(c *Config) { c.PlainHTTP = true; c.TrustedProxies = []string{"127.0.0.1"} },
		Setup:  func(s *Server) { s.AddProxyDomain(cfg) },
	})
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	req, err := http.NewRequest("GET", ts.url("/f"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = fwdTestDomain
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 192.0.2.9")
	resp, err := (&http.Client{Transport: tr, Timeout: harnessIOTimeout}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	got := parseForwardingEcho(t, string(body))
	if got["X-Forwarded-For"] != "198.51.100.1, 192.0.2.9, 127.0.0.1" {
		t.Errorf("trusted chain X-Forwarded-For=%q", got["X-Forwarded-For"])
	}
	if want := `for=192.0.2.9;proto=http;host="` + fwdTestDomain + `"`; got["Forwarded"] != want {
		t.Errorf("Forwarded=%q, want %q", got["Forwarded"], want)
	}
}

func TestProxyConnectionTokensSerializers(t *testing.T) {
	assertConnectionTokensStripped(t, string(appendProxyRequest(nil, connectionTokenRequest(), "app.test")))
	var wire strings.Builder
	for _, h := range fpProxyRequestHeaders(connectionTokenRequest()) {
		if isHopByHopFold(h[0]) {
			t.Errorf("engine relays hop-by-hop %q", h[0])
		}
		fmt.Fprintf(&wire, "\r\n%s: %s", h[0], h[1])
	}
	assertConnectionTokensStripped(t, wire.String()+"\r\n")
}

func checkConnectionTokensAtOrigin(t *testing.T, got map[string]string) {
	t.Helper()
	if got["X-Secret"] != "" || got["X-Also"] != "" || got["X-Keep"] != "3" {
		t.Errorf("origin saw X-Secret=%q X-Also=%q X-Keep=%q", got["X-Secret"], got["X-Also"], got["X-Keep"])
	}
}

func connectionTokenHTTPRequest(t *testing.T, client *http.Client, url string) map[string]string {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = fwdTestDomain
	req.Header.Set("Connection", "X-Secret, x-also")
	req.Header.Set("X-Secret", "1")
	req.Header.Set("X-Also", "2")
	req.Header.Set("X-Keep", "3")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("status %d body %q (%v)", resp.StatusCode, body, err)
	}
	return parseForwardingEcho(t, string(body))
}

func TestProxyConnectionTokensEpoll(t *testing.T) {
	t.Run("plain HTTP/1.1", func(t *testing.T) {
		addr := startInloopProxy(t, startForwardingEchoOrigin(t), nil)
		tr := &http.Transport{}
		t.Cleanup(tr.CloseIdleConnections)
		checkConnectionTokensAtOrigin(t, connectionTokenHTTPRequest(t, &http.Client{Transport: tr, Timeout: harnessIOTimeout}, "http://"+addr+"/t"))
	})
	t.Run("TLS http/1.1", func(t *testing.T) {
		cfg := startForwardingEchoOrigin(t)
		ts := newTestServer(t, testServerOptions{TLS: true, Domain: fwdTestDomain, Setup: func(s *Server) { s.AddProxyDomain(cfg) }})
		checkConnectionTokensAtOrigin(t, connectionTokenHTTPRequest(t, ts.client(t, "http/1.1"), ts.url("/t")))
	})
	t.Run("engine", func(t *testing.T) {
		pe := NewProxyEngine()
		pe.AddDomain(startForwardingEchoOrigin(t))
		t.Cleanup(pe.Stop)
		req := connectionTokenRequest()
		req.Host = fwdTestDomain
		resp := &Response{}
		resp.Reset()
		if !pe.Handle(req, resp) || resp.StatusCode != 200 {
			t.Fatalf("Handle status %d", resp.StatusCode)
		}
		checkConnectionTokensAtOrigin(t, parseForwardingEcho(t, string(resp.transmittedBodyBytes())))
	})
}
