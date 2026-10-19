//go:build linux && amd64

package core

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"
)

func listenIPv6Loopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func serveIPv6Origin(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, req.Body)
					body := "v6 " + c.LocalAddr().String()
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
				}
			}(conn)
		}
	}()
}

func TestProxyUpstreamIPv6(t *testing.T) {
	ln := listenIPv6Loopback(t)
	serveIPv6Origin(t, ln)
	addr := ln.Addr().String()
	want := "v6 " + addr
	backend := BackendConfig{Addr: addr}
	for path, through := range map[string]func(*testing.T, BackendConfig) (int, string){"epoll": proxyThroughEpoll, "engine": proxyThroughEngine} {
		if code, body := through(t, backend); code != 200 || body != want {
			t.Errorf("%s: %d %q, want 200 %q", path, code, body, want)
		}
	}
	if !probeBackendHealth(addr, false, false, nil, HealthCheckConfig{Enabled: true, Path: "/", Timeout: harnessIOTimeout}) {
		t.Error("health probe failed against an IPv6 backend")
	}
}

func TestProxyUpstreamIPv6TLS(t *testing.T) {
	ln := listenIPv6Loopback(t)
	ca := newTestCA(t, "ipv6 origin CA")
	now := wallNow()
	leaf := ca.issue(t, leafSpec{cn: "ipv6 origin", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), usage: x509.ExtKeyUsageServerAuth, ips: []net.IP{net.IPv6loopback}})
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	sniSeen := make(chan string, 4)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{leaf},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sniSeen <- hello.ServerName
			return nil, nil
		},
	}
	srv := &http.Server{
		Handler:  http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "v6 tls") }),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })

	for path, through := range map[string]func(*testing.T, BackendConfig) (int, string){"epoll": proxyThroughEpoll, "engine": proxyThroughEngine} {
		if code, body := through(t, BackendConfig{Addr: "https://" + ln.Addr().String(), RootCAs: roots}); code != 200 || body != "v6 tls" {
			t.Fatalf("%s: %d %q", path, code, body)
		}
		if sni := <-sniSeen; sni != "" {
			t.Fatalf("%s: SNI %q sent to an IPv6 literal", path, sni)
		}
	}
}
