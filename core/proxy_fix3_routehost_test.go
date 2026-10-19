//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/guno1928/turbo"
)

const (
	proxyFix3ClientHost   = "vhost.example"
	proxyFix3OverrideHost = "internal.example"
	proxyFix3RoutePath    = proxyFixRoutePrefix + "page"
)

type proxyFix3HostOrigin struct {
	*inloopOrigin
	hosts chan string
}

func newProxyFix3HostOrigin(t *testing.T) *proxyFix3HostOrigin {
	t.Helper()
	o := &proxyFix3HostOrigin{hosts: make(chan string, 4)}
	o.inloopOrigin = newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		select {
		case o.hosts <- req.Host:
		default:
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	return o
}

func (o *proxyFix3HostOrigin) nextHost(t *testing.T) string {
	t.Helper()
	select {
	case host := <-o.hosts:
		return host
	case <-turbo.After(proxyFixIOTimeout):
		t.Fatal("backend never received the routed request")
		return ""
	}
}

type proxyFix3RouteListener struct {
	name  string
	start func(t *testing.T, route HTTPRoute) string
}

var proxyFix3RouteListeners = []proxyFix3RouteListener{
	{name: "port80", start: func(t *testing.T, route HTTPRoute) string {
		_, _, httpAddr := proxyFixStartTLS(t, Config{MaxConnsPerIP: -1}, func(s *Server) {
			s.SetHTTPRoutes([]HTTPRoute{route})
		})
		return httpAddr
	}},
	{name: "plain-listener", start: func(t *testing.T, route HTTPRoute) string {
		_, addr := proxyFixStart(t, Config{}, nil, func(s *Server) {
			s.SetHTTPRoutes([]HTTPRoute{route})
		})
		return addr
	}},
}

func proxyFix3RouteHost(t *testing.T, l proxyFix3RouteListener, hostHeader, raw string) (status int, backendHost, backendAddr string) {
	t.Helper()
	o := newProxyFix3HostOrigin(t)
	addr := l.start(t, HTTPRoute{PathPrefix: proxyFixRoutePrefix, Backend: o.addr(), HostHeader: hostHeader})
	resp, _ := proxyFixRoundTrip(t, addr, raw)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, "", o.addr()
	}
	return resp.StatusCode, o.nextHost(t), o.addr()
}

func TestProxyFix3RouteForwardsClientHost(t *testing.T) {
	for _, l := range proxyFix3RouteListeners {
		t.Run(l.name, func(t *testing.T) {
			status, host, _ := proxyFix3RouteHost(t, l, "", proxyFixGet(proxyFix3ClientHost, proxyFix3RoutePath))
			if status != http.StatusOK || host != proxyFix3ClientHost {
				t.Fatalf("route without HostHeader: status %d, backend saw Host %q, want the client's %q", status, host, proxyFix3ClientHost)
			}
		})
	}
}

func TestProxyFix3RouteHostHeaderOverridesClientHost(t *testing.T) {
	for _, l := range proxyFix3RouteListeners {
		t.Run(l.name, func(t *testing.T) {
			status, host, _ := proxyFix3RouteHost(t, l, proxyFix3OverrideHost, proxyFixGet(proxyFix3ClientHost, proxyFix3RoutePath))
			if status != http.StatusOK || host != proxyFix3OverrideHost {
				t.Fatalf("route with HostHeader: status %d, backend saw Host %q, want %q", status, host, proxyFix3OverrideHost)
			}
		})
	}
}

func TestProxyFix3RouteWithoutClientHostSendsBackendAuthority(t *testing.T) {
	raw := "GET " + proxyFix3RoutePath + " HTTP/1.0\r\n\r\n"
	for _, l := range proxyFix3RouteListeners {
		t.Run(l.name, func(t *testing.T) {
			status, host, backend := proxyFix3RouteHost(t, l, "", raw)
			if status != http.StatusOK || host != backend {
				t.Fatalf("HTTP/1.0 request without Host: status %d, backend saw Host %q, want the backend authority %q", status, host, backend)
			}
		})
	}
}
