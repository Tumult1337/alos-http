//go:build linux && amd64

package core

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func proxyFix4TLSUpgrade(path string) string {
	return strings.Replace(proxyFix3Upgrade(path, "websocket"), "Host: "+proxyFixDomain, "Host: "+proxyFixTLSDomain, 1)
}

func proxyFix4ExpectTLSTunnel(t *testing.T, c net.Conn, request string, earlyBytes bool) {
	t.Helper()
	if earlyBytes {
		request += proxyFix3TunnelProbe
	}
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d, want 101", resp.StatusCode)
	}
	if !earlyBytes {
		if _, err := io.WriteString(c, proxyFix3TunnelProbe); err != nil {
			t.Fatalf("write tunnel bytes after the 101: %v", err)
		}
	}
	echo := make([]byte, len(proxyFix3TunnelProbe))
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != proxyFix3TunnelProbe {
		t.Fatalf("tunnel echo %q, err %v", echo, err)
	}
}

func TestProxyFix4TLSUpgradeTunnelsWithoutServerHooks(t *testing.T) {
	for _, version := range []struct {
		name       string
		maxVersion uint16
	}{{"tls1.3", tls.VersionTLS13}, {"tls1.2", tls.VersionTLS12}} {
		for _, tc := range []struct {
			name    string
			request string
			early   bool
		}{
			{"early-bytes", proxyFix4TLSUpgrade("/ws"), true},
			{"after-101", proxyFix4TLSUpgrade("/ws"), false},
			{"lowercase-upgrade-field", strings.Replace(proxyFix4TLSUpgrade("/ws"), "Upgrade: websocket", "upgrade: websocket", 1), true},
		} {
			t.Run(version.name+"/"+tc.name, func(t *testing.T) {
				o := newProxyFix3UpgradeOrigin(t)
				srv, httpsAddr, _ := proxyFixStartTLS(t, Config{MaxConnsPerIP: -1}, func(s *Server) {
					s.AddProxyDomain(DomainConfig{Domain: proxyFixTLSDomain, Backends: []BackendConfig{{Addr: o.addr()}}})
				})
				c, err := tls.DialWithDialer(&net.Dialer{Timeout: proxyFixIOTimeout}, "tcp", httpsAddr, &tls.Config{
					InsecureSkipVerify: true, ServerName: proxyFixTLSDomain, NextProtos: []string{"http/1.1"}, MaxVersion: version.maxVersion,
				})
				if err != nil {
					t.Fatalf("tls dial: %v", err)
				}
				_ = c.SetDeadline(wallDeadline(proxyFixIOTimeout))
				proxyFix4ExpectTLSTunnel(t, c, tc.request, tc.early)
				proxyFix3CloseTunnel(t, srv, c)
			})
		}
	}
}

func TestProxyFix4TLSTrailingEmptyUpgradeFieldGetsAnAnswer(t *testing.T) {
	o := newProxyFix3UpgradeOrigin(t)
	_, httpsAddr, _ := proxyFixStartTLS(t, Config{MaxConnsPerIP: -1}, func(s *Server) {
		s.AddProxyDomain(DomainConfig{Domain: proxyFixTLSDomain, Backends: []BackendConfig{{Addr: o.addr()}}})
	})
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: proxyFixIOTimeout}, "tcp", httpsAddr, &tls.Config{
		InsecureSkipVerify: true, ServerName: proxyFixTLSDomain, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(wallDeadline(proxyFixIOTimeout))
	request := strings.Replace(proxyFix4TLSUpgrade("/ws"), "\r\n\r\n", "\r\nUpgrade: \r\n\r\n", 1)
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, _ := proxyFixReadResponse(t, bufio.NewReader(c))
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("an upgrade whose last Upgrade field is empty was switched in the loop, where a TLS tunnel never relays")
	}
}

func TestProxyFix4TLSPlainRequestStaysInLoop(t *testing.T) {
	o := newProxyFix3UpgradeOrigin(t)
	loopProbe := &proxyFix3HookProbe{}
	_, httpsAddr, _ := proxyFixStartTLS(t, Config{MaxConnsPerIP: -1}, func(s *Server) {
		s.AddProxyDomain(DomainConfig{Domain: proxyFixTLSDomain, Backends: []BackendConfig{{Addr: o.addr()}}})
		proxyFix4ProbeProxyRequests(s, loopProbe)
	})
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: proxyFixIOTimeout}, "tcp", httpsAddr, &tls.Config{
		InsecureSkipVerify: true, ServerName: proxyFixTLSDomain, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(wallDeadline(proxyFixIOTimeout))
	if _, err := io.WriteString(c, proxyFixGet(proxyFixTLSDomain, "/plain")); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, body := proxyFixReadResponse(t, bufio.NewReader(c))
	if resp.StatusCode != http.StatusOK || body != proxyFix3PlainBody {
		t.Fatalf("tls proxied request: status %d body %q", resp.StatusCode, body)
	}
	loopProbe.assertOnLoop(t, 1)
}
