//go:build linux && amd64

package core

import (
	"crypto/tls"
	"errors"
	"net"
	"time"
)

func dialBackendConn(addr string, useTLS, tlsSkipVerify bool, trust *upstreamTrust, timeout time.Duration) (net.Conn, error) {
	conn, err := dialUpstreamTCP(addr, timeout)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return conn, nil
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	tlsCfg := trust.tlsConfig(host, tlsSkipVerify)
	conn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return tlsConn, nil
}

func dialUpstreamTCP(addr string, timeout time.Duration) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return dialTCPDirect("tcp6", addr, timeout)
	}
	conn, err := DialTCP4(addr, timeout)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dialTCPDirect("tcp6", addr, timeout)
	}
	return conn, err
}
