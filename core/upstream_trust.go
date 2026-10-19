//go:build linux && amd64

package core

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

var errUpstreamClientKey = errors.New("upstream client certificate key cannot sign")

type upstreamTrust struct {
	rootCAs    *x509.CertPool
	serverName string
	clientCert *tls.Certificate
}

func newUpstreamTrust(bc BackendConfig) *upstreamTrust {
	if bc.RootCAs == nil && bc.ServerName == "" && bc.ClientCert == nil {
		return nil
	}
	return &upstreamTrust{rootCAs: bc.RootCAs, serverName: bc.ServerName, clientCert: bc.ClientCert}
}

func (u *upstreamTrust) verifyName(host string) string {
	if u != nil && u.serverName != "" {
		return u.serverName
	}
	return host
}

func (u *upstreamTrust) roots() *x509.CertPool {
	if u == nil {
		return nil
	}
	return u.rootCAs
}

func (u *upstreamTrust) clientChain() ([][]byte, crypto.Signer, error) {
	if u == nil || u.clientCert == nil || len(u.clientCert.Certificate) == 0 {
		return nil, nil, nil
	}
	signer, ok := u.clientCert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, errUpstreamClientKey
	}
	return u.clientCert.Certificate, signer, nil
}

func (u *upstreamTrust) tlsConfig(host string, skipVerify bool) *tls.Config {
	cfg := &tls.Config{ServerName: u.verifyName(host), RootCAs: u.roots(), InsecureSkipVerify: skipVerify}
	if u != nil && u.clientCert != nil {
		cfg.Certificates = []tls.Certificate{*u.clientCert}
	}
	return cfg
}
