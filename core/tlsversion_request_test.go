//go:build linux && amd64

package core

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func freeLoopbackAddr(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func reportTLSVersion(req *Request, resp *Response) {
	resp.Status(200).String(strconv.Itoa(int(req.TLSVersion)))
}

func stopServer(srv *Server) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func fetchTLSVersion(t *testing.T, cl *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := cl.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	v, err := strconv.Atoi(string(body))
	if err != nil {
		t.Fatalf("body %q is not a version", body)
	}
	return v, resp.Proto
}

func TestRequestTLSVersionPerProtocol(t *testing.T) {
	addr := freeLoopbackAddr(t)
	srv := New(Config{
		Addr: addr, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1, Listeners: 1,
		Certs: []CertConfig{{Domain: "ver.test", Source: CertSelfSigned}},
	})
	srv.Router.GET("/tlsver", reportTLSVersion)
	go func() { _ = srv.ListenAndServeTLS() }()
	defer stopServer(srv)
	waitForProxy(t, addr)

	cases := []struct {
		name    string
		version uint16
		alpn    string
	}{
		{"h1 TLS1.2", tls.VersionTLS12, "http/1.1"},
		{"h1 TLS1.3", tls.VersionTLS13, "http/1.1"},
		{"h2 TLS1.2", tls.VersionTLS12, "h2"},
		{"h2 TLS1.3", tls.VersionTLS13, "h2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, ServerName: "ver.test",
					MinVersion: tc.version, MaxVersion: tc.version, NextProtos: []string{tc.alpn},
				},
				ForceAttemptHTTP2: tc.alpn == "h2",
				MaxConnsPerHost:   1,
			}
			defer tr.CloseIdleConnections()
			cl := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			wantProto := "HTTP/1.1"
			if tc.alpn == "h2" {
				wantProto = "HTTP/2.0"
			}
			for rep := range 3 {
				got, proto := fetchTLSVersion(t, cl, "https://"+addr+"/tlsver")
				if proto != wantProto {
					t.Fatalf("rep %d: negotiated %s, want %s", rep, proto, wantProto)
				}
				if got != int(tc.version) {
					t.Fatalf("rep %d: req.TLSVersion=%#x, want %#x", rep, got, tc.version)
				}
			}
		})
	}
}

func TestRequestTLSVersionIsZeroOnPlainHTTP(t *testing.T) {
	addr := freeLoopbackAddr(t)
	srv := New(Config{Addr: addr, LogRequests: false, MaxConnsPerIP: -1, Listeners: 1})
	srv.Router.GET("/tlsver", reportTLSVersion)
	go func() { _ = srv.ListenAndServe() }()
	defer stopServer(srv)
	waitForProxy(t, addr)

	cl := &http.Client{Timeout: 5 * time.Second}
	for rep := range 3 {
		if got, _ := fetchTLSVersion(t, cl, "http://"+addr+"/tlsver"); got != 0 {
			t.Fatalf("rep %d: plain request reported TLSVersion %#x", rep, got)
		}
	}
}

func TestRequestResetClearsTLSVersion(t *testing.T) {
	r := &Request{TLSVersion: TLSVersion13}
	r.Reset()
	if r.TLSVersion != 0 {
		t.Fatalf("Reset left TLSVersion=%#x", r.TLSVersion)
	}
}
