//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
)

const proxyFixTransferBody = "amount=100"

func proxyFixExecutingOrigin(t *testing.T, executed *atomic.Int64) *inloopOrigin {
	t.Helper()
	return newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.ReadAll(req.Body)
		executed.Add(1)
		_ = conn.Close()
	})
}

func proxyFixTransfer() string {
	return "POST /transfer HTTP/1.1\r\nHost: " + proxyFixDomain + "\r\nIdempotency-Key: k-1\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 10\r\nConnection: close\r\n\r\n" + proxyFixTransferBody
}

func proxyFixTwoExecutingBackends(t *testing.T, trust bool, viaDispatch bool) int64 {
	t.Helper()
	var executed atomic.Int64
	a := proxyFixExecutingOrigin(t, &executed)
	b := proxyFixExecutingOrigin(t, &executed)
	domains := []DomainConfig{{
		Domain:              proxyFixDomain,
		Backends:            []BackendConfig{{Addr: a.addr()}, {Addr: b.addr()}},
		MaxRetries:          1,
		TrustIdempotencyKey: trust,
	}}
	_, addr := proxyFixStart(t, Config{}, domains, func(s *Server) {
		if viaDispatch {
			s.OnResponse(func(req *Request, resp *Response) {})
		}
	})
	resp, _ := proxyFixRoundTrip(t, addr, proxyFixTransfer())
	if resp.StatusCode < http.StatusInternalServerError {
		t.Fatalf("both backends drop the connection after executing, got status %d", resp.StatusCode)
	}
	return executed.Load()
}

func TestProxyFixIdempotencyKeyDoesNotReplayPOSTByDefault(t *testing.T) {
	for _, path := range []struct {
		name        string
		viaDispatch bool
	}{{"in_loop", false}, {"dispatch", true}} {
		t.Run(path.name, func(t *testing.T) {
			if n := proxyFixTwoExecutingBackends(t, false, path.viaDispatch); n != 1 {
				t.Fatalf("a POST carrying a client Idempotency-Key was executed %d times across backends, want 1", n)
			}
		})
	}
}

func TestProxyFixTrustIdempotencyKeyOptInReplays(t *testing.T) {
	for _, path := range []struct {
		name        string
		viaDispatch bool
	}{{"in_loop", false}, {"dispatch", true}} {
		t.Run(path.name, func(t *testing.T) {
			if n := proxyFixTwoExecutingBackends(t, true, path.viaDispatch); n != 2 {
				t.Fatalf("with TrustIdempotencyKey the keyed POST was executed %d times, want 2 (one retry)", n)
			}
		})
	}
}
