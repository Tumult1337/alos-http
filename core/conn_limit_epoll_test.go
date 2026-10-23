//go:build linux && amd64

package core

import (
	"net"
	"testing"
)

func xffReq(port, realIP string) *Request {
	return &Request{RemoteAddr: "10.0.0.1:" + port, Headers: [][2]string{{"X-Forwarded-For", realIP}}}
}

func TestHandoffConn_ReleasesIPSlotOnClose(t *testing.T) {
	s := New(Config{MaxConnsPerIP: 1})
	defer s.perIPConnLimiter.Load().Stop()

	if !s.perIPConnLimiter.Load().acquire("203.0.113.5", s.Limits().MaxConnsPerIP) {
		t.Fatal("first acquire should succeed")
	}

	_, srvSide := net.Pipe()
	tracked := s.trackHandoffConn(srvSide, "203.0.113.5", false, nil)
	if tracked == nil {
		t.Fatal("trackHandoffConn returned nil")
	}

	if s.perIPConnLimiter.Load().acquire("203.0.113.5", s.Limits().MaxConnsPerIP) {
		t.Fatal("slot must stay held while the streamed connection is alive")
	}

	_ = tracked.Close()

	if !s.perIPConnLimiter.Load().acquire("203.0.113.5", s.Limits().MaxConnsPerIP) {
		t.Fatal("slot must be released once the streamed connection closes")
	}
}

func TestApplyTrustedIP_ProxyModeRewritesRealIP(t *testing.T) {
	s := New(Config{ProxyMode: true, MaxConnsPerIP: 2})
	defer s.perIPConnLimiter.Load().Stop()

	req := xffReq("1", "203.0.113.9")
	applyTrustedIP(s, req)
	if req.RemoteAddr != "203.0.113.9" {
		t.Fatalf("RemoteAddr=%q want rewritten real IP 203.0.113.9", req.RemoteAddr)
	}
}
