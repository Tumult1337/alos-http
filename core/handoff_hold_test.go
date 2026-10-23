//go:build linux && amd64

package core

import (
	"net"
	"testing"
)

func TestTrackedHandoffConnHoldAfterCloseReleasesOnce(t *testing.T) {
	srv := New(Config{})
	defer stopServer(srv)
	client, server := net.Pipe()
	defer client.Close()
	tracked := srv.trackHandoffConn(server, "", false, nil)
	if tracked == nil || srv.activeConns.Load() != 1 {
		t.Fatalf("tracking failed: activeConns %d", srv.activeConns.Load())
	}
	_ = tracked.Close()
	if tracked.retainSlots() {
		tracked.releaseHold()
		t.Fatalf("a hold was taken on a closed conn, activeConns %d", srv.activeConns.Load())
	}
	if got := srv.activeConns.Load(); got != 0 {
		t.Fatalf("activeConns %d after close, want 0", got)
	}
}

func TestTrackedHandoffConnHoldDefersRelease(t *testing.T) {
	srv := New(Config{})
	defer stopServer(srv)
	client, server := net.Pipe()
	defer client.Close()
	tracked := srv.trackHandoffConn(server, "", false, nil)
	if !tracked.retainSlots() {
		t.Fatal("hold on an open conn refused")
	}
	_ = tracked.Close()
	if got := srv.activeConns.Load(); got != 1 {
		t.Fatalf("activeConns %d while a hold is open, want 1", got)
	}
	tracked.releaseHold()
	if got := srv.activeConns.Load(); got != 0 {
		t.Fatalf("activeConns %d after the hold ends, want 0", got)
	}
}
