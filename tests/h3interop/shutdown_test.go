package h3interop

import (
	"context"
	"testing"

	"github.com/guno1928/alos-http/core"
	"github.com/guno1928/turbo"
)

type getResult struct {
	status int
	body   []byte
	err    error
}

func TestH3ShutdownDrainsInFlightRequest(t *testing.T) {
	hs := startH3(t, core.Config{})
	c := newClient(t)
	pingThrough(t, c, hs.addr)

	results := make(chan getResult, 1)
	go func() {
		status, body, err := doGet(c, hs.addr, "/slow")
		results <- getResult{status, body, err}
	}()
	select {
	case <-hs.slowEntered:
	case <-turbo.After(startupCeiling):
		t.Fatal("slow handler never started")
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownCeiling)
	defer cancel()
	start := turbo.Now()
	if err := hs.srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown did not drain the HTTP/3 connection within %v: %v", shutdownCeiling, err)
	}
	if took := turbo.Since(start); took >= shutdownCeiling {
		t.Fatalf("Shutdown took %v", took)
	}

	select {
	case r := <-results:
		if r.err != nil || r.status != 200 || string(r.body) != "slow done" {
			t.Fatalf("in-flight request during Shutdown: %d %q %v", r.status, r.body, r.err)
		}
	case <-turbo.After(clientTimeout):
		t.Fatal("in-flight request never completed")
	}
}
