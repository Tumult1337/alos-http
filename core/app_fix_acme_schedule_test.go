//go:build linux && amd64

package core

import (
	"context"
	"testing"
	"time"
)

func TestAppFixACMERenewalPanicDoesNotEscape(t *testing.T) {
	stub := newARIStub(t, true)
	f := newACMEScheduleFixture(t, stub)
	stub.setWindow(f.clock.Add(-2*time.Hour), f.clock.Add(-time.Hour))
	f.obtainFn = func() error { panic("renewal blew up") }
	escaped := func() (r any) {
		defer func() { r = recover() }()
		f.ai.renewAll()
		return nil
	}()
	if escaped != nil {
		t.Fatalf("a panic inside the ACME renewal escaped renewAll (it would kill the server): %v", escaped)
	}
	if f.obtained.Load() != 1 {
		t.Fatalf("renewal attempts %d, want 1", f.obtained.Load())
	}
	_, renewAt, _ := f.ai.renewalTime(context.Background(), "ari.test", f.leaf)
	if !renewAt.After(f.clock) {
		t.Fatal("a panicking renewal was not recorded as a failure with a retry delay")
	}
}

func TestAppFixACMEARIWindowPastExpiryIsClamped(t *testing.T) {
	stub := newARIStub(t, true)
	f := newACMEScheduleFixture(t, stub)
	stub.setWindow(f.leaf.NotAfter.Add(24*time.Hour), f.leaf.NotAfter.Add(48*time.Hour))
	_, renewAt, _ := f.ai.renewalTime(context.Background(), "ari.test", f.leaf)
	if !renewAt.Before(f.leaf.NotAfter) {
		t.Fatalf("renewal scheduled at %v, after the certificate expires at %v", renewAt, f.leaf.NotAfter)
	}
	if want := latestRenewal(f.leaf); !renewAt.Equal(want) {
		t.Fatalf("renewal at %v, want the clamp %v", renewAt, want)
	}
}

func TestAppFixACMEARITimeoutRetriesSooner(t *testing.T) {
	stub := newARIStub(t, true)
	f := newACMEScheduleFixture(t, stub)
	stub.setWindow(f.clock.Add(24*time.Hour), f.clock.Add(25*time.Hour))
	if _, _, nextPoll := f.ai.renewalTime(context.Background(), "ari.test", f.leaf); nextPoll.IsZero() {
		t.Fatal("first poll did not schedule a next poll")
	}
	f.clock = f.clock.Add(7 * time.Hour)
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(0, 1))
	defer cancel()
	_, _, nextPoll := f.ai.renewalTime(expired, "ari.test", f.leaf)
	if want := f.clock.Add(acmeARITimeoutRetry); !nextPoll.Equal(want) {
		t.Fatalf("after a timed-out renewalInfo poll the next poll is %v, want %v (not the 6h default)", nextPoll, want)
	}
}
