//go:build linux && amd64

package core

import (
	"context"
	"errors"
	"net"
	"testing"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}

func TestProxyRequestReplayable(t *testing.T) {
	cases := []struct {
		method  string
		headers [][2]string
		trust   bool
		want    bool
	}{
		{"GET", nil, false, true},
		{"HEAD", nil, false, true},
		{"OPTIONS", nil, false, true},
		{"TRACE", nil, false, true},
		{"POST", nil, true, false},
		{"PUT", nil, true, false},
		{"DELETE", nil, true, false},
		{"PATCH", nil, true, false},
		{"get", nil, true, false},
		{"POST", [][2]string{{"Idempotency-Key", "abc"}}, true, true},
		{"PATCH", [][2]string{{"x-idempotency-key", "abc"}}, true, true},
		{"POST", [][2]string{{"Idempotency", "abc"}}, true, false},
		{"POST", [][2]string{{"Idempotency-Key", "abc"}}, false, false},
		{"PATCH", [][2]string{{"x-idempotency-key", "abc"}}, false, false},
	}
	for _, c := range cases {
		if got := proxyRequestReplayable(c.method, c.headers, c.trust); got != c.want {
			t.Errorf("proxyRequestReplayable(%q, %v, trust=%v) = %v, want %v", c.method, c.headers, c.trust, got, c.want)
		}
	}
}

func TestProxyMayRetry(t *testing.T) {
	base := errors.New("boom")
	cases := []struct {
		name       string
		replayable bool
		err        error
		want       bool
	}{
		{"nothing sent, unsafe", false, &proxyAttemptError{err: base}, true},
		{"nothing sent, safe", true, &proxyAttemptError{err: base}, true},
		{"sent, unsafe", false, &proxyAttemptError{err: base, wroteRequest: true}, false},
		{"sent, safe", true, &proxyAttemptError{err: base, wroteRequest: true}, true},
		{"response started, safe", true, &proxyAttemptError{err: base, wroteRequest: true, gotResponse: true}, false},
		{"timeout after send, unsafe", false, &proxyAttemptError{err: base, wroteRequest: true, timeout: true}, false},
		{"timeout before send, unsafe", false, &proxyAttemptError{err: base, timeout: true}, true},
		{"unknown error, unsafe", false, base, false},
		{"unknown error, safe", true, base, true},
		{"wrapped attempt error", false, &wrappedErr{&proxyAttemptError{err: base}}, true},
	}
	for _, c := range cases {
		if got := proxyMayRetry(c.replayable, c.err); got != c.want {
			t.Errorf("%s: proxyMayRetry = %v, want %v", c.name, got, c.want)
		}
	}
}

type wrappedErr struct{ inner error }

func (w *wrappedErr) Error() string { return "wrapped: " + w.inner.Error() }
func (w *wrappedErr) Unwrap() error { return w.inner }

func TestProxyFailureStatus(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, 502},
		{errors.New("reset"), 502},
		{&proxyAttemptError{err: errors.New("x")}, 502},
		{&proxyAttemptError{err: errors.New("x"), timeout: true}, 504},
		{timeoutError{}, 504},
		{context.DeadlineExceeded, 504},
		{&net.OpError{Op: "read", Err: timeoutError{}}, 504},
	}
	for _, c := range cases {
		if got := proxyFailureStatus(c.err); got != c.want {
			t.Errorf("proxyFailureStatus(%v) = %d, want %d", c.err, got, c.want)
		}
	}
	if proxyFailureMessage(504) != "Gateway Timeout" || proxyFailureMessage(502) != "All backends failed" {
		t.Error("unexpected failure messages")
	}
}

func TestProxyAttemptErrorUnwraps(t *testing.T) {
	base := errors.New("base")
	e := &proxyAttemptError{err: base}
	if !errors.Is(e, base) || e.Error() != "base" {
		t.Fatalf("proxyAttemptError does not unwrap to its cause")
	}
}
