//go:build linux && amd64

package core

import (
	"errors"
	"net"
)

type proxyAttemptError struct {
	err          error
	wroteRequest bool
	gotResponse  bool
	timeout      bool
}

func (e *proxyAttemptError) Error() string { return e.err.Error() }

func (e *proxyAttemptError) Unwrap() error { return e.err }

func proxyRequestReplayable(method string, headers [][2]string, trustIdempotencyKey bool) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	if !trustIdempotencyKey {
		return false
	}
	for i := range headers {
		name := headers[i][0]
		if EqualFoldASCII(name, "idempotency-key") || EqualFoldASCII(name, "x-idempotency-key") {
			return true
		}
	}
	return false
}

func proxyMayRetry(replayable bool, err error) bool {
	var attempt *proxyAttemptError
	if !errors.As(err, &attempt) {
		return replayable
	}
	if attempt.gotResponse {
		return false
	}
	return !attempt.wroteRequest || replayable
}

func proxyFailureStatus(err error) int {
	var attempt *proxyAttemptError
	if errors.As(err, &attempt) {
		if attempt.timeout {
			return 504
		}
		return 502
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return 504
	}
	return 502
}

func proxyFailureMessage(status int) string {
	if status == 504 {
		return "Gateway Timeout"
	}
	return "All backends failed"
}
