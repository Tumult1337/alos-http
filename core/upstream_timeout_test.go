//go:build linux && amd64

package core

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	upstreamTimeoutShort     = 150 * time.Millisecond
	upstreamSweepGranularity = time.Duration(sweepIntervalNano)
	upstreamTimeoutCeil      = upstreamTimeoutShort + upstreamSweepGranularity + 150*time.Millisecond
	upstreamOriginDelay      = upstreamTimeoutCeil + 150*time.Millisecond
)

func delayedOrigin(t *testing.T, delay time.Duration) string {
	t.Helper()
	return rawOrigin(t, func(c net.Conn) {
		time.Sleep(delay)
		fmt.Fprint(c, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
	})
}

func newTimeoutClient(t *testing.T) *UpstreamClient {
	t.Helper()
	client, err := NewUpstreamClient(UpstreamConfig{Loops: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestUpstreamReadTimeoutFiresBeforeASlowOrigin(t *testing.T) {
	client := newTimeoutClient(t)
	origin := delayedOrigin(t, upstreamOriginDelay)
	start := time.Now()
	_, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: origin, Path: "/", ReadTimeout: upstreamTimeoutShort})
	elapsed := time.Since(start)
	if !errors.Is(err, errFPTimeout) {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if elapsed < upstreamTimeoutShort || elapsed > upstreamTimeoutCeil {
		t.Fatalf("timed out after %s, want between %s and %s", elapsed, upstreamTimeoutShort, upstreamTimeoutCeil)
	}
}

const (
	upstreamPromptSlack    = 75 * time.Millisecond
	upstreamPromptCeil     = upstreamTimeoutShort + upstreamTimeoutShort/sweepsPerTimeout + upstreamPromptSlack
	upstreamPromptAttempts = 5
)

func TestUpstreamShortReadTimeoutFiresWithinAQuarterOfItself(t *testing.T) {
	client := newTimeoutClient(t)
	origin := delayedOrigin(t, upstreamOriginDelay)
	for attempt := range upstreamPromptAttempts {
		start := turbo.Now()
		_, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: origin, Path: "/", ReadTimeout: upstreamTimeoutShort})
		elapsed := turbo.Since(start)
		if !errors.Is(err, errFPTimeout) {
			t.Fatalf("attempt %d: err = %v, want a timeout", attempt, err)
		}
		if elapsed < upstreamTimeoutShort || elapsed > upstreamPromptCeil {
			t.Fatalf("attempt %d: timed out after %s, want between %s and %s", attempt, elapsed, upstreamTimeoutShort, upstreamPromptCeil)
		}
	}
}

func TestUpstreamReadTimeoutLongerThanTheOriginSucceeds(t *testing.T) {
	client := newTimeoutClient(t)
	origin := delayedOrigin(t, upstreamOriginDelay)
	resp, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: origin, Path: "/", ReadTimeout: 2 * upstreamOriginDelay})
	if err != nil || resp.Status != 200 {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
}

func TestUpstreamDialTimeoutDoesNotCapTheResponseWait(t *testing.T) {
	client := newTimeoutClient(t)
	origin := delayedOrigin(t, upstreamOriginDelay)
	resp, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: origin, Path: "/", DialTimeout: upstreamTimeoutShort})
	if err != nil || resp.Status != 200 {
		t.Fatalf("a dial timeout shorter than the origin's think time failed the request: resp=%v err=%v", resp, err)
	}
}

func TestUpstreamReadTimeoutIsBetweenBytesNotTotal(t *testing.T) {
	client := newTimeoutClient(t)
	const chunks = 6
	origin := rawOrigin(t, func(c net.Conn) {
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\ncontent-length: %d\r\n\r\n", chunks)
		for range chunks {
			time.Sleep(upstreamTimeoutShort / 2)
			_, _ = c.Write([]byte("x"))
		}
	})
	resp, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: origin, Path: "/", ReadTimeout: 2 * upstreamTimeoutShort})
	if err != nil || resp.Status != 200 || len(resp.Body) != chunks {
		t.Fatalf("a steadily trickling origin was cut off: resp=%v err=%v", resp, err)
	}
}

func TestUpstreamDialTimeoutToABlackhole(t *testing.T) {
	client := newTimeoutClient(t)
	start := time.Now()
	_, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: "10.255.255.1:81", Path: "/", DialTimeout: upstreamTimeoutShort})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a blackholed origin answered")
	}
	if elapsed > upstreamTimeoutCeil {
		t.Fatalf("dial gave up after %s, want under %s (err=%v)", elapsed, upstreamTimeoutCeil, err)
	}
}
