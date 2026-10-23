//go:build linux && amd64

package core

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	perfIdleTimeoutTest  = 150 * time.Millisecond
	perfIdleCloseCeiling = 3 * time.Second
)

func perfIdleServer(t *testing.T, useTLS bool) *testServer {
	return newTestServer(t, testServerOptions{
		TLS:    useTLS,
		Routes: perfTLSRoutes,
		Config: func(cfg *Config) {
			cfg.IdleTimeout = perfIdleTimeoutTest
			cfg.PlainHTTP = !useTLS
		},
	})
}

func perfIdleAwaitServerClose(t *testing.T, conn net.Conn, br *bufio.Reader) {
	t.Helper()
	start := turbo.Now()
	_ = conn.SetReadDeadline(time.Unix(0, turbo.UnixNano()+int64(perfIdleCloseCeiling)))
	_, err := br.ReadByte()
	if err == nil {
		t.Fatal("server sent unexpected bytes on an idle keep-alive conn")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("idle keep-alive conn still open %v after its response (IdleTimeout %v)", turbo.Since(start), perfIdleTimeoutTest)
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Logf("conn closed by server after %v: %v", turbo.Since(start), err)
	}
}

func TestPerfTLSIdleTimeoutAfterResponse(t *testing.T) {
	ts := perfIdleServer(t, true)
	conn, err := tls.Dial("tcp4", ts.addr, &tls.Config{InsecureSkipVerify: true, ServerName: ts.domain, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /plaintext HTTP/1.1\r\nHost: " + ts.domain + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	if _, err := perfReadResponseBodyLen(br); err != nil {
		t.Fatal(err)
	}
	perfIdleAwaitServerClose(t, conn, br)
}

func TestPerfPlainIdleTimeoutAfterResponse(t *testing.T) {
	ts := perfIdleServer(t, false)
	conn, err := net.Dial("tcp4", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /plaintext HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	if _, err := perfReadResponseBodyLen(br); err != nil {
		t.Fatal(err)
	}
	perfIdleAwaitServerClose(t, conn, br)
}
