//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"testing"
)

func perfTLSCloseNotifyConn(t *testing.T) (*epollConn, *TrafficAEAD) {
	t.Helper()
	cs := NegotiateSuite([]uint16{0x1301})
	secret := bytes.Repeat([]byte{0x22}, cs.HashLen)
	writer, err := NewTrafficAEAD(cs.HashFn, secret, cs)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewTrafficAEAD(cs.HashFn, secret, cs)
	if err != nil {
		t.Fatal(err)
	}
	c := &epollConn{tls: true, fd: 1, phase: tlsConnPhaseApplication, appWriter: writer, closeAfter: true}
	c.writeBuf = buildTLSAppDataRecords(nil, writer, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	return c, reader
}

func TestPerfTLSCloseNotifyCoalescedAfterFinalRecord(t *testing.T) {
	c, reader := perfTLSCloseNotifyConn(t)
	c.coalesceCloseNotify()
	if !c.tlsAlertSent {
		t.Fatal("close_notify not appended to a quiescent closing TLS H1 conn")
	}
	_, payload, n, ok, err := nextTLSRecord(c.writeBuf)
	if err != nil || !ok {
		t.Fatalf("response record ok=%v err=%v", ok, err)
	}
	if _, err := reader.Decrypt(payload); err != nil {
		t.Fatalf("response record: %v", err)
	}
	ct, payload, m, ok, err := nextTLSRecord(c.writeBuf[n:])
	if err != nil || !ok || ct != tlsRecAppData || n+m != len(c.writeBuf) {
		t.Fatalf("alert record ct=%#x ok=%v err=%v, %d trailing bytes", ct, ok, err, len(c.writeBuf)-n-m)
	}
	pt, err := reader.Decrypt(payload)
	if err != nil {
		t.Fatalf("alert record: %v", err)
	}
	if want := []byte{tlsAlertLevelWarning, byte(alertCloseNotify), tlsRecAlert}; !bytes.Equal(pt, want) {
		t.Fatalf("alert plaintext %x, want %x", pt, want)
	}
	before := len(c.writeBuf)
	c.coalesceCloseNotify()
	if len(c.writeBuf) != before {
		t.Fatal("close_notify appended twice")
	}
}

func TestPerfTLSCloseNotifyNotCoalescedWhileOutputPending(t *testing.T) {
	cases := map[string]func(c *epollConn){
		"dispatching":  func(c *epollConn) { c.dispatching = true },
		"in flight":    func(c *epollConn) { c.inFlight = 1 },
		"body pending": func(c *epollConn) { c.bodyOut = []byte("x") },
		"progressive":  func(c *epollConn) { c.h1Body = []byte("x") },
		"h2":           func(c *epollConn) { c.phase = tlsConnPhaseH2Native },
		"not closing":  func(c *epollConn) { c.closeAfter = false },
		"alert sent":   func(c *epollConn) { c.tlsAlertSent = true },
		"plain":        func(c *epollConn) { c.tls = false },
		"lingering":    func(c *epollConn) { c.lingering = true },
	}
	for name, mutate := range cases {
		c, _ := perfTLSCloseNotifyConn(t)
		mutate(c)
		before := len(c.writeBuf)
		c.coalesceCloseNotify()
		if len(c.writeBuf) != before {
			t.Fatalf("%s: close_notify appended while the conn is not done writing", name)
		}
	}
}

func TestPerfTLSConnectionCloseEndsWithCloseNotify(t *testing.T) {
	ts := newTestServer(t, testServerOptions{TLS: true, Routes: perfTLSRoutes})
	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		conn, err := tls.Dial("tcp4", ts.addr, &tls.Config{InsecureSkipVerify: true, ServerName: ts.domain, NextProtos: []string{"http/1.1"}, MinVersion: version, MaxVersion: version})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, "GET /plaintext HTTP/1.1\r\nHost: "+ts.domain+"\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(conn)
		conn.Close()
		if err != nil {
			t.Fatalf("version %#x: read until close_notify: %v", version, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
		if err != nil {
			t.Fatalf("version %#x: %v", version, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK || len(body) == 0 {
			t.Fatalf("version %#x: status %d body %q err %v", version, resp.StatusCode, body, err)
		}
	}
}
