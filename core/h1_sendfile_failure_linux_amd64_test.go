//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	sendfileFailSize    = 8 << 20
	sendfileFailShort   = 4 << 20
	sendfileFailPrimeOK = 2
)

func TestH1DetachedSendfileFailureClosesConnection(t *testing.T) {
	perfCoreSettleStaticFiles(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'f'}, sendfileFailSize), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := startH2FixServer(t, nil, func(srv *Server) {
		srv.Router.GET("/files/*", Static("/files/", StaticConfig{Root: dir, CacheTTL: time.Hour, DisableCompression: true}))
		srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("second-response") })
	})
	for range sendfileFailPrimeOK {
		resp, err := http.Get("http://" + addr + "/files/big.bin")
		if err != nil {
			t.Fatal(err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || n != sendfileFailSize {
			t.Fatalf("priming request: status=%d bytes=%d", resp.StatusCode, n)
		}
	}
	if err := os.Truncate(path, sendfileFailShort); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", addr, h2FixCeiling)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(wallDeadline(h2FixCeiling))
	if _, err := io.WriteString(conn, "GET /files/big.bin HTTP/1.1\r\nHost: f.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(h2FixQuietWindow)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ContentLength != sendfileFailSize {
		t.Fatalf("fixture did not promise the cached size: Content-Length=%d", resp.ContentLength)
	}
	if _, err := io.WriteString(conn, "GET /ok HTTP/1.1\r\nHost: f.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("connection stayed open after a short sendfile body (%d of %s bytes read): %v", len(rest), strconv.Itoa(sendfileFailSize), err)
	}
	if len(rest) >= sendfileFailSize {
		t.Fatalf("fixture sent the whole body (%d bytes); the sendfile did not fail", len(rest))
	}
	if bytes.Contains(rest, []byte("second-response")) {
		t.Fatal("the next response was written into the short body of the failed one")
	}
}
