//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const (
	serveE2ESize      = 3<<20 + 12345
	serveE2ESparse    = 1 << 30
	serveE2ESparseOff = 1073741000
)

type serveE2EFixture struct {
	dir     string
	content []byte
	tail    []byte
}

func newServeE2EFixture(t *testing.T) serveE2EFixture {
	t.Helper()
	dir := t.TempDir()
	fx := serveE2EFixture{dir: dir, content: serveContentPattern(serveE2ESize), tail: serveContentPattern(serveE2ESparse - serveE2ESparseOff)}
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), fx.content, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "sparse.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(serveE2ESparse); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(fx.tail, serveE2ESparseOff); err != nil {
		t.Fatal(err)
	}
	return fx
}

func startServeContentServer(t *testing.T, fx serveE2EFixture, useTLS bool) *testServer {
	return newTestServer(t, testServerOptions{
		TLS: useTLS,
		Routes: func(r *Router) {
			r.GET("/s/*filepath", Static("/s", StaticConfig{Root: fx.dir}))
		},
	})
}

func TestServeContentOverHTTP1Pipelined(t *testing.T) {
	fx := newServeE2EFixture(t)
	ts := startServeContentServer(t, fx, false)
	c := ts.dial(t)
	br := bufio.NewReader(c)
	host := "Host: " + ts.domain + "\r\n"
	sizeText := strconv.Itoa(serveE2ESize)

	writeAll(t, c, "GET /s/big.bin HTTP/1.1\r\n"+host+"Range: bytes=1000000-2999999\r\n\r\n")
	resp, body := readH1Response(t, br, http.MethodGet)
	if resp.StatusCode != 206 || resp.Header.Get("Content-Range") != "bytes 1000000-2999999/"+sizeText {
		t.Fatalf("range: %d %q", resp.StatusCode, resp.Header.Get("Content-Range"))
	}
	if sha256.Sum256(body) != sha256.Sum256(fx.content[1000000:3000000]) {
		t.Fatalf("range body differs (%d bytes)", len(body))
	}
	etag := resp.Header.Get("ETag")

	writeAll(t, c, "GET /s/big.bin HTTP/1.1\r\n"+host+"If-None-Match: W/\"x\", "+etag+"\r\n\r\n"+
		"HEAD /s/big.bin HTTP/1.1\r\n"+host+"Range: bytes=0-9\r\n\r\n"+
		"GET /s/big.bin HTTP/1.1\r\n"+host+"Range: bytes="+sizeText+"-\r\n\r\n"+
		"GET /s/big.bin HTTP/1.1\r\n"+host+"Range: bytes=-500\r\n\r\n")

	notModified, body := readH1Response(t, br, http.MethodGet)
	if notModified.StatusCode != 304 || len(body) != 0 || notModified.Header.Get("ETag") != etag {
		t.Fatalf("304: %d etag %q body %d", notModified.StatusCode, notModified.Header.Get("ETag"), len(body))
	}
	if _, has := notModified.Header["Content-Length"]; has {
		t.Fatalf("304 carries Content-Length %q", notModified.Header.Get("Content-Length"))
	}

	head, body := readH1Response(t, br, http.MethodHead)
	if head.StatusCode != 200 || len(body) != 0 || head.Header.Get("Content-Length") != sizeText || head.Header.Get("Accept-Ranges") != "bytes" {
		t.Fatalf("HEAD with Range: %d CL %q body %d", head.StatusCode, head.Header.Get("Content-Length"), len(body))
	}

	unsatisfiable, _ := readH1Response(t, br, http.MethodGet)
	if unsatisfiable.StatusCode != 416 || unsatisfiable.Header.Get("Content-Range") != "bytes */"+sizeText {
		t.Fatalf("416: %d %q", unsatisfiable.StatusCode, unsatisfiable.Header.Get("Content-Range"))
	}

	suffix, body := readH1Response(t, br, http.MethodGet)
	if suffix.StatusCode != 206 || !bytes.Equal(body, fx.content[serveE2ESize-500:]) {
		t.Fatalf("suffix after pipelined bodyless responses: %d %d bytes", suffix.StatusCode, len(body))
	}
}

func TestServeContentSparseGiBOverHTTP1(t *testing.T) {
	fx := newServeE2EFixture(t)
	ts := startServeContentServer(t, fx, false)
	resp, body := ts.rawH1(t, "GET /s/sparse.bin HTTP/1.1\r\nHost: "+ts.domain+"\r\nRange: bytes=1073741000-\r\n\r\n")
	if resp.StatusCode != 206 || len(body) != 824 || sha256.Sum256(body) != sha256.Sum256(fx.tail) {
		t.Fatalf("sparse tail: %d %d bytes", resp.StatusCode, len(body))
	}
}

func TestServeContentOverTLS(t *testing.T) {
	fx := newServeE2EFixture(t)
	ts := startServeContentServer(t, fx, true)
	for _, proto := range []string{"http/1.1", "h2"} {
		cl := ts.client(t, proto)
		req, _ := http.NewRequest(http.MethodGet, ts.url("/s/big.bin"), nil)
		req.Header.Set("Range", "bytes=123-2000122")
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 206 || sha256.Sum256(body) != sha256.Sum256(fx.content[123:2000123]) {
			t.Fatalf("%s (%s): %d %d bytes", proto, resp.Proto, resp.StatusCode, len(body))
		}
		wantProto := 1
		if proto == "h2" {
			wantProto = 2
		}
		if resp.ProtoMajor != wantProto {
			t.Fatalf("negotiated %s, want %s", resp.Proto, proto)
		}

		cond, _ := http.NewRequest(http.MethodGet, ts.url("/s/big.bin"), nil)
		cond.Header.Set("If-None-Match", resp.Header.Get("ETag"))
		notModified, err := cl.Do(cond)
		if err != nil {
			t.Fatalf("%s conditional: %v", proto, err)
		}
		rest, _ := io.ReadAll(notModified.Body)
		_ = notModified.Body.Close()
		if notModified.StatusCode != 304 || len(rest) != 0 {
			t.Fatalf("%s conditional: %d %d bytes", proto, notModified.StatusCode, len(rest))
		}

		ifRange, _ := http.NewRequest(http.MethodGet, ts.url("/s/big.bin"), nil)
		ifRange.Header.Set("Range", "bytes=0-9")
		ifRange.Header.Set("If-Range", `"stale"`)
		full, err := cl.Do(ifRange)
		if err != nil {
			t.Fatalf("%s if-range: %v", proto, err)
		}
		all, _ := io.ReadAll(full.Body)
		_ = full.Body.Close()
		if full.StatusCode != 200 || len(all) != serveE2ESize {
			t.Fatalf("%s stale If-Range: %d %d bytes", proto, full.StatusCode, len(all))
		}
	}
}

func TestSendFileFDHonoursOffset(t *testing.T) {
	content := serveContentPattern(300 << 10)
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()

	const start, length = 70001, 200000
	srv := New(Config{})
	sw := srv.NewPlainH1StreamWriter(server)
	if err := sw.WriteHeader(206, [][2]string{{"content-length", strconv.Itoa(length)}}, "application/octet-stream"); err != nil {
		t.Fatal(err)
	}
	var native int64
	nativeSendFileHook = func(n int64) { native += n }
	defer func() { nativeSendFileHook = nil }()

	done := make(chan error, 1)
	go func() {
		sent, err := trySendFileFastPath(sw, f, start, length, nil)
		if !sent && err == nil {
			err = io.ErrNoProgress
		}
		done <- err
	}()
	_ = client.SetDeadline(wallDeadline(harnessIOTimeout))
	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, length))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("sendfile: %v", err)
	}
	if native != length {
		t.Fatalf("native path sent %d bytes, want %d", native, length)
	}
	if !bytes.Equal(body, content[start:start+length]) {
		t.Fatalf("sendfile body differs (%d bytes)", len(body))
	}
}
