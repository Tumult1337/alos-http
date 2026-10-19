//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	appFixTimeoutDeadline = 150 * time.Millisecond
	appFixFileBody        = "static file body served under Timeout"
)

func appFixTimeoutServer(t *testing.T, lateRelease <-chan struct{}, lateWriter chan<- bool, fileRoot string) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		Config: func(cfg *Config) { cfg.PlainHTTP = true },
		Routes: func(r *Router) {
			timeout := Timeout(appFixTimeoutDeadline)
			r.GET("/slow", timeout(func(req *Request, resp *Response) {
				<-req.Context().Done()
				<-lateRelease
				sw := resp.EnsureStreamWriter()
				if sw != nil {
					sw.WriteHeader(200, nil, "text/plain")
					resp.SetStreamer(sw)
					_ = sw.WriteChunk([]byte("INJECTED"))
					_ = sw.Close()
				}
				lateWriter <- sw != nil
			}))
			r.GET("/file/*filepath", timeout(Static("/file", StaticConfig{Root: fileRoot})))
			r.GET("/ping", func(req *Request, resp *Response) {
				resp.String("pong")
			})
		},
	})
}

func appFixWriteTempFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte(appFixFileBody), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func appFixGetOnConn(t *testing.T, w io.Writer, br *bufio.Reader, domain, path string) (*http.Response, string) {
	t.Helper()
	if _, err := io.WriteString(w, "GET "+path+" HTTP/1.1\r\nHost: "+domain+"\r\n\r\n"); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	resp, body := readH1Response(t, br, "GET")
	return resp, string(body)
}

func TestAppFixTimeoutLateStreamCannotReachTheConnection(t *testing.T) {
	release := make(chan struct{})
	lateWriter := make(chan bool, 1)
	ts := appFixTimeoutServer(t, release, lateWriter, appFixWriteTempFile(t))
	c := ts.dial(t)
	br := bufio.NewReader(c)
	if resp, _ := appFixGetOnConn(t, c, br, ts.domain, "/slow"); resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("slow status %d, want 504", resp.StatusCode)
	}
	close(release)
	if gotWriter := <-lateWriter; gotWriter {
		t.Fatal("the handler detached by Timeout still obtained a stream writer bound to the live connection")
	}
	resp, body := appFixGetOnConn(t, c, br, ts.domain, "/ping")
	if resp.StatusCode != http.StatusOK || body != "pong" {
		t.Fatalf("next request on the conn got %d %q, want 200 \"pong\"", resp.StatusCode, body)
	}
}

func TestAppFixTimeoutLateStreamCannotReachH2Stream(t *testing.T) {
	release := make(chan struct{})
	lateWriter := make(chan bool, 1)
	ts := appFixTimeoutServer(t, release, lateWriter, appFixWriteTempFile(t))
	cl := h2cClient()
	cl.Timeout = harnessIOTimeout
	defer cl.CloseIdleConnections()
	resp, err := cl.Get(ts.url("/slow"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("slow proto %d status %d, want h2 504", resp.ProtoMajor, resp.StatusCode)
	}
	close(release)
	if gotWriter := <-lateWriter; gotWriter {
		t.Fatal("the handler detached by Timeout still obtained an H2 stream writer")
	}
	resp, err = cl.Get(ts.url("/ping"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "pong" {
		t.Fatalf("next stream got %d %q, want 200 \"pong\"", resp.StatusCode, body)
	}
}

func TestAppFixTimeoutStreamingWithinDeadlineKeepsConnectionHealthy(t *testing.T) {
	ts := appFixTimeoutServer(t, nil, nil, appFixWriteTempFile(t))
	c := ts.dial(t)
	br := bufio.NewReader(c)
	for i := 0; i < 3; i++ {
		resp, body := appFixGetOnConn(t, c, br, ts.domain, "/file/f.txt")
		if resp.StatusCode != http.StatusOK || body != appFixFileBody {
			t.Fatalf("file request %d got %d %q", i, resp.StatusCode, body)
		}
		if resp.Close {
			t.Fatalf("file request %d closed the keep-alive connection", i)
		}
	}
	resp, body := appFixGetOnConn(t, c, br, ts.domain, "/ping")
	if resp.StatusCode != http.StatusOK || body != "pong" {
		t.Fatalf("ping after file got %d %q", resp.StatusCode, body)
	}
}
