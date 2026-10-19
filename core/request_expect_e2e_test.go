//go:build linux && amd64

package core

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	expectBodyPause    = 150 * time.Millisecond
	expectSmallMaxBody = 1024
	expectContinueLine = "HTTP/1.1 100 Continue\r\n"
)

func startExpectServer(t *testing.T, tlsMode bool, configure func(*Config)) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		TLS:    tlsMode,
		Config: configure,
		Routes: func(r *Router) {
			r.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("root") })
			r.GET("/echo", func(req *Request, resp *Response) { resp.Status(200).String("get") })
			r.POST("/echo", func(req *Request, resp *Response) { resp.Status(200).Bytes(req.Body) })
		},
	})
}

func expectPostHead(ts *testServer, proto string, contentLength int, expect string) string {
	head := "POST /echo " + proto + "\r\nHost: " + ts.domain + "\r\nContent-Length: " + strconv.Itoa(contentLength) + "\r\n"
	if expect != "" {
		head += "Expect: " + expect + "\r\n"
	}
	return head + "\r\n"
}

func writeAll(t *testing.T, c net.Conn, s string) {
	t.Helper()
	if _, err := io.WriteString(c, s); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readContinue(t *testing.T, br *bufio.Reader) {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("waiting for 100 Continue: %v", err)
	}
	if line != expectContinueLine {
		t.Fatalf("first line %q, want %q", line, expectContinueLine)
	}
	blank, err := br.ReadString('\n')
	if err != nil || blank != "\r\n" {
		t.Fatalf("100 Continue not terminated: %q %v", blank, err)
	}
}

func expectNothingFor(t *testing.T, c net.Conn, br *bufio.Reader, wait time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(wallDeadline(wait))
	if _, err := br.Peek(1); err == nil {
		t.Fatal("server sent bytes before the body arrived")
	} else {
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("peek: %v", err)
		}
	}
	_ = c.SetReadDeadline(wallDeadline(harnessIOTimeout))
}

func readFinal(t *testing.T, br *bufio.Reader, wantStatus int, wantBody string) *http.Response {
	t.Helper()
	resp, body := readH1Response(t, br, "POST")
	if resp.StatusCode != wantStatus {
		t.Fatalf("status %d, want %d (body %q)", resp.StatusCode, wantStatus, body)
	}
	if wantBody != "" && string(body) != wantBody {
		t.Fatalf("body %q, want %q", body, wantBody)
	}
	return resp
}

func expectClosed(t *testing.T, br *bufio.Reader) {
	t.Helper()
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("connection still open after a closing response (err %v)", err)
	}
}

func TestExpectContinueBeforeBody(t *testing.T) {
	for _, tlsMode := range []bool{false, true} {
		name := "plain"
		if tlsMode {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			ts := startExpectServer(t, tlsMode, nil)
			c := ts.dial(t)
			br := bufio.NewReader(c)
			writeAll(t, c, expectPostHead(ts, "HTTP/1.1", 5, "100-continue"))
			readContinue(t, br)
			writeAll(t, c, "hello")
			readFinal(t, br, 200, "hello")
		})
	}
}

func TestExpectContinueSentOncePerRequest(t *testing.T) {
	ts := startExpectServer(t, false, nil)
	c := ts.dial(t)
	br := bufio.NewReader(c)
	for i := 0; i < 2; i++ {
		writeAll(t, c, expectPostHead(ts, "HTTP/1.1", 10, "100-continue"))
		readContinue(t, br)
		writeAll(t, c, "hel")
		turbo.Sleep(expectBodyPause)
		writeAll(t, c, "lo")
		turbo.Sleep(expectBodyPause)
		writeAll(t, c, "world")
		readFinal(t, br, 200, "helloworld")
	}
}

func TestExpectContinueChunked(t *testing.T) {
	ts := startExpectServer(t, false, nil)
	c := ts.dial(t)
	br := bufio.NewReader(c)
	writeAll(t, c, "POST /echo HTTP/1.1\r\nHost: "+ts.domain+"\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n")
	readContinue(t, br)
	writeAll(t, c, "5\r\nhello\r\n0\r\n\r\n")
	readFinal(t, br, 200, "hello")
}

func TestExpectContinueTooLargeIs413WithoutBody(t *testing.T) {
	ts := startExpectServer(t, false, func(cfg *Config) { cfg.MaxBodySize = expectSmallMaxBody })
	c := ts.dial(t)
	br := bufio.NewReader(c)
	writeAll(t, c, expectPostHead(ts, "HTTP/1.1", 4*expectSmallMaxBody, "100-continue"))
	readFinal(t, br, 413, "")
	expectClosed(t, br)
}

func TestExpectUnknownIs417(t *testing.T) {
	for _, raw := range []string{
		"POST /echo HTTP/1.1\r\nHost: " + harnessDomain + "\r\nContent-Length: 0\r\nExpect: foo\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + harnessDomain + "\r\nExpect: foo\r\n\r\n",
		"GET /echo HTTP/1.1\r\nHost: " + harnessDomain + "\r\nExpect: 100-continue\r\nExpect: bar\r\n\r\n",
	} {
		ts := startExpectServer(t, false, nil)
		c := ts.dial(t)
		br := bufio.NewReader(c)
		writeAll(t, c, raw)
		readFinal(t, br, 417, "")
		expectClosed(t, br)
	}
}

func TestExpectIgnoredOnHTTP10(t *testing.T) {
	ts := startExpectServer(t, false, nil)
	c := ts.dial(t)
	br := bufio.NewReader(c)
	writeAll(t, c, expectPostHead(ts, "HTTP/1.0", 5, "100-continue"))
	expectNothingFor(t, c, br, expectBodyPause)
	writeAll(t, c, "hello")
	readFinal(t, br, 200, "hello")
}

func TestExpectContinueWithBodyAlreadySent(t *testing.T) {
	ts := startExpectServer(t, false, nil)
	c := ts.dial(t)
	br := bufio.NewReader(c)
	writeAll(t, c, expectPostHead(ts, "HTTP/1.1", 5, "100-continue")+"hello")
	readFinal(t, br, 200, "hello")
}

func TestExpectContinueWithoutBody(t *testing.T) {
	ts := startExpectServer(t, false, nil)
	resp, body := ts.rawH1(t, "GET /echo HTTP/1.1\r\nHost: "+ts.domain+"\r\nExpect: 100-continue\r\n\r\n")
	if resp.StatusCode != 200 || string(body) != "get" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
}
