//go:build linux && amd64

package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	uploadStreamAbove   = 64 << 10
	uploadMaxBody       = 2 << 30
	uploadBackpressured = 64 << 20
	uploadModeStream    = "stream"
	uploadModeBuffered  = "buffered"
)

type patternReader struct {
	off  int
	size int
}

func (p *patternReader) Read(b []byte) (int, error) {
	if p.off >= p.size {
		return 0, io.EOF
	}
	n := min(len(b), p.size-p.off)
	fillStreamPattern(b[:n], p.off)
	p.off += n
	return n, nil
}

type uploadProbe struct {
	errs     chan error
	received chan int64
}

func uploadSumHandler(req *Request, resp *Response) {
	h := sha256.New()
	mode := uploadModeBuffered
	var n int64
	if body := req.BodyStream(); body != nil {
		mode = uploadModeStream
		var err error
		n, err = io.Copy(h, body)
		if errors.Is(err, ErrBodyTooLarge) {
			resp.Status(413).String("too large")
			return
		}
		if err != nil {
			resp.Status(400).String(err.Error())
			return
		}
	} else {
		h.Write(req.Body)
		n = int64(len(req.Body))
	}
	resp.Status(200).String(fmt.Sprintf("%s %d %s", mode, n, hex.EncodeToString(h.Sum(nil))))
}

func (p *uploadProbe) slowHandler(req *Request, resp *Response) {
	body := req.BodyStream()
	if body == nil {
		resp.Status(500).String("not streamed")
		return
	}
	p.received <- plateauOf(body.receivedBytes, uploadBackpressured)
	_, err := io.Copy(io.Discard, body)
	p.errs <- err
	resp.Status(200).String("drained")
}

func (p *uploadProbe) abortHandler(req *Request, resp *Response) {
	body := req.BodyStream()
	if body == nil {
		resp.Status(500).String("not streamed")
		return
	}
	_, err := io.Copy(io.Discard, body)
	p.errs <- err
}

func startUploadServer(t *testing.T, tlsMode bool, probe *uploadProbe) string {
	t.Helper()
	addr := freeLoopbackAddr(t)
	cfg := Config{Addr: addr, LogRequests: false, MaxConnsPerIP: -1, Listeners: 1, StreamBodyAbove: uploadStreamAbove, MaxBodySize: uploadMaxBody}
	if tlsMode {
		cfg.HTTPAddr = "-"
		cfg.Certs = []CertConfig{{Domain: "stream.test", Source: CertSelfSigned}}
	}
	srv := New(cfg)
	srv.Router.POST("/sum", uploadSumHandler)
	srv.Router.POST("/ignore", func(req *Request, resp *Response) { resp.Status(200).String("ignored") })
	if probe != nil {
		srv.Router.POST("/slow", probe.slowHandler)
		srv.Router.POST("/abort", probe.abortHandler)
	}
	go func() {
		if tlsMode {
			_ = srv.ListenAndServeTLS()
		} else {
			_ = srv.ListenAndServe()
		}
	}()
	t.Cleanup(func() { stopServer(srv) })
	waitForProxy(t, addr)
	return addr
}

func postPattern(t *testing.T, cl *http.Client, url string, size int, chunked bool) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, &patternReader{size: size})
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(size)
	if chunked {
		req.ContentLength = -1
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("POST %s (%d bytes, chunked=%v): %v", url, size, chunked, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body), resp.Proto
}

func wantUploadSum(mode string, size int) string {
	sum := streamPatternSum(size)
	return fmt.Sprintf("%s %d %s", mode, size, hex.EncodeToString(sum[:]))
}

type uploadClient struct {
	name  string
	tls   bool
	proto string
	dial  func(dials *atomic.Int32) *http.Client
}

var uploadClients = []uploadClient{
	{"h1-plain", false, "HTTP/1.1", h1Client},
	{"h1-tls", true, "HTTP/1.1", h1Client},
	{"h2c", false, "HTTP/2.0", func(*atomic.Int32) *http.Client { return h2cClient() }},
	{"h2-tls", true, "HTTP/2.0", func(*atomic.Int32) *http.Client { return h2TLSClient() }},
}

func TestStreamedUploadIntegrityAndKeepAlive(t *testing.T) {
	sizes := []int{uploadStreamAbove + 1, 1 << 20, 10 << 20}
	if !testing.Short() {
		sizes = append(sizes, 1<<30)
	}
	for _, uc := range uploadClients {
		t.Run(uc.name, func(t *testing.T) {
			addr := startUploadServer(t, uc.tls, nil)
			var dials atomic.Int32
			cl := uc.dial(&dials)
			url := h1BaseURL(uc.tls, addr) + "/sum"
			for _, chunked := range []bool{false, true} {
				for _, size := range sizes {
					status, got, proto := postPattern(t, cl, url, size, chunked)
					if want := wantUploadSum(uploadModeStream, size); status != 200 || got != want || proto != uc.proto {
						t.Fatalf("chunked=%v size=%d: proto=%s status=%d body=%q want %q", chunked, size, proto, status, got, want)
					}
				}
			}
			status, got, _ := postPattern(t, cl, url, uploadStreamAbove, false)
			if want := wantUploadSum(uploadModeBuffered, uploadStreamAbove); status != 200 || got != want {
				t.Fatalf("a body at the threshold should stay buffered: status=%d body=%q", status, got)
			}
			if d := dials.Load(); d > 1 {
				t.Fatalf("dialed %d connections across the uploads, want 1", d)
			}
		})
	}
}

func TestStreamedUploadBackpressureBoundsBufferedBytes(t *testing.T) {
	probe := &uploadProbe{errs: make(chan error, 1), received: make(chan int64, 1)}
	addr := startUploadServer(t, false, probe)
	var dials atomic.Int32
	cl := h1Client(&dials)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = postPattern(t, cl, "http://"+addr+"/slow", uploadBackpressured, false)
	}()
	received := <-probe.received
	if limit := int64(h1BodyStreamCap + 2*h1BodyReadAhead); received > limit {
		t.Fatalf("server accepted %d body bytes while the handler was not reading, want at most %d", received, limit)
	}
	if err := <-probe.errs; err != nil {
		t.Fatalf("draining the body after the pause failed: %v", err)
	}
	<-done
}

func TestStreamedUploadHonoursExpectContinue(t *testing.T) {
	addr := startUploadServer(t, false, nil)
	conn, br := rawH1Conn(t, addr)
	const size = 1 << 20
	head := "POST /sum HTTP/1.1\r\nHost: stream.test\r\nExpect: 100-continue\r\nContent-Length: " + strconv.Itoa(size) + "\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatal(err)
	}
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 100") {
		t.Fatalf("interim line=%q err=%v, want 100 Continue before the body is sent", line, err)
	}
	if blank, err := br.ReadString('\n'); err != nil || blank != "\r\n" {
		t.Fatalf("100 Continue not terminated: %q %v", blank, err)
	}
	if _, err := io.Copy(conn, &patternReader{size: size}); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := wantUploadSum(uploadModeStream, size); string(body) != want {
		t.Fatalf("body=%q want %q", body, want)
	}
}

func TestStreamedUploadClientAbortFailsTheRead(t *testing.T) {
	probe := &uploadProbe{errs: make(chan error, 1), received: make(chan int64, 1)}
	addr := startUploadServer(t, false, probe)
	conn, _ := rawH1Conn(t, addr)
	head := "POST /abort HTTP/1.1\r\nHost: stream.test\r\nContent-Length: " + strconv.Itoa(16<<20) + "\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(conn, &patternReader{size: 1 << 20}, 1<<20); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case err := <-probe.errs:
		if !errors.Is(err, ErrBodyStreamAborted) {
			t.Fatalf("Read returned %v after the client went away, want ErrBodyStreamAborted", err)
		}
	case <-time.After(streamTestTimeout):
		t.Fatal("handler stayed blocked in Read after the client disconnected")
	}
}

func chunkedPattern(size, chunk int) []byte {
	var b bytes.Buffer
	buf := make([]byte, chunk)
	for off := 0; off < size; off += chunk {
		n := min(chunk, size-off)
		fillStreamPattern(buf[:n], off)
		b.WriteString(strconv.FormatInt(int64(n), 16) + "\r\n")
		b.Write(buf[:n])
		b.WriteString("\r\n")
	}
	b.WriteString("0\r\n\r\n")
	return b.Bytes()
}

func TestStreamedUploadOverMaxBodySize(t *testing.T) {
	const maxBody = 1 << 20
	addr := freeLoopbackAddr(t)
	srv := New(Config{Addr: addr, LogRequests: false, MaxConnsPerIP: -1, Listeners: 1, StreamBodyAbove: uploadStreamAbove, MaxBodySize: maxBody})
	srv.Router.POST("/sum", uploadSumHandler)
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { stopServer(srv) })
	waitForProxy(t, addr)
	oversized := 2 * maxBody
	cases := map[string][]byte{
		"content-length": append([]byte("POST /sum HTTP/1.1\r\nHost: stream.test\r\nContent-Length: "+strconv.Itoa(oversized)+"\r\n\r\n"), make([]byte, oversized)...),
		"chunked":        append([]byte("POST /sum HTTP/1.1\r\nHost: stream.test\r\nTransfer-Encoding: chunked\r\n\r\n"), chunkedPattern(oversized, 64<<10)...),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			conn, br := rawH1Conn(t, addr)
			go func() { _, _ = conn.Write(raw) }()
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 413 {
				t.Fatalf("status=%d, want 413", resp.StatusCode)
			}
		})
	}
}

func TestStreamedUploadIgnoredByHandlerClosesTheConnection(t *testing.T) {
	addr := startUploadServer(t, false, nil)
	conn, br := rawH1Conn(t, addr)
	head := "POST /ignore HTTP/1.1\r\nHost: stream.test\r\nContent-Length: " + strconv.Itoa(8<<20) + "\r\n\r\n"
	if _, err := io.WriteString(conn, head+strings.Repeat("x", 1024)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ignored" || !resp.Close {
		t.Fatalf("body=%q close=%v, want the response then Connection: close", body, resp.Close)
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("connection stayed open after an unread body: %v", err)
	}
}

func TestStreamedUploadPipelinedAfterBodyIsServed(t *testing.T) {
	addr := startUploadServer(t, false, nil)
	conn, br := rawH1Conn(t, addr)
	const size = 512 << 10
	var batch bytes.Buffer
	batch.WriteString("POST /sum HTTP/1.1\r\nHost: stream.test\r\nContent-Length: " + strconv.Itoa(size) + "\r\n\r\n")
	_, _ = io.Copy(&batch, &patternReader{size: size})
	batch.WriteString("POST /sum HTTP/1.1\r\nHost: stream.test\r\nContent-Length: 3\r\n\r\nabc")
	if _, err := conn.Write(batch.Bytes()); err != nil {
		t.Fatal(err)
	}
	abc := sha256.Sum256([]byte("abc"))
	for _, want := range []string{wantUploadSum(uploadModeStream, size), uploadModeBuffered + " 3 " + hex.EncodeToString(abc[:])} {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != want {
			t.Fatalf("body=%q want %q", body, want)
		}
	}
}

func TestStreamedUploadH2BackpressureIsBoundedByTheStreamWindow(t *testing.T) {
	probe := &uploadProbe{errs: make(chan error, 1), received: make(chan int64, 1)}
	addr := startUploadServer(t, false, probe)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = postPattern(t, h2cClient(), "http://"+addr+"/slow", uploadBackpressured, false)
	}()
	received := <-probe.received
	if limit := int64(H2StreamWindowSize); received > limit {
		t.Fatalf("server accepted %d body bytes while the handler was not reading, want at most the %d byte stream window", received, limit)
	}
	if err := <-probe.errs; err != nil {
		t.Fatalf("draining the body after the pause failed: %v", err)
	}
	<-done
}

func TestStreamedUploadH2ClientCancelFailsTheRead(t *testing.T) {
	probe := &uploadProbe{errs: make(chan error, 1), received: make(chan int64, 1)}
	addr := startUploadServer(t, false, probe)
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/abort", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	go func() {
		_, _ = io.CopyN(pw, &patternReader{size: 1 << 20}, 1<<20)
		cancel()
		pw.CloseWithError(context.Canceled)
	}()
	if resp, err := h2cClient().Do(req); err == nil {
		resp.Body.Close()
	}
	select {
	case err := <-probe.errs:
		if !errors.Is(err, ErrBodyStreamAborted) {
			t.Fatalf("Read returned %v after the client reset the stream, want ErrBodyStreamAborted", err)
		}
	case <-time.After(streamTestTimeout):
		t.Fatal("handler stayed blocked in Read after the client reset the stream")
	}
}

func TestStreamedUploadCompleteBodyThenHalfCloseIsAnswered(t *testing.T) {
	const bodySize = 1 << 20
	addr := startUploadServer(t, false, nil)
	for i := 0; i < 8; i++ {
		conn, br := rawH1Conn(t, addr)
		head := "POST /sum HTTP/1.1\r\nHost: stream.test\r\nConnection: close\r\nContent-Length: " + strconv.Itoa(bodySize) + "\r\n\r\n"
		if _, err := io.WriteString(conn, head); err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		if _, err := io.CopyN(io.MultiWriter(conn, h), &patternReader{size: bodySize}, bodySize); err != nil {
			t.Fatal(err)
		}
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		resp, body := readH1Response(t, br, "POST")
		want := fmt.Sprintf("%s %d %s", uploadModeStream, bodySize, hex.EncodeToString(h.Sum(nil)))
		if resp.StatusCode != 200 || string(body) != want {
			t.Fatalf("attempt %d: got %d %q, want 200 %q", i, resp.StatusCode, body, want)
		}
	}
}
