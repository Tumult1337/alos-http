package h3interop

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/alos-http/core"
	"github.com/guno1928/turbo"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	h3Domain         = "h3.test"
	startupCeiling   = 3 * time.Second
	startupPoll      = 25 * time.Millisecond
	shutdownCeiling  = 2 * time.Second
	clientTimeout    = 6 * time.Second
	cancelCeiling    = 2 * time.Second
	slowHandlerDelay = 300 * time.Millisecond
)

type h3Server struct {
	addr        string
	srv         *core.Server
	cancelled   chan error
	slowEntered chan struct{}
}

func startH3(t *testing.T, cfg core.Config) *h3Server {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	cfg.Addr = addr
	cfg.HTTPAddr = "-"
	cfg.Certs = append(cfg.Certs, core.CertConfig{Domain: h3Domain, Source: core.CertSelfSigned})
	cfg.MaxConnsPerIP = -1
	if cfg.Listeners == 0 {
		cfg.Listeners = 1
	}
	s := core.New(cfg)
	hs := &h3Server{addr: addr, srv: s, cancelled: make(chan error, 1), slowEntered: make(chan struct{}, 1)}
	s.Router.GET("/slow", func(req *core.Request, resp *core.Response) {
		hs.slowEntered <- struct{}{}
		turbo.Sleep(slowHandlerDelay)
		resp.Status(200).String("slow done")
	})
	s.Router.GET("/ping", func(req *core.Request, resp *core.Response) { resp.Status(200).String("pong") })
	s.Router.GET("/whoami", func(req *core.Request, resp *core.Response) {
		if certs := req.TLSPeerCertificates(); len(certs) > 0 {
			resp.Status(200).String(certs[0].Subject.CommonName)
			return
		}
		resp.Status(200).String("none")
	})
	s.Router.POST("/echo", func(req *core.Request, resp *core.Response) { resp.Status(200).Bytes(req.Body) })
	s.Router.GET("/panic", func(req *core.Request, resp *core.Response) { panic("h3 boom") })
	s.Router.GET("/big/:n", func(req *core.Request, resp *core.Response) {
		n, _ := strconv.Atoi(req.ParamValue("n"))
		resp.Status(200).Bytes(bytes.Repeat([]byte("y"), n))
	})
	s.Router.GET("/wait", func(req *core.Request, resp *core.Response) {
		select {
		case <-req.Context().Done():
			hs.cancelled <- req.CancelCause()
		case <-turbo.After(cancelCeiling):
			hs.cancelled <- errors.New("handler context was never cancelled")
		}
		resp.Status(200).String("late")
	})
	go func() { _ = s.ListenAndServeQUIC() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownCeiling)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	waitForH3(t, addr)
	return hs
}

func clientTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, ServerName: h3Domain, NextProtos: []string{http3.NextProtoH3}}
}

func waitForH3(t *testing.T, addr string) {
	t.Helper()
	deadline := turbo.Deadline(startupCeiling)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		conn, err := quic.DialAddr(ctx, addr, clientTLS(), &quic.Config{HandshakeIdleTimeout: 150 * time.Millisecond})
		cancel()
		if err == nil {
			_ = conn.CloseWithError(0, "")
			return
		}
		if turbo.Until(deadline) <= 0 {
			t.Fatalf("HTTP/3 server on %s never accepted a handshake: %v", addr, err)
		}
		turbo.Sleep(startupPoll)
	}
}

func newClient(t *testing.T) *http.Client {
	tr := &http3.Transport{
		TLSClientConfig: clientTLS(),
		QUICConfig:      &quic.Config{MaxIdleTimeout: 10 * time.Second, HandshakeIdleTimeout: 3 * time.Second},
	}
	t.Cleanup(func() { tr.Close() })
	return &http.Client{Transport: tr, Timeout: clientTimeout}
}

func doPost(c *http.Client, addr string, size int) (time.Duration, error) {
	body := bytes.Repeat([]byte("x"), size)
	start := turbo.Now()
	resp, err := c.Post("https://"+addr+"/echo", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		return turbo.Since(start), err
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		return turbo.Since(start), err
	}
	if resp.StatusCode != 200 {
		return turbo.Since(start), fmt.Errorf("status %d: %s", resp.StatusCode, got)
	}
	if !bytes.Equal(got, body) {
		return turbo.Since(start), fmt.Errorf("echo mismatch: got %d bytes, want %d", len(got), len(body))
	}
	return turbo.Since(start), nil
}

func doGet(c *http.Client, addr, path string) (int, []byte, error) {
	resp, err := c.Get("https://" + addr + path)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

func doGetBig(c *http.Client, addr string, size int) error {
	status, got, err := doGet(c, addr, fmt.Sprintf("/big/%d", size))
	if err != nil {
		return err
	}
	if status != 200 || len(got) != size {
		return fmt.Errorf("status %d, got %d bytes, want %d", status, len(got), size)
	}
	return nil
}

func TestH3GetAndSmallPost(t *testing.T) {
	hs := startH3(t, core.Config{})
	c := newClient(t)
	status, body, err := doGet(c, hs.addr, "/ping")
	if err != nil || status != 200 || string(body) != "pong" {
		t.Fatalf("GET over h3: %d %q %v", status, body, err)
	}
	if _, err := doPost(c, hs.addr, 1024); err != nil {
		t.Fatalf("small POST: %v", err)
	}
}

func TestH3PostAboveInitialStreamWindow(t *testing.T) {
	hs := startH3(t, core.Config{})
	c := newClient(t)
	for _, size := range []int{200 << 10, 300 << 10, 1 << 20, 3 << 20} {
		elapsed, err := doPost(c, hs.addr, size)
		if err != nil {
			t.Fatalf("POST %d bytes failed after %v: %v", size, elapsed, err)
		}
	}
}

func TestH3PostAboveMaxBodySizeIsRejected(t *testing.T) {
	hs := startH3(t, core.Config{MaxBodySize: 64 << 10})
	c := newClient(t)
	body := bytes.Repeat([]byte("x"), 512<<10)
	start := turbo.Now()
	resp, err := c.Post("https://"+hs.addr+"/echo", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		if turbo.Since(start) > 3*time.Second {
			t.Fatalf("oversized body was not rejected promptly: %v", err)
		}
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 413 {
		t.Fatalf("oversized POST status %d, want 413", resp.StatusCode)
	}
}

func TestH3PostAboveConnectionWindow(t *testing.T) {
	hs := startH3(t, core.Config{MaxBodySize: 32 << 20})
	c := newClient(t)
	for _, size := range []int{12 << 20, 24 << 20} {
		if elapsed, err := doPost(c, hs.addr, size); err != nil {
			t.Fatalf("POST %d bytes failed after %v: %v", size, elapsed, err)
		}
	}
}

func TestH3ConcurrentLargePosts(t *testing.T) {
	hs := startH3(t, core.Config{MaxBodySize: 8 << 20})
	c := newClient(t)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			_, err := doPost(c, hs.addr, (1+i)<<19)
			errs <- err
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent POST: %v", err)
		}
	}
}

func TestH3ConcurrentLargeGets(t *testing.T) {
	hs := startH3(t, core.Config{})
	c := newClient(t)
	for round := 0; round < 3; round++ {
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			go func(i int) { errs <- doGetBig(c, hs.addr, (1+i)<<19) }(i)
		}
		for i := 0; i < 8; i++ {
			if err := <-errs; err != nil {
				t.Fatalf("round %d concurrent GET: %v", round, err)
			}
		}
	}
}

func TestH3SequentialLargeGets(t *testing.T) {
	hs := startH3(t, core.Config{})
	c := newClient(t)
	for i := 0; i < 8; i++ {
		if err := doGetBig(c, hs.addr, (1+i)<<19); err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
	}
}

type h3PanicReport struct {
	path     string
	value    any
	hasFrame bool
}

func TestH3HandlerPanicYields500(t *testing.T) {
	reports := make(chan h3PanicReport, 4)
	hs := startH3(t, core.Config{Logger: slog.New(slog.DiscardHandler), OnPanic: func(req *core.Request, recovered any, stack []byte) {
		r := h3PanicReport{value: recovered, hasFrame: bytes.Contains(stack, []byte("startH3.func"))}
		if req != nil {
			r.path = req.Path
		}
		reports <- r
	}})
	c := newClient(t)
	status, _, err := doGet(c, hs.addr, "/panic")
	if err != nil {
		t.Fatalf("panicking handler left the stream hanging: %v", err)
	}
	if status != 500 {
		t.Fatalf("status %d, want 500", status)
	}
	select {
	case r := <-reports:
		if r.path != "/panic" || r.value != "h3 boom" || !r.hasFrame {
			t.Fatalf("panic report %+v", r)
		}
	case <-turbo.After(2 * time.Second):
		t.Fatal("OnPanic was not called")
	}
	if len(reports) != 0 {
		t.Fatalf("%d extra panic reports", len(reports))
	}
}

func TestH3MalformedQPACKGetsResponse(t *testing.T) {
	hs := startH3(t, core.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, hs.addr, clientTLS(), &quic.Config{MaxIdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	garbage := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	frame := append([]byte{0x01, byte(len(garbage))}, garbage...)
	if _, err := st.Write(frame); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st.SetReadDeadline(time.Unix(0, turbo.UnixNano()+int64(3*time.Second)))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(st, hdr); err != nil {
		t.Fatalf("no response to a malformed HEADERS block: %v", err)
	}
	if hdr[0] != 0x01 {
		t.Fatalf("first response frame type %#x, want HEADERS", hdr[0])
	}
}

func TestH3TenThousandSequentialRequestsOnOneConnection(t *testing.T) {
	hs := startH3(t, core.Config{})
	c := newClient(t)
	for i := 0; i < 10000; i++ {
		status, body, err := doGet(c, hs.addr, "/ping")
		if err != nil || status != 200 || string(body) != "pong" {
			t.Fatalf("request %d: %d %q %v", i, status, body, err)
		}
	}
}

func TestH3ConcurrencyBeyondStreamWindow(t *testing.T) {
	hs := startH3(t, core.Config{})
	c := newClient(t)
	const total = 300
	var wg sync.WaitGroup
	errs := make(chan error, total)
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, body, err := doGet(c, hs.addr, "/ping")
			if err == nil && (status != 200 || string(body) != "pong") {
				err = fmt.Errorf("status %d body %q", status, body)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent request beyond the stream window: %v", err)
		}
	}
}

func TestH3ClientCancelCancelsHandlerContext(t *testing.T) {
	hs := startH3(t, core.Config{})
	c := newClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hs.addr+"/wait", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		resp, err := c.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		done <- err
	}()
	turbo.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case cause := <-hs.cancelled:
		if !errors.Is(cause, core.ErrClientGone) {
			t.Fatalf("handler cancel cause %v, want ErrClientGone", cause)
		}
	case <-turbo.After(cancelCeiling + time.Second):
		t.Fatal("handler never observed the client cancelling")
	}
	<-done
	status, body, err := doGet(c, hs.addr, "/ping")
	if err != nil || status != 200 || string(body) != "pong" {
		t.Fatalf("connection unusable after a cancelled request: %d %q %v", status, body, err)
	}
}

func TestH3StatsCounters(t *testing.T) {
	hs := startH3(t, core.Config{})
	before := core.Stats.Snapshot()
	const conns, reqsPerConn = 2, 3
	for range conns {
		c := newClient(t)
		for range reqsPerConn {
			if status, _, err := doGet(c, hs.addr, "/ping"); err != nil || status != 200 {
				t.Fatalf("status %d err %v", status, err)
			}
		}
	}
	after := core.Stats.Snapshot()
	if after.H3Conns < before.H3Conns+conns {
		t.Errorf("H3Conns grew by %d, want at least %d", after.H3Conns-before.H3Conns, conns)
	}
	if after.TotalConns < before.TotalConns+conns {
		t.Errorf("TotalConns grew by %d, want at least %d", after.TotalConns-before.TotalConns, conns)
	}
	if after.TotalReqs < before.TotalReqs+conns*reqsPerConn {
		t.Errorf("TotalReqs grew by %d, want at least %d", after.TotalReqs-before.TotalReqs, conns*reqsPerConn)
	}
}

func TestH3StatsBytes(t *testing.T) {
	hs := startH3(t, core.Config{})
	c := newClient(t)
	const size = 4096
	inBefore, outBefore := core.Stats.BytesIn.Load(), core.Stats.BytesOut.Load()
	for i := 0; i < 10; i++ {
		if _, err := doPost(c, hs.addr, size); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		in, out := core.Stats.BytesIn.Load()-inBefore, core.Stats.BytesOut.Load()-outBefore
		if in >= 10*size && out >= 10*size {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("BytesIn grew by %d and BytesOut by %d, want at least %d each", in, out, 10*size)
		}
		time.Sleep(15 * time.Millisecond)
	}
}
