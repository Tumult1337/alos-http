//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	h1SmallBody          = "ok"
	h1PipelinedBigBytes  = 2 << 20
	h1PipelinedStreamLen = 100_000
	h1SlowReadChunk      = 64 << 10
	h1SlowReadPause      = 15 * time.Millisecond
	h1SlowBodyBytes      = 4 << 20
	h1ShortTimeout       = 300 * time.Millisecond
	h1StreamGap          = 600 * time.Millisecond
	h1ClientHoldOff      = 150 * time.Millisecond
	h1GapPrefixBytes     = 8 << 20
	h1GapSuffixBytes     = 1 << 10
)

var h1PatternBodies sync.Map

func h1PatternBody(size int) []byte {
	if b, ok := h1PatternBodies.Load(size); ok {
		return b.([]byte)
	}
	b := make([]byte, size)
	fillStreamPattern(b, 0)
	actual, _ := h1PatternBodies.LoadOrStore(size, b)
	return actual.([]byte)
}

func h1SizeParam(req *Request) int {
	size, _ := strconv.Atoi(req.ParamValue("size"))
	return size
}

func h1FixedLengthHandler(writeFraction int) HandlerFunc {
	return func(req *Request, resp *Response) {
		size := h1SizeParam(req)
		sw := resp.EnsureStreamWriter()
		resp.SetStreamer(sw)
		hdrs := [][2]string{{"Content-Length", strconv.Itoa(size)}}
		if err := sw.WriteHeader(200, hdrs, "application/octet-stream"); err != nil {
			return
		}
		body := h1PatternBody(size)
		_ = sw.WriteChunk(body[:size/writeFraction])
	}
}

func h1GapHandler(req *Request, resp *Response) {
	sw := resp.EnsureStreamWriter()
	resp.SetStreamer(sw)
	if sw.WriteHeader(200, nil, "application/octet-stream") != nil {
		return
	}
	if sw.WriteChunk(h1PatternBody(h1GapPrefixBytes)) != nil {
		return
	}
	turbo.Sleep(h1StreamGap)
	if sw.WriteChunk(make([]byte, h1GapSuffixBytes)) != nil {
		return
	}
	_ = sw.Close()
}

func startH1OutServer(t *testing.T, tlsMode bool, probe *streamProbe, tune func(*Config)) string {
	t.Helper()
	addr := freeLoopbackAddr(t)
	cfg := Config{Addr: addr, LogRequests: false, MaxConnsPerIP: -1, Listeners: 1}
	if tlsMode {
		cfg.HTTPAddr = "-"
		cfg.Certs = []CertConfig{{Domain: "stream.test", Source: CertSelfSigned}}
	}
	if tune != nil {
		tune(&cfg)
	}
	srv := New(cfg)
	srv.Router.GET("/stream/:size", probe.handler(true))
	srv.Router.HEAD("/stream/:size", probe.handler(true))
	srv.Router.GET("/noclose/:size", probe.handler(false))
	srv.Router.GET("/fixed/:size", h1FixedLengthHandler(1))
	srv.Router.GET("/short/:size", h1FixedLengthHandler(2))
	srv.Router.GET("/gap", h1GapHandler)
	srv.Router.GET("/big/:size", func(req *Request, resp *Response) {
		resp.Status(200).Bytes(h1PatternBody(h1SizeParam(req)))
	})
	srv.Router.GET("/small", func(req *Request, resp *Response) { resp.Status(200).String(h1SmallBody) })
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

func h1Client(dials *atomic.Int32) *http.Client {
	dialer := &net.Dialer{}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true, ServerName: "stream.test", NextProtos: []string{"http/1.1"}},
		TLSNextProto:       map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxConnsPerHost:    1,
		DisableCompression: true,
	}
	return &http.Client{Transport: tr, Timeout: 120 * time.Second}
}

func h1BaseURL(tlsMode bool, addr string) string {
	if tlsMode {
		return "https://" + addr
	}
	return "http://" + addr
}

var h1Modes = []struct {
	name string
	tls  bool
}{{"plain", false}, {"tls", true}}

func h1Sizes(base ...int) []int {
	if testing.Short() {
		return base
	}
	return append(base, 1<<30)
}

func assertH1Body(t *testing.T, cl *http.Client, url string, size int) {
	t.Helper()
	status, sum, n, proto := fetchStreamSum(t, cl, url)
	if proto != "HTTP/1.1" || status != 200 || n != int64(size) || sum != streamPatternSum(size) {
		t.Fatalf("%s: proto=%s status=%d bytes=%d want %d, checksum match=%v", url, proto, status, n, size, sum == streamPatternSum(size))
	}
}

func assertH1SmallOnSameConn(t *testing.T, cl *http.Client, base string, dials *atomic.Int32) {
	t.Helper()
	resp, err := cl.Get(base + "/small")
	if err != nil {
		t.Fatalf("follow-up request: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != h1SmallBody {
		t.Fatalf("follow-up body=%q err=%v", body, err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dialed %d connections, want 1 (keep-alive was lost)", got)
	}
}

func TestH1BufferedLargeBodyIsDeliveredIntactAndKeepsAlive(t *testing.T) {
	for _, mode := range h1Modes {
		for _, inline := range []bool{false, true} {
			t.Run(mode.name+"/inline="+strconv.FormatBool(inline), func(t *testing.T) {
				addr := startH1OutServer(t, mode.tls, nil, func(c *Config) { c.InlineHandlers, c.DisableInlineHandlers = inline, !inline })
				var dials atomic.Int32
				cl := h1Client(&dials)
				base := h1BaseURL(mode.tls, addr)
				for _, size := range h1Sizes(h1ProgressiveBodyThreshold+1, 48<<20) {
					assertH1Body(t, cl, base+"/big/"+strconv.Itoa(size), size)
				}
				assertH1SmallOnSameConn(t, cl, base, &dials)
			})
		}
	}
}

func TestH1StreamedResponseIntegrityAndKeepAlive(t *testing.T) {
	for _, mode := range h1Modes {
		t.Run(mode.name, func(t *testing.T) {
			addr := startH1OutServer(t, mode.tls, nil, nil)
			var dials atomic.Int32
			cl := h1Client(&dials)
			base := h1BaseURL(mode.tls, addr)
			for _, route := range []string{"/stream/", "/fixed/", "/noclose/"} {
				for _, size := range h1Sizes(0, 1<<10, 64<<10, 10<<20) {
					assertH1Body(t, cl, base+route+strconv.Itoa(size), size)
				}
			}
			assertH1SmallOnSameConn(t, cl, base, &dials)
		})
	}
}

func TestH1StreamedHeadSendsNoBodyAndKeepsAlive(t *testing.T) {
	addr := startH1OutServer(t, false, nil, nil)
	var dials atomic.Int32
	cl := h1Client(&dials)
	resp, err := cl.Head("http://" + addr + "/stream/4096")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Streamed") != "1" {
		t.Fatalf("status=%d headers=%v", resp.StatusCode, resp.Header)
	}
	assertH1SmallOnSameConn(t, cl, "http://"+addr, &dials)
}

func rawH1Conn(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(streamTestTimeout))
	return conn, bufio.NewReader(conn)
}

func rawH1Get(path string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: stream.test\r\n\r\n"
}

func TestH1ShortContentLengthBodyClosesTheConnection(t *testing.T) {
	addr := startH1OutServer(t, false, nil, nil)
	conn, br := rawH1Conn(t, addr)
	const declared = 1000
	if _, err := io.WriteString(conn, rawH1Get("/short/"+strconv.Itoa(declared))+rawH1Get("/small")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if n != declared/2 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read %d bytes err=%v, want %d bytes then the server closing the connection", n, err, declared/2)
	}
}

func TestH1PipelinedResponsesStayInOrder(t *testing.T) {
	for _, mode := range h1Modes {
		t.Run(mode.name, func(t *testing.T) {
			addr := startH1OutServer(t, mode.tls, nil, nil)
			conn, _ := rawH1Conn(t, addr)
			if mode.tls {
				tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "stream.test", NextProtos: []string{"http/1.1"}})
				conn = tc
			}
			br := bufio.NewReader(conn)
			batch := rawH1Get("/big/"+strconv.Itoa(h1PipelinedBigBytes)) +
				rawH1Get("/stream/"+strconv.Itoa(h1PipelinedStreamLen)) +
				rawH1Get("/small")
			if _, err := io.WriteString(conn, batch); err != nil {
				t.Fatal(err)
			}
			for _, want := range []struct {
				size  int
				small bool
			}{{h1PipelinedBigBytes, false}, {h1PipelinedStreamLen, false}, {len(h1SmallBody), true}} {
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || len(body) != want.size {
					t.Fatalf("got %d bytes err=%v, want %d", len(body), err, want.size)
				}
				if want.small {
					if string(body) != h1SmallBody {
						t.Fatalf("third response body=%q", body)
					}
					continue
				}
				if sha256.Sum256(body) != streamPatternSum(want.size) {
					t.Fatalf("response of %d bytes arrived corrupted or out of order", want.size)
				}
			}
		})
	}
}

func TestH1ClientDisconnectUnblocksStreamingHandler(t *testing.T) {
	probe := &streamProbe{errs: make(chan error, 1)}
	addr := startH1OutServer(t, false, probe, nil)
	conn, br := rawH1Conn(t, addr)
	if _, err := io.WriteString(conn, rawH1Get("/stream/-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(io.Discard, br, streamChunk); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case err := <-probe.errs:
		if err == nil {
			t.Fatal("handler finished without an error after the client went away")
		}
	case <-time.After(streamTestTimeout):
		t.Fatal("streaming handler stayed blocked after the client disconnected")
	}
}

func TestH1SlowReaderMakingProgressOutlivesWriteTimeout(t *testing.T) {
	addr := startH1OutServer(t, false, nil, func(c *Config) { c.WriteTimeout = h1ShortTimeout })
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.(*net.TCPConn).SetReadBuffer(h1SlowReadChunk)
	if _, err := io.WriteString(conn, rawH1Get("/big/"+strconv.Itoa(h1SlowBodyBytes))); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReaderSize(conn, h1SlowReadChunk)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	start := turbo.Now()
	var got int64
	for {
		n, err := io.CopyN(io.Discard, resp.Body, h1SlowReadChunk)
		got += n
		if err != nil {
			break
		}
		turbo.Sleep(h1SlowReadPause)
	}
	if got != h1SlowBodyBytes {
		t.Fatalf("received %d of %d bytes over %v; the write timeout cut a transfer that was making progress", got, h1SlowBodyBytes, turbo.Since(start))
	}
	if turbo.Since(start) < h1ShortTimeout {
		t.Skipf("transfer finished in %v, faster than the write timeout, so the test proved nothing", turbo.Since(start))
	}
}

func TestH1StreamGapLongerThanIdleTimeoutKeepsTheResponseAlive(t *testing.T) {
	addr := startH1OutServer(t, false, nil, func(c *Config) { c.IdleTimeout = h1ShortTimeout })
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(streamTestTimeout))
	if _, err := io.WriteString(conn, rawH1Get("/gap")); err != nil {
		t.Fatal(err)
	}
	turbo.Sleep(h1ClientHoldOff)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || n != h1GapPrefixBytes+h1GapSuffixBytes {
		t.Fatalf("read %d bytes err=%v, want %d; the idle timeout fired during a live response", n, err, h1GapPrefixBytes+h1GapSuffixBytes)
	}
}
