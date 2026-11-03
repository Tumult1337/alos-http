//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	perfH1PlaintextBody        = "Hello, World!"
	perfH1UserID               = "12345"
	perfH1Body64K              = 64 << 10
	perfH1Body1M               = 1 << 20
	perfH1PostBodyLen          = 1 << 10
	perfH1PipelineDepth        = 16
	perfH1ParallelConnsPerProc = 8
	perfH1LockWarmup           = 20
	perfH1LockRuns             = 200
	perfH1IODeadline           = 60 * time.Second
	perfH1BrowserUA            = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	perfH1BrowserLang          = "en-US,en;q=0.9"
	perfH1BrowserSID           = "abc123def456"
)

var perfH1ChurnRecvTimeout = unix.Timeval{Sec: int64(perfH1IODeadline / time.Second)}

type perfH1Workload struct {
	name    string
	method  string
	request []byte
	body    []byte
}

func perfH1Get(path string, extraHeaders string) []byte {
	return []byte("GET " + path + " HTTP/1.1\r\nHost: alos.gg\r\n" + extraHeaders + "\r\n")
}

var (
	perfH1W1 = perfH1Workload{"W1", "GET", perfH1Get("/plaintext", ""), []byte(perfH1PlaintextBody)}
	perfH1W3 = perfH1Workload{"W3", "GET", perfH1Get("/user/"+perfH1UserID, ""), []byte(perfH1UserID)}
	perfH1W4 = perfH1Workload{"W4", "POST", []byte("POST /echo HTTP/1.1\r\nHost: alos.gg\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
		strconv.Itoa(perfH1PostBodyLen) + "\r\n\r\n" + strings.Repeat("a", perfH1PostBodyLen)), []byte(strconv.Itoa(perfH1PostBodyLen))}
	perfH1W5a = perfH1Workload{"W5a", "GET", perfH1Get("/bytes/64k", ""), bytes.Repeat([]byte{'x'}, perfH1Body64K)}
	perfH1W5b = perfH1Workload{"W5b", "GET", perfH1Get("/bytes/1m", ""), bytes.Repeat([]byte{'x'}, perfH1Body1M)}
	perfH1W8  = perfH1Workload{"W8", "GET", perfH1Get("/browser", "User-Agent: "+perfH1BrowserUA+"\r\n"+
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"+
		"Accept-Language: "+perfH1BrowserLang+"\r\n"+
		"Accept-Encoding: identity\r\n"+
		"Cache-Control: no-cache\r\n"+
		"Pragma: no-cache\r\n"+
		"Referer: https://example.com/\r\n"+
		"Sec-Fetch-Dest: document\r\n"+
		"Sec-Fetch-Mode: navigate\r\n"+
		"Sec-Fetch-Site: none\r\n"+
		"Sec-Fetch-User: ?1\r\n"+
		"Upgrade-Insecure-Requests: 1\r\n"+
		"sec-ch-ua: \"Chromium\";v=\"141\", \"Not?A_Brand\";v=\"8\"\r\n"+
		"sec-ch-ua-mobile: ?0\r\n"+
		"sec-ch-ua-platform: \"Windows\"\r\n"+
		"Cookie: sid="+perfH1BrowserSID+"; theme=dark; lang=en\r\n"),
		[]byte(perfH1BrowserUA + "|" + perfH1BrowserLang + "|" + perfH1BrowserSID)}
	perfH1W10 = perfH1Workload{"W10", "GET", perfH1Get("/plaintext", "Connection: close\r\n"), []byte(perfH1PlaintextBody)}

	perfH1PostLenText = strconv.Itoa(perfH1PostBodyLen)
	perfH1W4Server    = perfH1Workload{"W4-server", "POST", bytes.Replace(perfH1W4.request, []byte("/echo "), []byte("/echo-fixed "), 1), []byte(perfH1PostLenText)}
)

var perfH1KeepAliveWorkloads = []perfH1Workload{perfH1W1, perfH1W3, perfH1W4, perfH1W5a, perfH1W5b, perfH1W8}

func perfH1Routes(r *Router) {
	body64K := perfH1W5a.body
	body1M := perfH1W5b.body
	r.GET("/plaintext", func(req *Request, resp *Response) { resp.String(perfH1PlaintextBody) })
	r.GET("/user/:id", func(req *Request, resp *Response) { resp.String(req.ParamValue("id")) })
	r.POST("/echo", func(req *Request, resp *Response) { resp.String(strconv.Itoa(len(req.Body))) })
	r.POST("/echo-fixed", func(req *Request, resp *Response) {
		if len(req.Body) != perfH1PostBodyLen {
			resp.Status(http.StatusBadRequest).String("unexpected body length")
			return
		}
		resp.String(perfH1PostLenText)
	})
	r.GET("/bytes/64k", func(req *Request, resp *Response) { resp.Bytes(body64K) })
	r.GET("/bytes/1m", func(req *Request, resp *Response) { resp.Bytes(body1M) })
	r.GET("/browser", func(req *Request, resp *Response) {
		resp.String(req.Header("User-Agent") + "|" + req.Header("Accept-Language") + "|" + req.Cookie("sid"))
	})
}

func perfH1Server(tb testing.TB) *testServer {
	tb.Helper()
	return perfH1ServerWith(tb, nil)
}

func perfH1InlineServer(tb testing.TB) *testServer {
	tb.Helper()
	return perfH1ServerWith(tb, func(cfg *Config) { cfg.InlineHandlers = true })
}

func perfH1ServerWith(tb testing.TB, config func(*Config)) *testServer {
	tb.Helper()
	prevOut := log.Writer()
	log.SetOutput(io.Discard)
	tb.Cleanup(func() { log.SetOutput(prevOut) })
	return newTestServer(tb, testServerOptions{Routes: perfH1Routes, Config: config})
}

type perfH1RecordingReader struct {
	r    io.Reader
	seen []byte
}

func (r *perfH1RecordingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.seen = append(r.seen, p[:n]...)
	return n, err
}

func perfH1ReadValidated(tb testing.TB, r io.Reader, w perfH1Workload) []byte {
	tb.Helper()
	rec := &perfH1RecordingReader{r: r}
	resp, err := http.ReadResponse(bufio.NewReader(rec), &http.Request{Method: w.method})
	if err != nil {
		tb.Fatalf("%s: read response: %v", w.name, err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		tb.Fatalf("%s: read body: %v", w.name, err)
	}
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, w.body) {
		tb.Fatalf("%s: status=%d body len=%d want %d", w.name, resp.StatusCode, len(body), len(w.body))
	}
	return rec.seen
}

type perfH1Client struct {
	name     string
	conn     net.Conn
	request  []byte
	expected []byte
	got      []byte
	rounds   int
}

func dialPerfH1Client(tb testing.TB, addr string, w perfH1Workload, depth int) *perfH1Client {
	tb.Helper()
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		tb.Fatalf("dial %s: %v", addr, err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(wallDeadline(perfH1IODeadline))
	if _, err := conn.Write(w.request); err != nil {
		tb.Fatalf("%s: write probe: %v", w.name, err)
	}
	single := perfH1ReadValidated(tb, conn, w)
	expected := bytes.Repeat(single, depth)
	return &perfH1Client{
		name:     w.name,
		conn:     conn,
		request:  bytes.Repeat(w.request, depth),
		expected: expected,
		got:      make([]byte, len(expected)),
	}
}

func (c *perfH1Client) roundTrip() error {
	c.rounds++
	if _, err := c.conn.Write(c.request); err != nil {
		return err
	}
	_, err := io.ReadFull(c.conn, c.got)
	return err
}

func perfH1MaskDates(b []byte) []byte {
	prefix := []byte("\r\nDate: ")
	for off := 0; ; {
		i := bytes.Index(b[off:], prefix)
		if i < 0 {
			return b
		}
		start := off + i + len(prefix)
		end := min(start+len(http.TimeFormat), len(b))
		for j := start; j < end; j++ {
			b[j] = '#'
		}
		off = end
	}
}

func (c *perfH1Client) verify(tb testing.TB) {
	tb.Helper()
	if !bytes.Equal(perfH1MaskDates(c.got), perfH1MaskDates(c.expected)) {
		tb.Fatalf("%s: response bytes changed between requests (%d bytes, want %d)", c.name, len(c.got), len(c.expected))
	}
}

func benchPerfH1RoundTrip(b *testing.B, w perfH1Workload, depth int) {
	benchPerfH1RoundTripOn(b, perfH1Server(b), w, depth)
}

func benchPerfH1RoundTripOn(b *testing.B, ts *testServer, w perfH1Workload, depth int) {
	c := dialPerfH1Client(b, ts.addr, w, depth)
	b.SetBytes(int64(len(c.expected)))
	b.ReportAllocs()
	for b.Loop() {
		if err := c.roundTrip(); err != nil {
			b.Fatalf("%s: %v", w.name, err)
		}
	}
	c.verify(b)
}

func BenchmarkPerfH1Plaintext(b *testing.B) { benchPerfH1RoundTrip(b, perfH1W1, 1) }

func BenchmarkPerfH1UserParam(b *testing.B) { benchPerfH1RoundTrip(b, perfH1W3, 1) }

func BenchmarkPerfH1Post1K(b *testing.B) { benchPerfH1RoundTrip(b, perfH1W4, 1) }

func BenchmarkPerfH1Post1KFixedReply(b *testing.B) { benchPerfH1RoundTrip(b, perfH1W4Server, 1) }

func BenchmarkPerfH1Bytes64K(b *testing.B) { benchPerfH1RoundTrip(b, perfH1W5a, 1) }

func BenchmarkPerfH1Bytes1M(b *testing.B) { benchPerfH1RoundTrip(b, perfH1W5b, 1) }

func BenchmarkPerfH1Browser(b *testing.B) { benchPerfH1RoundTrip(b, perfH1W8, 1) }

func BenchmarkPerfH1PlaintextInline(b *testing.B) {
	benchPerfH1RoundTripOn(b, perfH1InlineServer(b), perfH1W1, 1)
}

func BenchmarkPerfH1Bytes64KInline(b *testing.B) {
	benchPerfH1RoundTripOn(b, perfH1InlineServer(b), perfH1W5a, 1)
}

func BenchmarkPerfH1Bytes1MInline(b *testing.B) {
	benchPerfH1RoundTripOn(b, perfH1InlineServer(b), perfH1W5b, 1)
}

func BenchmarkPerfH1PipelinedPlaintext16(b *testing.B) {
	benchPerfH1RoundTrip(b, perfH1W1, perfH1PipelineDepth)
}

func benchPerfH1Parallel(b *testing.B, w perfH1Workload) {
	ts := perfH1Server(b)
	b.SetParallelism(perfH1ParallelConnsPerProc)
	clients := make([]*perfH1Client, perfH1ParallelConnsPerProc*runtime.GOMAXPROCS(0))
	for i := range clients {
		clients[i] = dialPerfH1Client(b, ts.addr, w, 1)
	}
	var next atomic.Int32
	b.SetBytes(int64(len(clients[0].expected)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		c := clients[next.Add(1)-1]
		for pb.Next() {
			if err := c.roundTrip(); err != nil {
				b.Errorf("%s: %v", w.name, err)
				return
			}
		}
	})
	b.StopTimer()
	for _, c := range clients {
		if c.rounds > 0 {
			c.verify(b)
		}
	}
}

func BenchmarkPerfH1Bytes64KParallel(b *testing.B) { benchPerfH1Parallel(b, perfH1W5a) }

func BenchmarkPerfH1Bytes1MParallel(b *testing.B) { benchPerfH1Parallel(b, perfH1W5b) }

func BenchmarkPerfH1PlaintextParallel(b *testing.B) { benchPerfH1Parallel(b, perfH1W1) }

func perfH1Sockaddr(tb testing.TB, addr string) *unix.SockaddrInet4 {
	tb.Helper()
	tcpAddr, err := net.ResolveTCPAddr("tcp4", addr)
	if err != nil {
		tb.Fatalf("resolve %s: %v", addr, err)
	}
	sa := &unix.SockaddrInet4{Port: tcpAddr.Port}
	copy(sa.Addr[:], tcpAddr.IP.To4())
	return sa
}

type perfH1ChurnClient struct {
	sa      *unix.SockaddrInet4
	request []byte
	got     []byte
	n       int
}

func (c *perfH1ChurnClient) once() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &perfH1ChurnRecvTimeout); err != nil {
		return err
	}
	if err := unix.Connect(fd, c.sa); err != nil {
		return err
	}
	for sent := 0; sent < len(c.request); {
		n, err := unix.Write(fd, c.request[sent:])
		if err != nil {
			return err
		}
		sent += n
	}
	c.n = 0
	for c.n < len(c.got) {
		n, err := unix.Read(fd, c.got[c.n:])
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		c.n += n
	}
	return nil
}

func newPerfH1ChurnClient(tb testing.TB, addr string, w perfH1Workload) (*perfH1ChurnClient, []byte) {
	tb.Helper()
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		tb.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(perfH1IODeadline))
	if _, err := conn.Write(w.request); err != nil {
		tb.Fatalf("%s: write probe: %v", w.name, err)
	}
	expected := perfH1ReadValidated(tb, conn, w)
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		tb.Fatalf("%s: server kept the connection open after Connection: close (n=%d err=%v)", w.name, n, err)
	}
	return &perfH1ChurnClient{sa: perfH1Sockaddr(tb, addr), request: w.request, got: make([]byte, len(expected)+1)}, expected
}

func (c *perfH1ChurnClient) verify(tb testing.TB, expected []byte) {
	tb.Helper()
	if !bytes.Equal(perfH1MaskDates(c.got[:c.n]), perfH1MaskDates(expected)) {
		tb.Fatalf("churn response mismatch: got %d bytes %q, want %d bytes", c.n, c.got[:min(c.n, 80)], len(expected))
	}
}

func BenchmarkPerfH1ChurnClose(b *testing.B) {
	ts := perfH1Server(b)
	c, expected := newPerfH1ChurnClient(b, ts.addr, perfH1W10)
	b.ReportAllocs()
	for b.Loop() {
		if err := c.once(); err != nil {
			b.Fatalf("churn: %v", err)
		}
	}
	c.verify(b, expected)
}

func TestPerfH1ChurnCloseServesAndCloses(t *testing.T) {
	ts := perfH1Server(t)
	c, expected := newPerfH1ChurnClient(t, ts.addr, perfH1W10)
	for range perfH1LockWarmup {
		if err := c.once(); err != nil {
			t.Fatalf("churn: %v", err)
		}
		c.verify(t, expected)
	}
}

var perfH1ZeroAllocWorkloads = []perfH1Workload{perfH1W1, perfH1W3, perfH1W4Server, perfH1W5a}

func TestPerfH1KeepAlivePathsDoNotAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	ts := perfH1Server(t)
	for _, w := range perfH1ZeroAllocWorkloads {
		t.Run(w.name, func(t *testing.T) {
			perfH1AssertNoAllocs(t, dialPerfH1Client(t, ts.addr, w, 1))
		})
	}
	t.Run("W1-pipelined16", func(t *testing.T) {
		perfH1AssertNoAllocs(t, dialPerfH1Client(t, ts.addr, perfH1W1, perfH1PipelineDepth))
	})
	inline := perfH1InlineServer(t)
	for _, w := range perfH1ZeroAllocWorkloads {
		t.Run(w.name+"-inline", func(t *testing.T) {
			perfH1AssertNoAllocs(t, dialPerfH1Client(t, inline.addr, w, 1))
		})
	}
}

func perfH1AssertNoAllocs(t *testing.T, c *perfH1Client) {
	t.Helper()
	round := func() {
		if err := c.roundTrip(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	for range perfH1LockWarmup {
		round()
	}
	allocs := testing.AllocsPerRun(perfH1LockRuns, round)
	c.verify(t)
	if allocs > 0 {
		t.Fatalf("%s: %.2f allocs per round trip, want 0", c.name, allocs)
	}
}

func TestPerfH1KeepAliveResponsesStable(t *testing.T) {
	ts := perfH1Server(t)
	for _, w := range perfH1KeepAliveWorkloads {
		t.Run(w.name, func(t *testing.T) {
			c := dialPerfH1Client(t, ts.addr, w, 1)
			for range perfH1LockWarmup {
				if err := c.roundTrip(); err != nil {
					t.Fatalf("%s: %v", w.name, err)
				}
				c.verify(t)
			}
		})
	}
}
