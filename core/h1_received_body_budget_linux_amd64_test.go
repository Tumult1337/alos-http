package core

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

func h1ReceivedFixture(t *testing.T, cfg Config) (*epollWorker, *epollConn, int) {
	t.Helper()
	cfg.MaxConnsPerIP = -1
	cfg.DisableInlineHandlers = !cfg.InlineHandlers
	w := newWorkerForBackendTest(t)
	if limiter := w.server.perIPConnLimiter.Load(); limiter != nil {
		limiter.Stop()
	}
	w.server = New(cfg)
	w.be.panicReporter = w.server
	w.inlineAll = w.server.inlineDispatchEnabled()
	w.refreshLimits()
	w.maxPendingWrite = epollMaxPendingWriteDefault
	w.taskCh = make(chan func(*epollWorker), 32)
	w.handlers = newHandlerPool(1)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := w.pool.get()
	c.fd, c.worker, c.protocol = pair[0], w, plainConnProtoH1
	c.readBuf = make([]byte, epollReadBufCap)
	w.conns = make([]*epollConn, c.fd+1)
	w.conns[c.fd] = c
	t.Cleanup(func() {
		if c.fd >= 0 {
			w.closeConn(c)
		}
		w.handlers.close()
		_ = unix.Close(pair[1])
	})
	return w, c, pair[1]
}

func h1ReceivedInput(t *testing.T, c *epollConn, request string) {
	t.Helper()
	if c.tls {
		c.appBuf = append(c.appBuf[:0], request...)
		c.appBufOff = 0
	} else {
		if len(request) > cap(c.readBuf) {
			c.readBuf = make([]byte, len(request))
		}
		copy(c.readBuf, request)
		c.readN, c.h1Off = len(request), 0
	}
}

func h1ReceivedAssert(t *testing.T, c *epollConn, want int64) {
	t.Helper()
	if c.h1BodyAccounted != want || c.worker.server.inFlightBodyBytes.Load() != want {
		t.Fatalf("body charge local=%d global=%d, want received span %d", c.h1BodyAccounted, c.worker.server.inFlightBodyBytes.Load(), want)
	}
}

func h1ReceivedFinish(t *testing.T, w *epollWorker, c *epollConn) {
	t.Helper()
	start := time.Now()
	for w.h1Done.Load() == nil && time.Since(start) < h2FixCeiling {
		time.Sleep(time.Millisecond)
	}
	if w.h1Done.Load() == nil {
		t.Fatal("real handler did not post its completion")
	}
	w.drainTasks()
	if c.inFlight != 0 {
		t.Fatalf("completion left %d handlers", c.inFlight)
	}
}

func h1ReceivedRunInline(t *testing.T, w *epollWorker) {
	t.Helper()
	if !w.inlinePending() {
		t.Fatal("inline handler was not queued")
	}
	w.inlineDeadline = turbo.Now() + int64(h2FixCeiling)
	if !w.runInlineQueue() {
		t.Fatal("inline queue handed off the event loop")
	}
	w.drainTasks()
}

func h1ReceivedBlockedHandler(t *testing.T, w *epollWorker, c *epollConn) (<-chan string, func()) {
	t.Helper()
	entered, release := make(chan string, 1), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	w.server.Router.POST("/body", func(req *Request, resp *Response) {
		body := string(req.Body)
		entered <- body
		<-release
		if string(req.Body) != body {
			t.Error("handler body changed while it retained ownership")
		}
		resp.Status(200).String("accepted")
	})
	w.server.Router.Build()
	w.server.computeFastDispatch()
	t.Cleanup(func() {
		unblock()
		if c.inFlight > 0 && c.proxyEx == nil {
			h1ReceivedFinish(t, w, c)
		}
	})
	return entered, unblock
}

func h1ReceivedAwait(t *testing.T, entered <-chan string) string {
	t.Helper()
	select {
	case body := <-entered:
		return body
	case <-time.After(h2FixCeiling):
		t.Fatal("buffered handler did not enter")
	}
	return ""
}

func TestH1ReceivedBodyHeaderOnly(t *testing.T) {
	for _, mode := range []string{"content-length", "small-budget", "chunked", "chunk-size"} {
		t.Run(mode, func(t *testing.T) {
			budget := int64(epollReadBufCap * 8)
			if mode == "small-budget" {
				budget = 17
			}
			w, c, _ := h1ReceivedFixture(t, Config{MaxInFlightBodyBytes: budget})
			request := fmt.Sprintf("POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: %d\r\n\r\n", epollReadBufCap*4)
			want := int64(0)
			if strings.HasPrefix(mode, "chunk") {
				request = "POST /body HTTP/1.1\r\nHost: body.test\r\nTransfer-Encoding: chunked\r\n\r\n"
			}
			if mode == "chunk-size" {
				request += "100000\r\n"
				want = 8
			}
			if w.streamsH1Body(strings.HasPrefix(mode, "chunk"), !strings.HasPrefix(mode, "chunk"), epollReadBufCap*4) {
				t.Fatal("fixture bypasses buffering")
			}
			h1ReceivedInput(t, c, request)
			initialCap := cap(c.readBuf)
			out, step := c.serveH1(w.server, nil)
			if step != h1StepNeedInput || len(out) != 0 {
				t.Fatalf("head rejected: step=%d output=%q", step, out)
			}
			h1ReceivedAssert(t, c, want)
			if cap(c.readBuf) != initialCap {
				t.Fatalf("absent body grew buffer %d -> %d", initialCap, cap(c.readBuf))
			}
		})
	}
}

func TestH1ReceivedBodyIncremental(t *testing.T) {
	for _, tls := range []bool{false, true} {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprintf("tls=%v/chunked=%v", tls, chunked), func(t *testing.T) {
				w, c, _ := h1ReceivedFixture(t, Config{MaxInFlightBodyBytes: 31})
				c.tls, c.phase = tls, tlsConnPhaseApplication
				head := "POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: 100\r\n\r\n"
				if chunked {
					head = "POST /body HTTP/1.1\r\nHost: body.test\r\nTransfer-Encoding: chunked\r\n\r\n"
				}
				for _, part := range []string{"abc", "abcdef", "abcdef"} {
					h1ReceivedInput(t, c, head+part)
					if chunked {
						h1ReceivedInput(t, c, head+"64\r\n"+part)
					}
					out, step := c.serveH1(w.server, nil)
					if step != h1StepNeedInput || len(out) != 0 {
						t.Fatalf("partial input: step=%d output=%q", step, out)
					}
					want := len(part)
					if chunked {
						want += len("64\r\n")
					}
					h1ReceivedAssert(t, c, int64(want))
				}
				before := c.h1BodyAccounted
				h1ReceivedInput(t, c, head+strings.Repeat("x", 32))
				if chunked {
					h1ReceivedInput(t, c, head+"64\r\n"+strings.Repeat("x", 32))
				}
				out, step := c.serveH1(w.server, nil)
				if step != h1StepClose || !bytes.Contains(out, []byte("503")) {
					t.Fatalf("budget rejection: step=%d output=%q", step, out)
				}
				h1ReceivedAssert(t, c, before)
			})
		}
	}
}

func TestH1ReceivedBodyCloseRetainsHandlerCharge(t *testing.T) {
	w, c, _ := h1ReceivedFixture(t, Config{MaxInFlightBodyBytes: 31})
	entered, unblock := h1ReceivedBlockedHandler(t, w, c)
	h1ReceivedInput(t, c, "POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: 5\r\n\r\nhello")
	_, step := c.serveH1(w.server, nil)
	if step != h1StepDispatched || h1ReceivedAwait(t, entered) != "hello" || c.inFlight != 1 || !c.dispatching {
		t.Fatal("real buffered handler did not own body")
	}
	h1ReceivedAssert(t, c, 5)
	sibling := &epollConn{worker: w}
	if !sibling.reserveH1BodyBudget(w.server, 11) {
		t.Fatal("sibling reservation failed")
	}
	t.Cleanup(sibling.releaseH1BodyBudget)
	w.closeConn(c)
	w.closeConn(c)
	if c.fd >= 0 || c.inFlight != 1 || w.pool.slotsHeld() != 1 {
		t.Fatal("closed active handler was recycled")
	}
	if got := w.server.inFlightBodyBytes.Load(); got != 16 {
		t.Fatalf("closed handler lost body charge: got %d, want 16", got)
	}
	unblock()
	h1ReceivedFinish(t, w, c)
	if got := w.server.inFlightBodyBytes.Load(); got != 11 {
		t.Fatalf("completion affected sibling charge: got %d, want 11", got)
	}
	c.releaseH1BodyBudget()
	if got := w.server.inFlightBodyBytes.Load(); got != 11 {
		t.Fatalf("duplicate release affected sibling charge: %d", got)
	}
}

func TestH1ReceivedBodyTimeout(t *testing.T) {
	w, c, _ := h1ReceivedFixture(t, Config{ReadTimeout: h2FixShutdownGrace / 10, ReadHeaderTimeout: h2FixCeiling, IdleTimeout: h2FixShutdownGrace})
	head := "POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: 100\r\n\r\n"
	before := turbo.UnixNano()
	h1ReceivedInput(t, c, head)
	_, step := c.serveH1(w.server, nil)
	if step != h1StepNeedInput {
		t.Fatal("head did not enter body wait")
	}
	deadline := c.deadline
	if deadline < before+w.readTO || deadline > turbo.UnixNano()+w.readTO {
		t.Fatal("body wait did not select existing ReadTimeout")
	}
	clockStart := time.Now()
	for turbo.UnixNano() <= deadline-w.readTO && time.Since(clockStart) < h2FixCeiling {
		time.Sleep(time.Millisecond)
	}
	if turbo.UnixNano() <= deadline-w.readTO {
		t.Fatal("clock did not advance before the second body pass")
	}
	h1ReceivedInput(t, c, head+"abc")
	_, step = c.serveH1(w.server, nil)
	if step != h1StepNeedInput || c.deadline != deadline {
		t.Fatal("partial body extended the body deadline")
	}
	h1ReceivedAssert(t, c, 3)
	start := time.Now()
	for turbo.UnixNano() <= deadline && time.Since(start) < h2FixCeiling {
		time.Sleep(time.Millisecond)
	}
	if turbo.UnixNano() <= deadline {
		t.Fatal("sweeper clock did not cross saved deadline")
	}
	w.sweepDeadlines()
	if c.fd >= 0 || w.server.inFlightBodyBytes.Load() != 0 {
		t.Fatal("partial body timeout retained connection or budget")
	}
	w.closeConn(c)
	if got := w.server.inFlightBodyBytes.Load(); got != 0 {
		t.Fatalf("repeated close drifted budget: %d", got)
	}
}

func TestH1ReceivedBodyDeclaredCapacity(t *testing.T) {
	w, c, _ := h1ReceivedFixture(t, Config{})
	h1ReceivedInput(t, c, fmt.Sprintf("POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: %d\r\n\r\n", epollReadBufCap*4))
	initialCap := cap(c.readBuf)
	_, step := c.serveH1(w.server, nil)
	if step != h1StepNeedInput {
		t.Fatal("head did not reach body wait")
	}
	if cap(c.readBuf) != initialCap {
		t.Fatalf("declared absent body grew read capacity from %d to %d", initialCap, cap(c.readBuf))
	}
}

func TestH1ReceivedBodyPipelineSpan(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%v", chunked), func(t *testing.T) {
			w, c, _ := h1ReceivedFixture(t, Config{})
			entered, unblock := h1ReceivedBlockedHandler(t, w, c)
			body := "hello"
			head := "POST /body HTTP/1.1\r\nHost: body.test\r\nConnection: close\r\nContent-Length: 5\r\n\r\n"
			if chunked {
				head = "POST /body HTTP/1.1\r\nHost: body.test\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
				body = "5;ext=1\r\nhello\r\n0\r\nX-End: accepted\r\n\r\n"
			}
			next := "GET /next HTTP/1.1\r\nHost: body.test\r\nX-Next: " + strings.Repeat("n", 257) + "\r\n\r\n"
			h1ReceivedInput(t, c, head+body+next)
			_, step := c.serveH1(w.server, nil)
			if step != h1StepDispatched || h1ReceivedAwait(t, entered) != "hello" {
				t.Fatal("complete body did not reach real buffered handler")
			}
			h1ReceivedAssert(t, c, int64(len(body)))
			if string(c.h1Unread()) != next {
				t.Fatal("following request was consumed as body")
			}
			if chunked {
				trailers := c.req.Trailers()
				if len(trailers) != 1 || trailers[0][0] != "X-End" || trailers[0][1] != "accepted" {
					t.Fatalf("trailers changed: %v", trailers)
				}
			}
			unblock()
			h1ReceivedFinish(t, w, c)
			h1ReceivedAssert(t, c, 0)
		})
	}
}

func TestH1ReceivedBodyReservationTargets(t *testing.T) {
	w, c, _ := h1ReceivedFixture(t, Config{MaxInFlightBodyBytes: 17})
	want := int64(0)
	for _, target := range []int{0, 3, 3, 7, 2, 17} {
		want = max(want, int64(target))
		if !c.reserveH1BodyBudget(w.server, target) {
			t.Fatalf("valid target %d refused", target)
		}
		h1ReceivedAssert(t, c, want)
	}
	if c.reserveH1BodyBudget(w.server, 18) {
		t.Fatal("aggregate budget accepted excessive target")
	}
	h1ReceivedAssert(t, c, 17)
	c.releaseH1BodyBudget()
	c.releaseH1BodyBudget()
	h1ReceivedAssert(t, c, 0)
}

func TestH1ReceivedBodyDisabledBudget(t *testing.T) {
	w, c, _ := h1ReceivedFixture(t, Config{MaxInFlightBodyBytes: -1})
	if !c.reserveH1BodyBudget(w.server, epollReadBufCap*4) {
		t.Fatal("disabled global budget rejected input")
	}
	if c.h1BodyAccounted != epollReadBufCap*4 || w.server.inFlightBodyBytes.Load() != 0 {
		t.Fatal("disabled budget changed global counter or lost local ownership")
	}
	c.releaseH1BodyBudget()
	c.releaseH1BodyBudget()
	h1ReceivedAssert(t, c, 0)
}

func TestH1ReceivedBodyRejectedCleanup(t *testing.T) {
	tests := []struct {
		name, head, initial, rest, status string
		maxBody                           int64
	}{
		{name: "bad-chunk", head: "Transfer-Encoding: chunked", initial: "5\r\nhello\r\n", rest: "zz\r\n", status: "400"},
		{name: "bad-trailer", head: "Transfer-Encoding: chunked", initial: "5\r\nhello\r\n", rest: "0\r\nBad trailer\r\n\r\n", status: "400"},
		{name: "chunked-decoded-limit", head: "Transfer-Encoding: chunked", initial: "5\r\nhello\r\n", rest: "5\r\nworld\r\n0\r\n\r\n", status: "413", maxBody: 7},
		{name: "content-length-limit", head: "Content-Length: 8", initial: "", rest: "abcdefgh", status: "413", maxBody: 7},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w, c, _ := h1ReceivedFixture(t, Config{MaxBodySize: test.maxBody})
			head := "POST /body HTTP/1.1\r\nHost: body.test\r\n" + test.head + "\r\n\r\n"
			if test.initial != "" {
				h1ReceivedInput(t, c, head+test.initial)
				_, step := c.serveH1(w.server, nil)
				if step != h1StepNeedInput {
					t.Fatal("valid prefix was not retained")
				}
				h1ReceivedAssert(t, c, int64(len(test.initial)))
			}
			h1ReceivedInput(t, c, head+test.initial+test.rest)
			out, step := c.serveH1(w.server, nil)
			if step != h1StepClose || !bytes.Contains(out, []byte("HTTP/1.1 "+test.status)) {
				t.Fatalf("rejection step=%d output=%q", step, out)
			}
			w.closeConn(c)
			w.closeConn(c)
			h1ReceivedAssert(t, c, 0)
		})
	}
}

func TestH1ReceivedBodyInlineClose(t *testing.T) {
	w, c, _ := h1ReceivedFixture(t, Config{InlineHandlers: true})
	observed := false
	w.server.Router.POST("/body", func(req *Request, resp *Response) {
		if string(req.Body) != "hello" {
			t.Fatal("inline handler did not receive copied body")
		}
		h1ReceivedAssert(t, c, 5)
		w.closeConn(c)
		h1ReceivedAssert(t, c, 5)
		observed = true
		resp.Status(200)
	})
	w.server.Router.Build()
	w.server.computeFastDispatch()
	h1ReceivedInput(t, c, "POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: 5\r\n\r\nhello")
	w.serviceBuffered(c, false, false)
	h1ReceivedRunInline(t, w)
	if !observed || c.inFlight != 0 || w.pool.slotsHeld() != 0 {
		t.Fatal("inline close did not finish the real owner")
	}
	h1ReceivedAssert(t, c, 0)
}

func TestH1ReceivedBodyStreamingSelection(t *testing.T) {
	tests := []struct {
		name                             string
		threshold                        int64
		size                             int
		chunked, inline, proxy, streamed bool
	}{
		{name: "threshold", threshold: uploadStreamAbove, size: uploadStreamAbove},
		{name: "above-threshold", threshold: uploadStreamAbove, size: uploadStreamAbove + 1, streamed: true},
		{name: "chunked-stream", threshold: uploadStreamAbove, size: 5, chunked: true, streamed: true},
		{name: "zero-disables", size: uploadStreamAbove + 1},
		{name: "inline-exempts", threshold: uploadStreamAbove, size: uploadStreamAbove + 1, inline: true},
		{name: "proxy-exempts", threshold: uploadStreamAbove, size: uploadStreamAbove + 1, proxy: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w, c, _ := h1ReceivedFixture(t, Config{StreamBodyAbove: test.threshold, InlineHandlers: test.inline})
			if test.proxy {
				proxy := NewProxyEngine()
				w.server.proxy.Store(proxy)
				t.Cleanup(proxy.Stop)
			}
			type result struct {
				streamed bool
				size     int
				held     int64
				err      error
			}
			entered, release := make(chan result, 1), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			w.server.Router.POST("/body", func(req *Request, resp *Response) {
				body := req.Body
				var err error
				streamed := req.BodyStream() != nil
				if streamed {
					body, err = io.ReadAll(req.BodyStream())
				}
				entered <- result{streamed: streamed, size: len(body), held: w.server.inFlightBodyBytes.Load(), err: err}
				if !test.inline {
					<-release
				}
				resp.Status(200).String("accepted")
			})
			w.server.Router.Build()
			w.server.computeFastDispatch()
			t.Cleanup(func() {
				unblock()
				if c.inFlight > 0 {
					h1ReceivedFinish(t, w, c)
				}
			})
			body := strings.Repeat("b", test.size)
			head := fmt.Sprintf("POST /body HTTP/1.1\r\nHost: body.test\r\nConnection: close\r\nContent-Length: %d\r\n\r\n", len(body))
			if test.chunked {
				head = "POST /body HTTP/1.1\r\nHost: body.test\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
				body = fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)
			}
			if got := w.streamsH1Body(test.chunked, !test.chunked, test.size); got != test.streamed {
				t.Fatalf("selection=%v want %v", got, test.streamed)
			}
			h1ReceivedInput(t, c, head+body)
			_, step := c.serveH1(w.server, nil)
			if test.inline {
				if step != h1StepDispatched {
					t.Fatalf("inline queue step=%d", step)
				}
				h1ReceivedRunInline(t, w)
				if !bytes.Contains(c.writeBuf, []byte("200 OK")) {
					t.Fatalf("inline output=%q", c.writeBuf)
				}
			} else if step != h1StepDispatched {
				t.Fatalf("async dispatch step=%d", step)
			}
			var got result
			select {
			case got = <-entered:
			case <-time.After(h2FixCeiling):
				t.Fatal("selected handler did not consume complete body")
			}
			if got.err != nil || got.streamed != test.streamed || got.size != test.size {
				t.Fatalf("handler result=%+v expected stream=%v size=%d", got, test.streamed, test.size)
			}
			want := int64(len(body))
			if test.streamed {
				want = 0
			}
			if got.held != want {
				t.Fatalf("handler-held charge=%d want %d", got.held, want)
			}
			if !test.inline {
				unblock()
				h1ReceivedFinish(t, w, c)
			}
			h1ReceivedAssert(t, c, 0)
		})
	}
}

func TestH1ReceivedBodyProxyCloseReleases(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	w, c, _ := h1ReceivedFixture(t, Config{MaxInFlightBodyBytes: 31, StreamBodyAbove: uploadStreamAbove})
	w.server.AddProxyDomain(DomainConfig{Domain: "body.test", Backends: []BackendConfig{{Addr: backend.Addr().String()}}})
	t.Cleanup(w.server.proxy.Load().Stop)
	w.server.Router.Build()
	h1ReceivedInput(t, c, "POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: 5\r\n\r\nhello")
	_, step := c.serveH1(w.server, nil)
	if step != h1StepProxyInFlight || c.proxyEx == nil || !c.dispatching || c.inFlight != 1 {
		t.Fatalf("real proxy did not own request: step=%d exchange=%v inFlight=%d", step, c.proxyEx != nil, c.inFlight)
	}
	h1ReceivedAssert(t, c, 5)
	w.closeConn(c)
	if c.proxyEx != nil || c.inFlight != 0 || w.pool.slotsHeld() != 0 {
		t.Fatal("proxy abort retained exchange or connection")
	}
	h1ReceivedAssert(t, c, 0)
}

func TestH1ReceivedBodyReadLimit(t *testing.T) {
	w, c, _ := h1ReceivedFixture(t, Config{MaxReadSize: epollReadBufCap, MaxBodySize: limitDefaultMaxBodySize})
	h1ReceivedInput(t, c, fmt.Sprintf("POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: %d\r\n\r\n", epollReadBufCap))
	out, step := c.serveH1(w.server, nil)
	if step != h1StepClose || !bytes.Contains(out, []byte("413")) {
		t.Fatalf("header plus body bypassed read cap: step=%d output=%q", step, out)
	}
	h1ReceivedAssert(t, c, 0)
}

func TestH1ReceivedBodyLengthOverflow(t *testing.T) {
	w, c, _ := h1ReceivedFixture(t, Config{MaxBodySize: -1, MaxReadSize: -1})
	h1ReceivedInput(t, c, fmt.Sprintf("POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: %d\r\n\r\n", int(^uint(0)>>1)))
	out, step := c.serveH1(w.server, nil)
	if step != h1StepClose || !bytes.Contains(out, []byte("400")) {
		t.Fatalf("overflow not rejected: step=%d output=%q", step, out)
	}
	h1ReceivedAssert(t, c, 0)
}

func TestH1ReceivedBodyIncompleteChunkLimit(t *testing.T) {
	w, c, _ := h1ReceivedFixture(t, Config{MaxBodySize: 7})
	h1ReceivedInput(t, c, "POST /body HTTP/1.1\r\nHost: body.test\r\nTransfer-Encoding: chunked\r\n\r\n100000\r\n"+strings.Repeat("x", chunkedFramingSlack+8))
	out, step := c.serveH1(w.server, nil)
	if step != h1StepClose || !bytes.Contains(out, []byte("413")) {
		t.Fatalf("incomplete body bypassed framing allowance: step=%d output=%q", step, out)
	}
	w.closeConn(c)
	h1ReceivedAssert(t, c, 0)
}

func TestH1ReceivedBodyHeadLeavesVictimCapacity(t *testing.T) {
	w, holder, peer := h1ReceivedFixture(t, Config{MaxInFlightBodyBytes: 17, InlineHandlers: true})
	w.server.Router.POST("/body", func(req *Request, resp *Response) { resp.Status(200).Bytes(req.Body) })
	w.server.Router.Build()
	w.server.computeFastDispatch()
	head := fmt.Sprintf("POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: %d\r\n\r\n", epollReadBufCap*4)
	if n, err := unix.Write(peer, []byte(head)); err != nil || n != len(head) {
		t.Fatalf("head write=%d: %v", n, err)
	}
	w.readable(holder, false)
	if holder.fd < 0 || holder.lingering {
		t.Fatal("valid header-only upload was rejected")
	}
	h1ReceivedAssert(t, holder, 0)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	victim := w.pool.get()
	victim.fd, victim.worker, victim.protocol = pair[0], w, plainConnProtoH1
	victim.readBuf = make([]byte, epollReadBufCap)
	if victim.fd >= len(w.conns) {
		w.conns = append(w.conns, make([]*epollConn, victim.fd-len(w.conns)+1)...)
	}
	w.conns[victim.fd] = victim
	t.Cleanup(func() {
		if victim.fd >= 0 {
			w.closeConn(victim)
		}
		_ = unix.Close(pair[1])
	})
	request := "POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: 5\r\n\r\nhello"
	if n, err := unix.Write(pair[1], []byte(request)); err != nil || n != len(request) {
		t.Fatalf("victim write=%d: %v", n, err)
	}
	w.readable(victim, false)
	h1ReceivedRunInline(t, w)
	w.flushPending()
	output := make([]byte, epollReadBufCap)
	length, err := unix.Read(pair[1], output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output[:length], []byte("200 OK")) || !bytes.HasSuffix(output[:length], []byte("hello")) {
		t.Fatalf("victim denied usable capacity: %q", output[:length])
	}
	if w.server.inFlightBodyBytes.Load() != 0 {
		t.Fatal("completed victim retained budget")
	}
}

func TestH1ReceivedBodyTakeover(t *testing.T) {
	w, c, _ := h1ReceivedFixture(t, Config{})
	observed := make(chan struct{})
	w.server.Router.POST("/body", func(req *Request, _ *Response) {
		defer close(observed)
		if string(req.Body) != "hello" {
			t.Error("takeover lost body")
			return
		}
		connection := req.HijackConn()
		if connection == nil {
			t.Error("real takeover failed")
			return
		}
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
	})
	w.server.Router.Build()
	w.server.computeFastDispatch()
	h1ReceivedInput(t, c, "POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: 5\r\n\r\nhello")
	w.serviceBuffered(c, false, false)
	h1ReceivedAssert(t, c, 5)
	start := time.Now()
	for finished := false; !finished; {
		select {
		case <-observed:
			finished = true
		case <-time.After(time.Millisecond):
			if time.Since(start) > h2FixCeiling {
				t.Fatal("takeover handler did not finish")
			}
			w.drainTasks()
		}
	}
	start = time.Now()
	for c.inFlight != 0 && time.Since(start) < h2FixCeiling {
		time.Sleep(time.Millisecond)
		w.drainTasks()
	}
	if c.inFlight != 0 || w.pool.slotsHeld() != 0 || c.takeoverPinned {
		t.Fatal("takeover owner or pin was retained")
	}
	h1ReceivedAssert(t, c, 0)
}

func TestH1ReceivedBodyPanicCompletion(t *testing.T) {
	for _, inline := range []bool{false, true} {
		t.Run(fmt.Sprintf("inline=%v", inline), func(t *testing.T) {
			var panics atomic.Int32
			w, c, _ := h1ReceivedFixture(t, Config{InlineHandlers: inline, OnPanic: func(_ *Request, _ any, _ []byte) { panics.Add(1) }})
			entered := make(chan string, 1)
			w.server.Router.POST("/body", func(req *Request, _ *Response) { entered <- string(req.Body); panic("body-test") })
			w.server.Router.Build()
			w.server.computeFastDispatch()
			h1ReceivedInput(t, c, "POST /body HTTP/1.1\r\nHost: body.test\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello")
			out, step := c.serveH1(w.server, nil)
			if inline {
				if step != h1StepDispatched {
					t.Fatal("inline panic was not queued")
				}
				h1ReceivedRunInline(t, w)
				out = c.writeBuf
			}
			if h1ReceivedAwait(t, entered) != "hello" {
				t.Fatal("panicking handler did not receive body")
			}
			if !inline {
				if step != h1StepDispatched {
					t.Fatal("async panic did not dispatch")
				}
				h1ReceivedFinish(t, w, c)
				out = c.writeBuf
			}
			if panics.Load() != 1 || !bytes.Contains(out, []byte("500 Internal Server Error")) {
				t.Fatalf("panic response missing: count=%d output=%q", panics.Load(), out)
			}
			h1ReceivedAssert(t, c, 0)
		})
	}
}

func TestH1ReceivedBodyActualInputGrowsBuffer(t *testing.T) {
	w, c, peer := h1ReceivedFixture(t, Config{})
	body := strings.Repeat("b", 3*epollReadBufCap)
	request := fmt.Sprintf("POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: %d\r\n\r\n%s", len(body)+1, body)
	if n, err := unix.Write(peer, []byte(request)); err != nil || n != len(request) {
		t.Fatalf("upload write=%d: %v", n, err)
	}
	w.readable(c, false)
	if c.fd < 0 || c.dispatching || c.readN != len(request) {
		t.Fatal("actual partial upload was not buffered")
	}
	if cap(c.readBuf) <= epollReadBufCap || cap(c.readBuf) < c.readN || cap(c.readBuf) > w.server.effectiveReadCap() {
		t.Fatalf("actual-input capacity=%d input=%d cap=%d", cap(c.readBuf), c.readN, w.server.effectiveReadCap())
	}
	h1ReceivedAssert(t, c, int64(len(body)))
	w.closeConn(c)
	h1ReceivedAssert(t, c, 0)
}

func TestH1ReceivedBodyRejectedBeforeCopy(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%v", chunked), func(t *testing.T) {
			w, c, _ := h1ReceivedFixture(t, Config{MaxInFlightBodyBytes: 17})
			body := strings.Repeat("x", 64)
			head := "POST /body HTTP/1.1\r\nHost: body.test\r\nContent-Length: 64\r\n\r\n"
			if chunked {
				head = "POST /body HTTP/1.1\r\nHost: body.test\r\nTransfer-Encoding: chunked\r\n\r\n"
				body = "40\r\n" + body + "\r\n0\r\n\r\n"
			}
			initialCap := cap(c.reqBodyCopy)
			h1ReceivedInput(t, c, head+body)
			out, step := c.serveH1(w.server, nil)
			if step != h1StepClose || !bytes.Contains(out, []byte("503")) {
				t.Fatalf("over-budget complete input step=%d output=%q", step, out)
			}
			if cap(c.reqBodyCopy) != initialCap {
				t.Fatalf("rejected body allocated copy capacity %d -> %d", initialCap, cap(c.reqBodyCopy))
			}
			h1ReceivedAssert(t, c, 0)
		})
	}
}
