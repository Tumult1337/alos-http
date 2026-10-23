package core

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

func h2DeadlineFixture(t *testing.T) (*epollWorker, *epollConn, int) {
	t.Helper()
	w := newWorkerForBackendTest(t)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := w.pool.get()
	c.fd, c.worker = pair[0], w
	c.readBuf = acquireEpollReadBuf()
	w.conns = make([]*epollConn, c.fd+1)
	w.conns[c.fd] = c
	w.readTO, w.writeTO, w.idleTO = int64(h2FixCeiling), int64(h2FixShutdownGrace), int64(h2FixShutdownGrace/10)
	w.maxPendingWrite = epollMaxPendingWriteDefault
	w.taskCh = make(chan func(*epollWorker), 32)
	w.handlers = newHandlerPool(1)
	event := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(c.fd)}
	if err := unix.EpollCtl(w.epfd, unix.EPOLL_CTL_ADD, c.fd, &event); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c.fd >= 0 {
			w.closeConn(c)
		}
		w.handlers.close()
		_ = unix.Close(pair[1])
	})
	return w, c, pair[1]
}

func h2DeadlineTask(t *testing.T, w *epollWorker) {
	t.Helper()
	start := time.Now()
	for !w.taskPending.Load() && time.Since(start) < h2FixCeiling {
		time.Sleep(time.Millisecond)
	}
	if !w.taskPending.Load() {
		t.Fatal("async completion was not posted")
	}
	w.drainTasks()
}

func h2DeadlineWant(t *testing.T, c *epollConn, before, after, timeout int64) {
	t.Helper()
	if c.deadline < before+timeout || c.deadline > after+timeout {
		t.Fatalf("deadline = %d; want configured timeout %v after [%d, %d]", c.deadline, time.Duration(timeout), before, after)
	}
}

func TestH2IdleDeadlineAsyncSmallResponse(t *testing.T) {
	w, c, peer := h2DeadlineFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() {
		unblock()
		for c.inFlight > 0 {
			h2DeadlineTask(t, w)
		}
	})
	w.server.Router.GET("/deadline", func(_ *Request, response *Response) {
		close(entered)
		<-release
		response.Status(200).String("deadline-body")
	})
	w.server.Router.Build()
	w.server.computeFastDispatch()
	request := append([]byte(nil), H2ClientPreface[:]...)
	request = appendH2Frame(request, H2FrameSettings, 0, 0, nil)
	request = appendH2Frame(request, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/deadline"))
	if _, err := unix.Write(peer, request); err != nil {
		t.Fatal(err)
	}
	w.readable(c, false)
	select {
	case <-entered:
	case <-time.After(h2FixCeiling):
		t.Fatal("handler was not entered asynchronously")
	}
	if c.inFlight != 1 || c.deadline != 0 || w.spawned != 1 {
		t.Fatalf("async suspension: inFlight=%d deadline=%d spawned=%d", c.inFlight, c.deadline, w.spawned)
	}
	if c.outArmed || c.writeSent != len(c.writeBuf) {
		t.Fatal("initial output was not drained immediately")
	}
	capacity, err := unix.GetsockoptInt(c.fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
	if err != nil {
		t.Fatal(err)
	}
	if capacity < 4096 {
		t.Fatalf("socket capacity %d cannot guarantee the small immediate write", capacity)
	}
	before := turbo.UnixNano()
	unblock()
	h2DeadlineTask(t, w)
	w.flushPending()
	after := turbo.UnixNano()
	if c.inFlight != 0 || !c.h2Quiescent() || c.outArmed || len(c.writeBuf) != 0 {
		t.Fatalf("response did not finish immediately: inFlight=%d outArmed=%v buffered=%d", c.inFlight, c.outArmed, len(c.writeBuf))
	}
	output := make([]byte, 4096)
	length, err := unix.Read(peer, output)
	if err != nil {
		t.Fatal(err)
	}
	output = output[:length]
	var body []byte
	ended, headers := false, false
	for len(output) >= 9 {
		size := int(output[0])<<16 | int(output[1])<<8 | int(output[2])
		if size+9 > len(output) {
			t.Fatal("partial response frame")
		}
		id := binary.BigEndian.Uint32(output[5:9])
		if id == 1 {
			if output[3] == H2FrameHeaders {
				headers = h2RawStatusFromHeaders(t, output[9:9+size]) == 200
			}
			if output[3] == H2FrameData {
				body = append(body, output[9:9+size]...)
			}
			ended = ended || output[4]&H2FlagEndStream != 0
		}
		output = output[9+size:]
	}
	if !headers || !ended || !bytes.Equal(body, []byte("deadline-body")) {
		t.Fatalf("missing completed real response: headers=%v ended=%v body=%q", headers, ended, body)
	}
	h2DeadlineWant(t, c, before, after, w.idleTO)
	savedDeadline := c.deadline
	waitStart := time.Now()
	for turbo.UnixNano() <= savedDeadline && time.Since(waitStart) < h2FixCeiling {
		time.Sleep(time.Millisecond)
	}
	if turbo.UnixNano() <= savedDeadline {
		t.Fatal("sweeper clock did not advance beyond the saved deadline")
	}
	w.sweepDeadlines()
	if c.fd >= 0 {
		t.Fatal("idle connection survived its configured deadline")
	}
	length, err = unix.Read(peer, output[:cap(output)])
	if err != nil || length != 0 {
		t.Fatalf("peer did not observe close: bytes=%d error=%v", length, err)
	}
}

func TestH2IdleDeadlineStatePolicy(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*epollConn, *epollWorker)
		timeout   func(*epollWorker) int64
		unchanged int64
	}{
		{name: "idle", timeout: func(w *epollWorker) int64 { return w.idleTO }},
		{name: "partial-frame", setup: func(c *epollConn, _ *epollWorker) { c.readN = 2; c.h2.appBufOff = 1 }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "consumed-raw-input", setup: func(c *epollConn, _ *epollWorker) { c.readN = 2; c.h2.appBufOff = 2 }, timeout: func(w *epollWorker) int64 { return w.idleTO }},
		{name: "continuation", setup: func(c *epollConn, _ *epollWorker) { c.h2.expectContinuation = 3 }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "receiving-stream", setup: func(c *epollConn, _ *epollWorker) { c.h2.streams = map[uint32]*H2Stream{3: {}} }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "receiving-body", setup: func(c *epollConn, _ *epollWorker) { c.h2BodyIn = map[uint32]*h2BodyIn{3: {}} }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "tls-cipher-fragment", setup: func(c *epollConn, _ *epollWorker) { c.tls = true; c.phase = tlsConnPhaseH2Native; c.readN = 1 }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "tls-application-fragment", setup: func(c *epollConn, _ *epollWorker) {
			c.tls = true
			c.phase = tlsConnPhaseH2Native
			c.appBuf = []byte{1}
			c.appBufOff = 1
		}, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "tls-unconsumed-application", setup: func(c *epollConn, _ *epollWorker) {
			c.tls = true
			c.phase = tlsConnPhaseH2Native
			c.appBuf = []byte{1}
			c.h2.appBufOff = 1
		}, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "active-sibling", setup: func(c *epollConn, _ *epollWorker) { c.inFlight = 1 }},
		{name: "active-sibling-partial-input", setup: func(c *epollConn, _ *epollWorker) { c.inFlight = 1; c.readN = 1 }},
		{name: "dispatching", setup: func(c *epollConn, _ *epollWorker) { c.dispatching = true }},
		{name: "pending-write", setup: func(c *epollConn, _ *epollWorker) { c.writeBuf = []byte{1} }},
		{name: "write-armed", setup: func(c *epollConn, _ *epollWorker) { c.outArmed = true }, timeout: func(w *epollWorker) int64 { return w.writeTO }},
		{name: "write-armed-active-sibling", setup: func(c *epollConn, _ *epollWorker) { c.outArmed = true; c.inFlight = 1 }},
		{name: "write-armed-dispatching", setup: func(c *epollConn, _ *epollWorker) { c.outArmed = true; c.dispatching = true }},
		{name: "write-armed-closed", setup: func(c *epollConn, _ *epollWorker) { c.outArmed = true; c.fd = -1 }},
		{name: "write-armed-write-disabled", setup: func(c *epollConn, w *epollWorker) { c.outArmed = true; w.writeTO = 0 }},
		{name: "buffered-flow-blocked", setup: func(c *epollConn, _ *epollWorker) { c.h2.sending = map[uint32]*H2Stream{1: {}} }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "streamed-flow-blocked", setup: func(c *epollConn, _ *epollWorker) { c.h2Streaming = map[uint32]*epollH2StreamWriter{1: {}} }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "existing-read", setup: func(c *epollConn, _ *epollWorker) { c.readN = 1; c.deadline = 17 }, unchanged: 17},
		{name: "existing-write", setup: func(c *epollConn, _ *epollWorker) { c.deadline = 29 }, unchanged: 29},
		{name: "lingering", setup: func(c *epollConn, _ *epollWorker) { c.lingering = true }},
		{name: "closing", setup: func(c *epollConn, _ *epollWorker) { c.closeAfter = true }},
		{name: "closed", setup: func(c *epollConn, _ *epollWorker) { c.fd = -1 }},
		{name: "http1", setup: func(c *epollConn, _ *epollWorker) { c.protocol = plainConnProtoH1 }},
		{name: "idle-disabled", setup: func(_ *epollConn, w *epollWorker) { w.idleTO = 0 }},
		{name: "read-disabled", setup: func(c *epollConn, w *epollWorker) { c.readN = 1; w.readTO = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := &epollWorker{readTO: int64(h2FixCeiling), writeTO: int64(h2FixShutdownGrace), idleTO: int64(h2FixShutdownGrace / 10)}
			c := &epollConn{fd: 1, protocol: plainConnProtoH2}
			if test.setup != nil {
				test.setup(c, w)
			}
			before := turbo.UnixNano()
			c.restoreH2Deadline(w)
			after := turbo.UnixNano()
			if test.timeout != nil {
				h2DeadlineWant(t, c, before, after, test.timeout(w))
			} else if c.deadline != test.unchanged {
				t.Fatalf("deadline changed to %d, want %d", c.deadline, test.unchanged)
			}
		})
	}
}

func TestH2IdleDeadlineFinisherBranches(t *testing.T) {
	for _, branch := range []string{"zero-body", "body", "abandoned", "streamed-finished", "unused-writer", "pending-output", "flow-blocked", "stale-generation", "closed", "existing-deadline"} {
		t.Run(branch, func(t *testing.T) {
			w, c, _ := h2DeadlineFixture(t)
			c.protocol = plainConnProtoH2
			c.h2.init(w.server.h2HeaderTableSize(), w.server.h2HeaderListLimit())
			stream := StreamPool.Get().(*H2Stream)
			stream.Reset()
			stream.ID, stream.asyncBusy = 1, true
			stream.Window.Store(H2DefaultWindowSize)
			stream.resp.Status(200)
			c.inFlight = 1
			c.h2.linkBusy(stream)
			gen := c.generation
			switch branch {
			case "body":
				stream.resp.String("response")
			case "abandoned":
				stream.abandoned, stream.abandonCounted, c.h2EndedInFlight = true, true, 1
			case "streamed-finished", "unused-writer":
				writer := epollH2StreamWriterPool.Get().(*epollH2StreamWriter)
				writer.c, writer.w, writer.stream, writer.gen, writer.streamID = c, w, stream, gen, 1
				writer.headerReady, writer.finished = branch == "streamed-finished", branch == "streamed-finished"
				stream.resp.sw = writer
			case "pending-output":
				stream.abandoned = true
				c.writeBuf = append(c.writeBuf, 1)
			case "flow-blocked":
				stream.resp.String("flow-blocked")
				stream.Window.Store(0)
			case "stale-generation":
				c.generation++
			case "closed":
				w.closeConn(c)
				gen = c.generation
			case "existing-deadline":
				c.deadline = 31
			}
			before := turbo.UnixNano()
			c.finishH2Dispatch(w, gen, 1, stream)
			if (branch == "stale-generation" || branch == "closed") && (len(c.writeBuf) != 0 || c.flushQueued) {
				t.Fatal("stale completion wrote or queued a response")
			}
			if branch == "stale-generation" || branch == "closed" || branch == "pending-output" || branch == "flow-blocked" {
				if c.deadline != 0 {
					t.Fatalf("finisher rearmed excluded state to %d", c.deadline)
				}
				return
			}
			if branch == "existing-deadline" {
				w.flushPending()
				if c.deadline != 31 {
					t.Fatalf("extended existing deadline to %d", c.deadline)
				}
				return
			}
			if branch == "abandoned" || branch == "streamed-finished" {
				h2DeadlineWant(t, c, before, turbo.UnixNano(), w.idleTO)
			}
			w.flushPending()
			h2DeadlineWant(t, c, before, turbo.UnixNano(), w.idleTO)
			if !c.h2Quiescent() || c.h2EndedInFlight != 0 {
				t.Fatal("completion did not release stream state")
			}
		})
	}
}

func TestH2IdleDeadlineAfterFinalFlush(t *testing.T) {
	for _, mode := range []string{"immediate", "armed", "armed-existing-read", "armed-existing-write", "armed-partial-input", "armed-active-sibling"} {
		t.Run(mode, func(t *testing.T) {
			w, c, _ := h2DeadlineFixture(t)
			c.protocol = plainConnProtoH2
			c.h2.init(w.server.h2HeaderTableSize(), w.server.h2HeaderListLimit())
			c.writeBuf = appendH2Frame(c.writeBuf, H2FramePing, H2FlagAck, 0, make([]byte, 8))
			c.outArmed = mode != "immediate"
			switch mode {
			case "armed-existing-read":
				c.deadline = 37
			case "armed-existing-write":
				c.deadline = 41
			case "armed-partial-input":
				c.readN = 1
			case "armed-active-sibling":
				c.inFlight = 1
				t.Cleanup(func() { c.inFlight = 0 })
			}
			before := turbo.UnixNano()
			if !w.flush(c) {
				t.Fatal("flush closed connection")
			}
			if c.outArmed || len(c.writeBuf) != 0 {
				t.Fatal("final flush did not drain")
			}
			switch mode {
			case "armed-active-sibling":
				if c.deadline != 0 {
					t.Fatalf("active sibling acquired deadline %d", c.deadline)
				}
			case "armed-partial-input":
				h2DeadlineWant(t, c, before, turbo.UnixNano(), w.readTO)
			default:
				h2DeadlineWant(t, c, before, turbo.UnixNano(), w.idleTO)
			}
		})
	}
}

func TestH2IdleDeadlineWaitsForActiveSibling(t *testing.T) {
	w, c, peer := h2DeadlineFixture(t)
	entered := make(chan struct{}, 2)
	first, second := make(chan struct{}), make(chan struct{})
	var firstOnce, secondOnce sync.Once
	unblockFirst := func() { firstOnce.Do(func() { close(first) }) }
	unblockSecond := func() { secondOnce.Do(func() { close(second) }) }
	t.Cleanup(func() {
		unblockFirst()
		unblockSecond()
		for c.inFlight > 0 {
			h2DeadlineTask(t, w)
		}
	})
	w.server.Router.GET("/first", func(_ *Request, response *Response) {
		entered <- struct{}{}
		<-first
		response.Status(200).String("first")
	})
	w.server.Router.GET("/second", func(_ *Request, response *Response) {
		entered <- struct{}{}
		<-second
		response.Status(200).String("second")
	})
	w.server.Router.Build()
	w.server.computeFastDispatch()
	request := append([]byte(nil), H2ClientPreface[:]...)
	request = appendH2Frame(request, H2FrameSettings, 0, 0, nil)
	request = appendH2Frame(request, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2FixRequestBlock("GET", "/first"))
	request = appendH2Frame(request, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, h2FixRequestBlock("GET", "/second"))
	if _, err := unix.Write(peer, request); err != nil {
		t.Fatal(err)
	}
	w.readable(c, false)
	for range 2 {
		select {
		case <-entered:
		case <-time.After(h2FixCeiling):
			t.Fatal("both handlers did not enter")
		}
	}
	if c.inFlight != 2 || c.deadline != 0 || w.spawned != 2 {
		t.Fatalf("sibling setup: inFlight=%d deadline=%d spawned=%d", c.inFlight, c.deadline, w.spawned)
	}
	unblockFirst()
	h2DeadlineTask(t, w)
	w.flushPending()
	if c.inFlight != 1 || c.deadline != 0 {
		t.Fatalf("blocked sibling lost exemption: inFlight=%d deadline=%d", c.inFlight, c.deadline)
	}
	before := turbo.UnixNano()
	unblockSecond()
	h2DeadlineTask(t, w)
	w.flushPending()
	if c.inFlight != 0 || !c.h2Quiescent() {
		t.Fatal("last handler did not finish")
	}
	h2DeadlineWant(t, c, before, turbo.UnixNano(), w.idleTO)
}

func TestH2IdleDeadlineBufferedService(t *testing.T) {
	for _, mode := range []string{"idle", "continuation", "receiving-stream", "existing-read"} {
		t.Run(mode, func(t *testing.T) {
			w := &epollWorker{readTO: int64(h2FixCeiling), writeTO: int64(h2FixShutdownGrace), idleTO: int64(h2FixShutdownGrace / 10)}
			c := &epollConn{fd: 1, protocol: plainConnProtoH2}
			switch mode {
			case "continuation":
				c.h2.expectContinuation = 3
			case "receiving-stream":
				c.h2.streams = map[uint32]*H2Stream{3: {}}
			case "existing-read":
				c.deadline = 43
			}
			before := turbo.UnixNano()
			w.serviceBuffered(c, false, false)
			switch mode {
			case "existing-read":
				if c.deadline != 43 {
					t.Fatalf("extended existing read deadline to %d", c.deadline)
				}
			case "idle":
				h2DeadlineWant(t, c, before, turbo.UnixNano(), w.idleTO)
			default:
				h2DeadlineWant(t, c, before, turbo.UnixNano(), w.readTO)
			}
		})
	}
}

func h2DeadlineBlockWrite(t *testing.T, w *epollWorker, c *epollConn) {
	t.Helper()
	if err := unix.SetsockoptInt(c.fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4096); err != nil {
		t.Fatal(err)
	}
	ping := appendH2Frame(nil, H2FramePing, H2FlagAck, 0, make([]byte, 8))
	for len(c.writeBuf) < 1<<20 {
		c.writeBuf = append(c.writeBuf, ping...)
	}
	before := turbo.UnixNano()
	if !w.flush(c) {
		t.Fatal("blocked flush closed connection")
	}
	if !c.outArmed || c.writeSent == len(c.writeBuf) {
		t.Fatal("write did not reach EAGAIN")
	}
	if w.writeTO > 0 {
		h2DeadlineWant(t, c, before, turbo.UnixNano(), w.writeTO)
	}
}

func h2DeadlineDrainOutput(t *testing.T, w *epollWorker, c *epollConn, peer int) (int64, int64) {
	t.Helper()
	sink := make([]byte, 64<<10)
	var before, after int64
	start := time.Now()
	for c.fd >= 0 && c.outArmed && time.Since(start) < h2FixCeiling {
		if _, err := unix.Read(peer, sink); err != nil && err != unix.EAGAIN {
			t.Fatal(err)
		}
		before = turbo.UnixNano()
		w.serviceConn(c, unix.EPOLLOUT)
		after = turbo.UnixNano()
	}
	if c.fd < 0 || c.outArmed || len(c.writeBuf) != 0 {
		t.Fatalf("output did not drain: fd=%d outArmed=%v buffered=%d", c.fd, c.outArmed, len(c.writeBuf))
	}
	return before, after
}

func TestH2IdleDeadlineAfterBlockedWriteDrains(t *testing.T) {
	const priorDeadline = 37
	tests := []struct {
		name    string
		setup   func(*epollConn, *epollWorker)
		timeout func(*epollWorker) int64
		want    int64
	}{
		{name: "quiescent", timeout: func(w *epollWorker) int64 { return w.idleTO }},
		{name: "partial-frame", setup: func(c *epollConn, _ *epollWorker) { c.readN = 2; c.h2.appBufOff = 1 }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "idle-disabled", setup: func(_ *epollConn, w *epollWorker) { w.idleTO = 0 }},
		{name: "read-disabled", setup: func(c *epollConn, w *epollWorker) { c.readN = 2; c.h2.appBufOff = 1; w.readTO = 0 }},
		{name: "write-disabled-existing", setup: func(c *epollConn, w *epollWorker) { w.writeTO = 0; c.deadline = priorDeadline }, want: priorDeadline},
		{name: "write-disabled", setup: func(_ *epollConn, w *epollWorker) { w.writeTO = 0 }, timeout: func(w *epollWorker) int64 { return w.idleTO }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w, c, peer := h2DeadlineFixture(t)
			c.protocol = plainConnProtoH2
			c.h2.init(w.server.h2HeaderTableSize(), w.server.h2HeaderListLimit())
			if test.setup != nil {
				test.setup(c, w)
			}
			if w.writeTO == w.idleTO || w.writeTO == w.readTO {
				t.Fatal("fixture cannot separate the write timeout")
			}
			h2DeadlineBlockWrite(t, w, c)
			before, after := h2DeadlineDrainOutput(t, w, c, peer)
			if test.timeout != nil {
				h2DeadlineWant(t, c, before, after, test.timeout(w))
				return
			}
			if c.deadline != test.want {
				t.Fatalf("deadline = %d, want %d", c.deadline, test.want)
			}
		})
	}
}

func TestH2DisarmOutDeadlinePolicy(t *testing.T) {
	const writeDeadline, wsDeadline = 53, 61
	tests := []struct {
		name    string
		setup   func(*epollConn, *epollWorker)
		timeout func(*epollWorker) int64
		want    int64
	}{
		{name: "quiescent", timeout: func(w *epollWorker) int64 { return w.idleTO }},
		{name: "partial-frame", setup: func(c *epollConn, _ *epollWorker) { c.readN = 2; c.h2.appBufOff = 1 }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "receiving-stream", setup: func(c *epollConn, _ *epollWorker) { c.h2.streams = map[uint32]*H2Stream{3: {}} }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "buffered-flow-blocked", setup: func(c *epollConn, _ *epollWorker) { c.h2.sending = map[uint32]*H2Stream{1: {}} }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "streamed-flow-blocked", setup: func(c *epollConn, _ *epollWorker) { c.h2Streaming = map[uint32]*epollH2StreamWriter{1: {}} }, timeout: func(w *epollWorker) int64 { return w.readTO }},
		{name: "lingering", setup: func(c *epollConn, _ *epollWorker) { c.lingering = true }, want: writeDeadline},
		{name: "closing", setup: func(c *epollConn, _ *epollWorker) { c.closeAfter = true }, want: writeDeadline},
		{name: "pending-write", setup: func(c *epollConn, _ *epollWorker) { c.writeBuf = []byte{1} }, want: writeDeadline},
		{name: "in-flight", setup: func(c *epollConn, _ *epollWorker) { c.inFlight = 1 }},
		{name: "dispatching", setup: func(c *epollConn, _ *epollWorker) { c.dispatching = true }},
		{name: "websocket", setup: func(c *epollConn, _ *epollWorker) { c.ws = &wsLoopConn{readDeadline: wsDeadline} }, want: wsDeadline},
		{name: "idle-disabled", setup: func(_ *epollConn, w *epollWorker) { w.idleTO = 0 }},
		{name: "read-disabled", setup: func(c *epollConn, w *epollWorker) { c.readN = 2; c.h2.appBufOff = 1; w.readTO = 0 }},
		{name: "write-disabled-existing", setup: func(_ *epollConn, w *epollWorker) { w.writeTO = 0 }, want: writeDeadline},
		{name: "write-disabled", setup: func(c *epollConn, w *epollWorker) { w.writeTO = 0; c.deadline = 0 }, timeout: func(w *epollWorker) int64 { return w.idleTO }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := &epollWorker{readTO: int64(h2FixCeiling), writeTO: int64(h2FixShutdownGrace), idleTO: int64(h2FixShutdownGrace / 10)}
			c := &epollConn{fd: 1, protocol: plainConnProtoH2, outArmed: true, deadline: writeDeadline}
			if test.setup != nil {
				test.setup(c, w)
			}
			before := turbo.UnixNano()
			w.disarmOut(c)
			after := turbo.UnixNano()
			if c.outArmed {
				t.Fatal("disarmOut left output armed")
			}
			if test.timeout != nil {
				h2DeadlineWant(t, c, before, after, test.timeout(w))
				return
			}
			if c.deadline != test.want {
				t.Fatalf("deadline = %d, want %d", c.deadline, test.want)
			}
		})
	}
}
