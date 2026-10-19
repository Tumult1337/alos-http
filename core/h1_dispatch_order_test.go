//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type dispatchOrderServer struct {
	*testServer
	panics    atomic.Int32
	reqPanics atomic.Int32
	slowDone  atomic.Int32
}

func streamedChunkBody(chunks int) string {
	var buf bytes.Buffer
	for i := 0; i < chunks; i++ {
		fmt.Fprintf(&buf, "%02d,", i)
	}
	return buf.String()
}

func newDispatchOrderServer(t *testing.T) *dispatchOrderServer {
	t.Helper()
	ds := &dispatchOrderServer{}
	ds.testServer = newTestServer(t, testServerOptions{
		Config: func(cfg *Config) {
			cfg.OnPanic = func(req *Request, recovered any, stack []byte) {
				if req == nil {
					ds.panics.Add(1)
					return
				}
				ds.reqPanics.Add(1)
			}
		},
		Routes: func(r *Router) {
			r.GET("/stream", func(req *Request, resp *Response) {
				chunks, _ := strconv.Atoi(req.QueryParam("n"))
				sw := resp.EnsureStreamWriter()
				if sw.WriteHeader(200, nil, "text/plain") != nil {
					return
				}
				for i := 0; i < chunks; i++ {
					if sw.WriteChunk([]byte(fmt.Sprintf("%02d,", i))) != nil {
						return
					}
					_ = sw.Flush()
				}
			})
			r.GET("/slow", func(req *Request, resp *Response) {
				time.Sleep(150 * time.Millisecond)
				resp.Status(200).String("slow")
				ds.slowDone.Add(1)
			})
			r.GET("/boom", func(req *Request, resp *Response) { panic("boom") })
			r.GET("/hello", func(req *Request, resp *Response) { resp.Status(200).String("hello") })
		},
	})
	return ds
}

func TestH1StreamedCompletionRunsAfterQueuedPumps(t *testing.T) {
	ds := newDispatchOrderServer(t)
	const conns, perConn = 4, 150
	var wg sync.WaitGroup
	errs := make(chan error, conns)
	for c := 0; c < conns; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 1}, Timeout: 5 * time.Second}
			defer client.CloseIdleConnections()
			for i := 0; i < perConn; i++ {
				chunks := 1 + (i+c)%64
				resp, err := client.Get(ds.url("/stream?n=" + strconv.Itoa(chunks)))
				if err != nil {
					errs <- err
					return
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					errs <- err
					return
				}
				if want := streamedChunkBody(chunks); string(body) != want {
					errs <- fmt.Errorf("conn %d request %d: body %q want %q", c, i, body, want)
					return
				}
			}
		}(c)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := ds.panics.Load(); n != 0 {
		t.Fatalf("event loop recovered %d panics while finishing streamed responses", n)
	}
}

func TestH1ClientCloseDuringAsyncHandlerIsHarmless(t *testing.T) {
	ds := newDispatchOrderServer(t)
	const abandoned = 8
	for i := 0; i < abandoned; i++ {
		conn, err := net.Dial("tcp4", ds.addr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("GET /slow HTTP/1.1\r\nHost: alos.gg\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	waitFor(t, harnessIOTimeout, func() bool { return ds.slowDone.Load() == abandoned })
	resp, err := http.Get(ds.url("/hello"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello" {
		t.Fatalf("server after abandoned handlers: status %d body %q", resp.StatusCode, body)
	}
	if n := ds.panics.Load() + ds.reqPanics.Load(); n != 0 {
		t.Fatalf("%d panics recovered after clients left mid-handler", n)
	}
}

func TestH1AsyncHandlerPanicAnswers500(t *testing.T) {
	ds := newDispatchOrderServer(t)
	for i := 0; i < 3; i++ {
		resp, err := http.Get(ds.url("/boom"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 500 {
			t.Fatalf("panicking handler answered %d, want 500", resp.StatusCode)
		}
	}
	if n := ds.reqPanics.Load(); n != 3 {
		t.Fatalf("OnPanic saw %d handler panics, want 3", n)
	}
	if n := ds.panics.Load(); n != 0 {
		t.Fatalf("event loop recovered %d panics", n)
	}
}

func TestH1AsyncPipelinedDispatchDoesNotAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	ds := newDispatchOrderServer(t)
	conn, err := net.Dial("tcp4", ds.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const depth = 16
	request := []byte("GET /hello HTTP/1.1\r\nHost: alos.gg\r\n\r\n")
	br := bufio.NewReaderSize(conn, 64<<10)
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	for !bytes.HasSuffix(raw.Bytes(), []byte("hello")) {
		n, err := br.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(buf[:n])
	}
	batch := bytes.Repeat(request, depth)
	in := make([]byte, raw.Len()*depth)
	round := func() {
		if _, err := conn.Write(batch); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(br, in); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ {
		round()
	}
	allocs := testing.AllocsPerRun(200, round)
	if perRequest := allocs / depth; perRequest > 0.25 {
		t.Fatalf("async pipelined dispatch allocates %.2f objects per request (%.1f per batch of %d)", perRequest, allocs, depth)
	}
}
