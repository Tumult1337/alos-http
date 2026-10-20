//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func dateRequireAt(t *testing.T, fields [][2]string, unix int64) {
	t.Helper()
	want := time.Unix(unix, 0).UTC().Format(http.TimeFormat)
	if got := dateValues(fields); len(got) != 1 || got[0] != want {
		t.Fatalf("Date=%q, want %q", got, want)
	}
}

func dateMemoServer(t *testing.T, clock *atomic.Int64, body string, headers ...[2]string) (*Server, *atomic.Int64) {
	t.Helper()
	calls := new(atomic.Int64)
	server := New(Config{})
	server.dateNow = clock.Load
	server.Router.GET("/", func(_ *Request, response *Response) {
		calls.Add(1)
		response.Headers = append(response.Headers, headers...)
		response.String(body)
	})
	server.Router.Build()
	server.computeFastDispatch()
	server.enableAltSvc(443)
	if server.plainRootFast.Load() == nil || server.h2RootFast.Load() == nil {
		t.Fatal("missing eligible root templates")
	}
	return server, calls
}

func dateMemoH2Fields(t *testing.T, fast *h2RootFastResponse) [][2]string {
	t.Helper()
	wire := appendFastH2RootResponse(nil, fast, 123, H2DefaultMaxFrameSize)
	block, body, _ := responseHeaderFlight(t, wire, 123, H2DefaultMaxFrameSize, len(fast.body) == 0)
	if !bytes.Equal(body, fast.body) {
		t.Fatal("cached H2 body changed")
	}
	fields, err := newHpackDecoder(4096).Decode(block)
	if err != nil {
		t.Fatal(err)
	}
	return fields
}

func TestResponseDateMemoEpochsAndSnapshots(t *testing.T) {
	for _, size := range []int{4, 32768} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			var clock atomic.Int64
			first := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC).Unix()
			clock.Store(first)
			server, calls := dateMemoServer(t, &clock, strings.Repeat("r", size))
			count := calls.Load()
			oldH1, oldH2 := server.plainRootFast.Load(), server.h2RootFast.Load()
			oldH1Bytes, oldH2Bytes := bytes.Clone(oldH1.getKeepAlive), bytes.Clone(oldH2.headerPayload)
			oldAltH1, oldAltH2 := bytes.Clone(oldH1.tlsKeepAlive), bytes.Clone(oldH2.withAltSvc.headerPayload)
			for _, unix := range []int64{first, first + 86400*700, first} {
				clock.Store(unix)
				for _, tlsMode := range []bool{false, true} {
					for _, closeMode := range []bool{false, true} {
						connection := ""
						if closeMode {
							connection = "Connection: close\r\n"
						}
						request := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n" + connection + "\r\n")
						wire, consumed, closed, ok := server.matchPlainRootFastRequest(request, tlsMode)
						if !ok || consumed != len(request) || closed != closeMode {
							t.Fatalf("root match ok=%v consumed=%d closed=%v", ok, consumed, closed)
						}
						dateRequireAt(t, dateH1Fields(t, wire), unix)
						if tlsMode && !bytes.Contains(wire, []byte("Alt-Svc:")) {
							t.Fatal("missing TLS Alt-Svc")
						}
					}
				}
				h1 := server.plainRootFast.Load()
				dateRequireAt(t, dateH1Fields(t, h1.getKeepAliveTLS[:len(h1.getKeepAliveTLS)-1]), unix)
				dateRequireAt(t, dateH1Fields(t, h1.getCloseTLS[:len(h1.getCloseTLS)-1]), unix)
				h2 := server.currentH2RootDate(server.h2RootFast.Load())
				for _, tlsMode := range []bool{false, true} {
					dateRequireAt(t, dateMemoH2Fields(t, h2.forConn(tlsMode)), unix)
				}
				if !bytes.Equal(oldH1Bytes, oldH1.getKeepAlive) || !bytes.Equal(oldH2Bytes, oldH2.headerPayload) || !bytes.Equal(oldAltH1, oldH1.tlsKeepAlive) || !bytes.Equal(oldAltH2, oldH2.withAltSvc.headerPayload) {
					t.Fatal("old snapshot changed during epoch transition")
				}
			}
			if calls.Load() != count {
				t.Fatalf("root handler reran: calls %d -> %d", count, calls.Load())
			}
		})
	}
}

func TestResponseDateMemoReloadAndClock(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			var clock atomic.Int64
			clock.Store(1000000000)
			server, _ := dateMemoServer(t, &clock, "root")
			oldH1, oldH2 := server.plainRootFast.Load(), server.h2RootFast.Load()
			samples := 0
			var clockOutsideLock []bool
			server.dateNow = func() int64 {
				samples++
				unlocked := server.rootFastMu.TryLock()
				if unlocked {
					server.rootFastMu.Unlock()
				}
				clockOutsideLock = append(clockOutsideLock, unlocked)
				return 1000000000 + int64(samples)
			}
			if protocol == "h1" {
				dateRequireAt(t, dateH1Fields(t, server.currentPlainRootDate(oldH1).getKeepAlive), 1000000002)
			} else {
				dateRequireAt(t, dateMemoH2Fields(t, server.currentH2RootDate(oldH2)), 1000000002)
			}
			if samples != 2 {
				t.Fatalf("clock sampled %d times, want outside+inside lock", samples)
			}
			if len(clockOutsideLock) != 2 || !clockOutsideLock[0] || clockOutsideLock[1] {
				t.Fatalf("clock lock states=%v, want outside then inside", clockOutsideLock)
			}
			if !server.rootFastMu.TryLock() {
				t.Fatal("refresh retained root lock")
			}
			server.rootFastMu.Unlock()
			samples = 0
			server.dateNow = func() int64 {
				samples++
				if protocol == "h1" {
					server.plainRootFast.Store(nil)
				} else {
					server.h2RootFast.Store(nil)
				}
				return 1000000003
			}
			if protocol == "h1" {
				if server.currentPlainRootDate(oldH1) != nil {
					t.Fatal("reload lost nil cache")
				}
			} else {
				if server.currentH2RootDate(oldH2) != nil {
					t.Fatal("reload lost nil cache")
				}
			}
		})
	}
	for _, value := range []string{"", "opaque"} {
		var clock atomic.Int64
		clock.Store(1000000000)
		server, _ := dateMemoServer(t, &clock, "root", [2]string{"dAtE", value})
		oldH1, oldH2 := server.plainRootFast.Load(), server.h2RootFast.Load()
		clock.Add(1)
		if server.currentPlainRootDate(oldH1) != oldH1 || server.currentH2RootDate(oldH2) != oldH2 {
			t.Fatal("explicit Date template refreshed")
		}
		if got := dateValues(dateH1Fields(t, oldH1.getKeepAlive)); len(got) != 1 || got[0] != value {
			t.Fatalf("explicit Date=%q", got)
		}
	}
}

func TestResponseDateMemoIgnoresNonRootAndRejectedInput(t *testing.T) {
	var clock atomic.Int64
	clock.Store(1000000000)
	server, _ := dateMemoServer(t, &clock, "root")
	oldH1 := server.plainRootFast.Load()
	var samples atomic.Int64
	server.dateNow = func() int64 { samples.Add(1); return 1000000001 }
	for _, request := range []string{"GET /other HTTP/1.1\r\nHost: example.test\r\n\r\n", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", "GET / HTTP/1.1\r\nHost: a\r\n"} {
		if _, _, _, ok := server.matchPlainRootFastRequest([]byte(request), false); ok {
			t.Fatalf("unexpected root match %q", request)
		}
	}
	if samples.Load() != 0 || server.plainRootFast.Load() != oldH1 {
		t.Fatal("invalid/nonroot input refreshed memo")
	}
}

func TestResponseDateMemoConcurrentReaders(t *testing.T) {
	const readers = 4
	var clock atomic.Int64
	clock.Store(1000000000)
	server, calls := dateMemoServer(t, &clock, "root")
	count := calls.Load()
	for _, protocol := range []string{"h1", "h2"} {
		for _, unix := range []int64{1000000001, 1000000002, 1000000000} {
			clock.Store(unix)
			var samples atomic.Int64
			entered, release := make(chan struct{}, readers), make(chan struct{})
			server.dateNow = func() int64 {
				if samples.Add(1) <= readers {
					entered <- struct{}{}
					<-release
				}
				return clock.Load()
			}
			want := time.Unix(unix, 0).UTC().Format(http.TimeFormat)
			errors := make(chan error, readers)
			var group sync.WaitGroup
			for worker := 0; worker < readers; worker++ {
				group.Add(1)
				go func() {
					defer group.Done()
					for iteration := 0; iteration < 20; iteration++ {
						if protocol == "h1" {
							wire, _, _, ok := server.matchPlainRootFastRequest([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), true)
							if !ok {
								errors <- fmt.Errorf("H1 root did not match")
								return
							}
							response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(wire)), nil)
							if err != nil {
								errors <- err
								return
							}
							body, err := io.ReadAll(response.Body)
							response.Body.Close()
							if err != nil || string(body) != "root" || len(response.Header.Values("Date")) != 1 || response.Header.Get("Date") != want {
								errors <- fmt.Errorf("H1 snapshot Date=%q body=%q err=%v", response.Header.Values("Date"), body, err)
								return
							}
						} else {
							fast := server.currentH2RootDate(server.h2RootFast.Load()).forConn(true)
							fields, err := newHpackDecoder(4096).Decode(fast.headerPayload)
							if err != nil {
								errors <- err
								return
							}
							values := dateValues(fields)
							if len(values) != 1 || values[0] != want || string(fast.body) != "root" {
								errors <- fmt.Errorf("H2 snapshot Date=%q body=%q", values, fast.body)
								return
							}
						}
					}
				}()
			}
			timer := time.NewTimer(proxyFixCeiling)
			for arrived := 0; arrived < readers; arrived++ {
				select {
				case <-entered:
				case <-timer.C:
					close(release)
					group.Wait()
					t.Fatalf("only %d stale readers reached clock barrier", arrived)
				}
			}
			timer.Stop()
			close(release)
			group.Wait()
			close(errors)
			for err := range errors {
				t.Error(err)
			}
		}
	}
	if calls.Load() != count {
		t.Fatal("concurrent update reran handler")
	}
}

func TestResponseDateMemoH2ActualRootPaths(t *testing.T) {
	for _, mode := range []string{"indexed", "memoized", "decoded"} {
		for _, tlsMode := range []bool{false, true} {
			t.Run(mode+strconv.FormatBool(tlsMode), func(t *testing.T) {
				var clock atomic.Int64
				clock.Store(1000000000)
				server, calls := dateMemoServer(t, &clock, "root")
				count := calls.Load()
				connection := &epollConn{worker: &epollWorker{server: server}, tls: tlsMode}
				connection.h2.decoder = newHpackDecoder(H2HeaderTableSize)
				connection.h2.maxFrameSize = H2DefaultMaxFrameSize
				block := h2FixRequestBlock("GET", "/")
				if mode == "indexed" {
					block = []byte{0x82, 0x84, 0x87}
					if !matchIndexedH2FastRootHeaderBlock(block) {
						t.Fatal("indexed fixture not indexed")
					}
				} else if matchIndexedH2FastRootHeaderBlock(block) {
					t.Fatal("nonindexed fixture bypasses decode")
				}
				if mode == "memoized" {
					_, _, root, err := connection.h2.decoder.DecodeRequest(nil, block)
					if err != nil || !root || !connection.h2.decoder.MemoizedRootRequest(block) {
						t.Fatalf("not memoized root: root=%v err=%v", root, err)
					}
				} else if connection.h2.decoder.MemoizedRootRequest(block) {
					t.Fatal("fresh block unexpectedly memoized")
				}
				clock.Store(1000000001)
				if connection.epollH2DecodedHeaders(server, 1, block, true) {
					t.Fatal("root response closed connection")
				}
				encoded, body, _ := responseHeaderFlight(t, connection.writeBuf, 1, H2DefaultMaxFrameSize, false)
				fields, err := newHpackDecoder(4096).Decode(encoded)
				if err != nil {
					t.Fatal(err)
				}
				dateRequireAt(t, fields, 1000000001)
				if string(body) != "root" || calls.Load() != count {
					t.Fatal("actual root path changed body or reran handler")
				}
				altCount := 0
				for _, field := range fields {
					if field[0] == "alt-svc" {
						altCount++
					}
				}
				wantAlt := 0
				if tlsMode {
					wantAlt = 1
				}
				if altCount != wantAlt {
					t.Fatalf("alt count=%d want=%d", altCount, wantAlt)
				}
			})
		}
	}
}

func TestResponseDateMemoReloadExplicitTemplate(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			var clock atomic.Int64
			clock.Store(1000000000)
			server, _ := dateMemoServer(t, &clock, "root")
			oldH1, oldH2 := server.plainRootFast.Load(), server.h2RootFast.Load()
			explicitH1 := &plainRootFastResponse{getKeepAlive: appendPlainResponse(&Response{StatusCode: 200, Headers: [][2]string{{"Date", "opaque"}}}, nil)}
			encoder := HpackEncoder{}
			encodeH2ResponseHeaders(&encoder, 200, "", 0, [][2]string{{"Date", "opaque"}}, "ALOS")
			explicitH2 := newH2RootFastResponse(encoder.Buf, nil)
			server.dateNow = func() int64 {
				if protocol == "h1" {
					server.plainRootFast.Store(explicitH1)
				} else {
					server.h2RootFast.Store(explicitH2)
				}
				return 1000000001
			}
			if protocol == "h1" {
				if server.currentPlainRootDate(oldH1) != explicitH1 {
					t.Fatal("stale refresh replaced explicit H1 template")
				}
			} else {
				if server.currentH2RootDate(oldH2) != explicitH2 {
					t.Fatal("stale refresh replaced explicit H2 template")
				}
			}
		})
	}
}

func TestResponseDateMemoRootHeaderCrossing(t *testing.T) {
	_, block := responseHeaderBlockOfSize(t, H2DefaultMaxFrameSize)
	fields, err := newHpackDecoder(4096).Decode(block)
	if err != nil {
		t.Fatal(err)
	}
	var headers [][2]string
	for _, field := range fields {
		if field[0] != "" && field[0][0] != ':' && field[0] != "content-length" && field[0] != "server" && field[0] != "date" {
			headers = append(headers, field)
		}
	}
	var clock atomic.Int64
	clock.Store(1000000000)
	server, calls := dateMemoServer(t, &clock, "root", headers...)
	count := calls.Load()
	for _, unix := range []int64{1000000000, 1000000001, 1000000000} {
		clock.Store(unix)
		current := server.currentH2RootDate(server.h2RootFast.Load())
		for _, tlsMode := range []bool{false, true} {
			if len(current.forConn(tlsMode).headerPayload) <= H2DefaultMaxFrameSize || len(current.forConn(tlsMode).framed) != 0 {
				t.Fatal("Date root crossing not in fragmented fallback")
			}
			dateRequireAt(t, dateMemoH2Fields(t, current.forConn(tlsMode)), unix)
		}
	}
	if calls.Load() != count {
		t.Fatal("large root Date refresh reran handler")
	}
}

func TestResponseDateMemoHTTPRouteEligibility(t *testing.T) {
	var clock, samples atomic.Int64
	clock.Store(1000000000)
	server, address := proxyFixStart(t, Config{InlineHandlers: true}, nil, func(server *Server) {
		server.dateNow = func() int64 { samples.Add(1); return clock.Load() }
		server.Router.GET("/", func(_ *Request, response *Response) { response.String("root") })
		server.httpRouter.Store(newHTTPRouter())
	})
	original := server.plainRootFast.Load()
	if original == nil {
		t.Fatal("fixture did not construct a root template")
	}
	samples.Store(0)
	clock.Add(1)
	response, body := proxyFixRoundTrip(t, address, proxyFixGet("example.test", "/"))
	if response.StatusCode != 200 || body != "root" {
		t.Fatalf("route fallback status=%d body=%q", response.StatusCode, body)
	}
	if samples.Load() != 0 || server.plainRootFast.Load() != original {
		t.Fatal("HTTP-route ineligible request refreshed root template")
	}
}

func TestResponseDateMemoH2InvalidDoesNotRefresh(t *testing.T) {
	var clock atomic.Int64
	clock.Store(1000000000)
	server, _ := dateMemoServer(t, &clock, "root")
	original := server.h2RootFast.Load()
	var samples atomic.Int64
	server.dateNow = func() int64 { samples.Add(1); return 1000000001 }
	connection := &epollConn{worker: &epollWorker{server: server}}
	connection.h2.decoder = newHpackDecoder(4096)
	connection.h2.maxFrameSize = H2DefaultMaxFrameSize
	if !connection.epollH2DecodedHeaders(server, 1, []byte{0xff}, true) || len(connection.writeBuf) < 9 || connection.writeBuf[3] != H2FrameGoAway {
		t.Fatal("fixture did not reach malformed header rejection")
	}
	if samples.Load() != 0 || server.h2RootFast.Load() != original {
		t.Fatal("invalid H2 request refreshed root template")
	}
}

func TestResponseDateMemoHotClockSample(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, explicit := range []bool{false, true} {
			var clock atomic.Int64
			clock.Store(1000000000)
			var headers [][2]string
			if explicit {
				headers = [][2]string{{"Date", "opaque"}}
			}
			server, _ := dateMemoServer(t, &clock, "root", headers...)
			if explicit {
				clock.Add(1)
			}
			samples := 0
			server.dateNow = func() int64 { samples++; return clock.Load() }
			if protocol == "h1" {
				original := server.plainRootFast.Load()
				if server.currentPlainRootDate(original) != original {
					t.Fatal("unchanged H1 template replaced")
				}
			} else {
				original := server.h2RootFast.Load()
				if server.currentH2RootDate(original) != original {
					t.Fatal("unchanged H2 template replaced")
				}
			}
			if samples != 1 {
				t.Fatalf("protocol=%s explicit=%v samples=%d want=1", protocol, explicit, samples)
			}
		}
	}
}
