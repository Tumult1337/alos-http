//go:build linux && amd64

package core

import (
	"crypto/sha256"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/guno1928/turbo"
)

const openBigBody = 256 << 20

func patternOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{Protocols: protocols, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		size, _ := strconv.Atoi(parts[len(parts)-1])
		if parts[0] == "fixed" {
			w.Header().Set("Content-Length", strconv.Itoa(size))
		}
		w.Header().Set("X-Origin", "pattern")
		buf := make([]byte, streamChunk)
		for off := 0; off < size; {
			n := min(len(buf), size-off)
			fillStreamPattern(buf[:n], off)
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			off += n
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func openAndSum(t *testing.T, client *UpstreamClient, req *UpstreamRequest) (int, string, int64, [32]byte) {
	t.Helper()
	resp, body, err := client.Open(req)
	if err != nil {
		t.Fatalf("Open %s: %v", req.Path, err)
	}
	defer body.Close()
	h := sha256.New()
	n, err := io.Copy(h, body)
	if err != nil {
		t.Fatalf("reading %s: %v", req.Path, err)
	}
	var sum [32]byte
	h.Sum(sum[:0])
	origin := ""
	for _, hd := range resp.Headers {
		if strings.EqualFold(hd[0], "x-origin") {
			origin = hd[1]
		}
	}
	return resp.Status, origin, n, sum
}

func TestUpstreamOpenStreamsTheResponse(t *testing.T) {
	origin := patternOrigin(t)
	client := newTimeoutClient(t)
	sizes := []int{0, 1, 64 << 10, 10 << 20}
	if !testing.Short() {
		sizes = append(sizes, 1<<30)
	}
	for _, tc := range []struct {
		name  string
		route string
		h2    bool
	}{{"h1-content-length", "fixed", false}, {"h1-chunked", "chunked", false}, {"h2", "fixed", true}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, size := range sizes {
				if tc.h2 && size > 10<<20 {
					continue
				}
				status, hdr, n, sum := openAndSum(t, client, &UpstreamRequest{Scheme: "http", Authority: origin, Path: "/" + tc.route + "/" + strconv.Itoa(size), H2: tc.h2})
				if status != 200 || hdr != "pattern" || n != int64(size) || sum != streamPatternSum(size) {
					t.Fatalf("size=%d: status=%d header=%q bytes=%d checksum ok=%v", size, status, hdr, n, sum == streamPatternSum(size))
				}
			}
		})
	}
}

func TestUpstreamOpenBoundsBufferedBytesForASlowReader(t *testing.T) {
	origin := patternOrigin(t)
	client := newTimeoutClient(t)
	_, body, err := client.Open(&UpstreamRequest{Scheme: "http", Authority: origin, Path: "/fixed/" + strconv.Itoa(openBigBody)})
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	limit := respPipeHighMark + loopScratchSize
	buffered := plateauOf(func() int64 {
		body.pipe.mu.Lock()
		defer body.pipe.mu.Unlock()
		return int64(len(body.pipe.buf) - body.pipe.off)
	}, int64(limit))
	if buffered > int64(limit) {
		t.Fatalf("%d bytes buffered for a reader that is not reading, want at most %d", buffered, limit)
	}
	n, err := io.Copy(io.Discard, body)
	if err != nil || n != openBigBody {
		t.Fatalf("draining after the stall: n=%d err=%v", n, err)
	}
}

func TestUpstreamOpenStalledReaderDoesNotBlockOtherExchanges(t *testing.T) {
	origin := patternOrigin(t)
	client := newTimeoutClient(t)
	_, stalled, err := client.Open(&UpstreamRequest{Scheme: "http", Authority: origin, Path: "/fixed/" + strconv.Itoa(openBigBody)})
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	start := turbo.Now()
	status, _, n, sum := openAndSum(t, client, &UpstreamRequest{Scheme: "http", Authority: origin, Path: "/fixed/" + strconv.Itoa(10<<20)})
	if status != 200 || n != 10<<20 || sum != streamPatternSum(10<<20) {
		t.Fatalf("status=%d bytes=%d", status, n)
	}
	if took := turbo.Since(start); took > streamTestTimeout {
		t.Fatalf("a second download on the same loop took %v while another reader was stalled", took)
	}
}

func TestUpstreamOpenCloseEarlyAbortsAndKeepsTheClientUsable(t *testing.T) {
	origin := patternOrigin(t)
	client := newTimeoutClient(t)
	_, body, err := client.Open(&UpstreamRequest{Scheme: "http", Authority: origin, Path: "/fixed/" + strconv.Itoa(openBigBody)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(io.Discard, body, 1<<20); err != nil {
		t.Fatal(err)
	}
	body.Close()
	if _, err := body.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read after Close returned data")
	}
	status, _, n, _ := openAndSum(t, client, &UpstreamRequest{Scheme: "http", Authority: origin, Path: "/fixed/1024"})
	if status != 200 || n != 1024 {
		t.Fatalf("follow-up request after an aborted download: status=%d bytes=%d", status, n)
	}
}

func TestUpstreamOpenReportsDialFailure(t *testing.T) {
	client := newTimeoutClient(t)
	addr := refusedLoopbackAddr(t)
	if _, _, err := client.Open(&UpstreamRequest{Scheme: "http", Authority: addr, Path: "/"}); err == nil {
		t.Fatal("Open succeeded against a closed port")
	}
}
