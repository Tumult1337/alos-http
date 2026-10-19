//go:build linux && amd64

package core

import (
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

	"github.com/guno1928/turbo"
)

const (
	upstreamSlowChunkPause = 50 * time.Millisecond
	upstreamSlowChunks     = 12
	upstreamShortTimeout   = 300 * time.Millisecond
)

func bodySumOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{Protocols: protocols, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reject" {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		h := sha256.New()
		n, err := io.Copy(h, r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "%s %d %d %s %s", r.Proto, r.ContentLength, n, strings.Join(r.TransferEncoding, ","), hex.EncodeToString(h.Sum(nil)))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func wantOriginSum(proto string, declared int64, size int, transferEncoding string) string {
	sum := streamPatternSum(size)
	return fmt.Sprintf("%s %d %d %s %s", proto, declared, size, transferEncoding, hex.EncodeToString(sum[:]))
}

func TestUpstreamStreamsTheRequestBody(t *testing.T) {
	origin := bodySumOrigin(t)
	client := newTimeoutClient(t)
	sizes := []int{0, 1, 64 << 10, 10 << 20}
	if !testing.Short() {
		sizes = append(sizes, 1<<30)
	}
	for _, tc := range []struct {
		name  string
		h2    bool
		known bool
	}{{"h1-content-length", false, true}, {"h1-chunked", false, false}, {"h2-content-length", true, true}, {"h2-unknown-length", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, size := range sizes {
				req := &UpstreamRequest{Scheme: "http", Authority: origin, Method: "POST", Path: "/sum", H2: tc.h2, BodySource: &patternReader{size: size}}
				declared, te, proto := int64(-1), "chunked", "HTTP/1.1"
				if tc.known && size > 0 {
					req.BodyLength = int64(size)
					declared, te = int64(size), ""
				}
				if tc.h2 {
					proto, te = "HTTP/2.0", ""
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("size=%d: %v", size, err)
				}
				if want := wantOriginSum(proto, declared, size, te); resp.Status != 200 || string(resp.Body) != want {
					t.Fatalf("size=%d: status=%d body=%q want %q", size, resp.Status, resp.Body, want)
				}
			}
		})
	}
}

type countingReader struct {
	r    io.Reader
	read atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read.Add(int64(n))
	return n, err
}

func TestUpstreamOriginRejectingEarlyStopsTheUpload(t *testing.T) {
	origin := bodySumOrigin(t)
	client := newTimeoutClient(t)
	const size = 256 << 20
	for _, h2 := range []bool{false, true} {
		src := &countingReader{r: &patternReader{size: size}}
		start := turbo.Now()
		resp, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: origin, Method: "POST", Path: "/reject", H2: h2, BodySource: src, BodyLength: size})
		if took := turbo.Since(start); took > streamTestTimeout {
			t.Fatalf("h2=%v: the rejected upload took %v", h2, took)
		}
		if err == nil && resp.Status != http.StatusRequestEntityTooLarge {
			t.Fatalf("h2=%v: status=%d, want 413", h2, resp.Status)
		}
		if read := src.read.Load(); read >= size {
			t.Fatalf("h2=%v: the whole %d byte body was read although the origin refused it", h2, read)
		}
	}
}

type failingReader struct {
	ok  int
	err error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.ok <= 0 {
		return 0, f.err
	}
	n := min(len(p), f.ok)
	f.ok -= n
	return n, nil
}

func TestUpstreamBodySourceFailureFailsTheExchange(t *testing.T) {
	origin := bodySumOrigin(t)
	client := newTimeoutClient(t)
	sourceErr := errors.New("client went away")
	for _, h2 := range []bool{false, true} {
		_, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: origin, Method: "POST", Path: "/sum", H2: h2, BodySource: &failingReader{ok: 1 << 20, err: sourceErr}})
		if !errors.Is(err, errFPBodySource) {
			t.Fatalf("h2=%v: err=%v, want errFPBodySource", h2, err)
		}
	}
}

func TestUpstreamBodyShorterThanItsDeclaredLengthFails(t *testing.T) {
	origin := bodySumOrigin(t)
	client := newTimeoutClient(t)
	_, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: origin, Method: "POST", Path: "/sum", BodySource: &patternReader{size: 1000}, BodyLength: 2000})
	if !errors.Is(err, errFPBodySource) {
		t.Fatalf("err=%v, want errFPBodySource", err)
	}
}

type pacedReader struct {
	chunks int
}

func (p *pacedReader) Read(b []byte) (int, error) {
	if p.chunks == 0 {
		return 0, io.EOF
	}
	p.chunks--
	turbo.Sleep(upstreamSlowChunkPause)
	n := min(len(b), 1024)
	for i := range b[:n] {
		b[i] = 'x'
	}
	return n, nil
}

func TestUpstreamSlowUploadMakingProgressOutlivesTheRequestTimeout(t *testing.T) {
	origin := bodySumOrigin(t)
	client, err := NewUpstreamClient(UpstreamConfig{Loops: 1, RequestTimeout: upstreamShortTimeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	for _, h2 := range []bool{false, true} {
		resp, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: origin, Method: "POST", Path: "/sum", H2: h2, BodySource: &pacedReader{chunks: upstreamSlowChunks}})
		if err != nil {
			t.Fatalf("h2=%v: an upload that kept making progress failed: %v", h2, err)
		}
		if !strings.Contains(string(resp.Body), " "+strconv.Itoa(upstreamSlowChunks*1024)+" ") {
			t.Fatalf("h2=%v: body=%q", h2, resp.Body)
		}
	}
}

func TestUpstreamH2BodyFailureLeavesOtherStreamsAlive(t *testing.T) {
	origin := bodySumOrigin(t)
	client := newTimeoutClient(t)
	healthy := make(chan error, 1)
	go func() {
		resp, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: origin, Method: "POST", Path: "/sum", H2: true, BodySource: &pacedReader{chunks: upstreamSlowChunks / 2}})
		if err == nil && resp.Status != http.StatusOK {
			err = fmt.Errorf("status %d", resp.Status)
		}
		healthy <- err
	}()
	turbo.Sleep(upstreamSlowChunkPause)
	_, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: origin, Method: "POST", Path: "/sum", H2: true, BodySource: &failingReader{ok: 64 << 10, err: errors.New("client went away")}})
	if !errors.Is(err, errFPBodySource) {
		t.Fatalf("failing upload: err=%v, want errFPBodySource", err)
	}
	if err := <-healthy; err != nil {
		t.Fatalf("the healthy upload sharing the connection failed: %v", err)
	}
}
