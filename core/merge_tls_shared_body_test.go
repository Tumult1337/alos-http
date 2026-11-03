//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	mergeSharedBodyLen   = 256<<10 + 7
	mergeSharedConns     = 8
	mergeSharedRequests  = 12
	mergeSharedListeners = 4
	mergeSharedIOCeiling = 20 * time.Second
)

func mergeSharedPattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31) ^ seed
	}
	return b
}

func mergeReadResponseBody(br *bufio.Reader) ([]byte, error) {
	bodyLen := -1
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(name, "content-length") {
			n, perr := strconv.Atoi(strings.TrimSpace(value))
			if perr != nil {
				return nil, perr
			}
			bodyLen = n
		}
	}
	if bodyLen < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, bodyLen)
	_, err := io.ReadFull(br, body)
	return body, err
}

func TestMergeTLSSharedBodiesStayExactAcrossConnections(t *testing.T) {
	shared := mergeSharedPattern(mergeSharedBodyLen, 0x5a)
	sharedWant := bytes.Clone(shared)
	cachedSource := mergeSharedPattern(mergeSharedBodyLen, 0xa5)
	owned := mergeSharedPattern(mergeSharedBodyLen, 0x3c)
	ts := newTestServer(t, testServerOptions{
		TLS:    true,
		Config: func(cfg *Config) { cfg.Listeners = mergeSharedListeners },
		Routes: func(r *Router) {
			r.GET("/nocopy", func(req *Request, resp *Response) { resp.Status(200).BytesNoCopy(shared) })
			r.GET("/cached", Chain(func(req *Request, resp *Response) {
				resp.Status(200).Bytes(cachedSource)
			}, Cache(CacheConfig{TTL: time.Minute, MaxBodyBytes: 2 * mergeSharedBodyLen})))
			r.GET("/owned", func(req *Request, resp *Response) { resp.Status(200).Bytes(owned) })
		},
	})
	cases := []struct {
		path string
		want []byte
	}{
		{"/nocopy", sharedWant},
		{"/cached", cachedSource},
		{"/owned", owned},
	}
	var wg sync.WaitGroup
	errs := make(chan error, mergeSharedConns)
	for i := 0; i < mergeSharedConns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := tls.Dial("tcp4", ts.addr, perfTLSClientConfig(ts, tls.VersionTLS13))
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Unix(0, turbo.UnixNano()+int64(mergeSharedIOCeiling)))
			br := bufio.NewReader(conn)
			for n := 0; n < mergeSharedRequests; n++ {
				c := cases[(id+n)%len(cases)]
				if _, err := conn.Write([]byte("GET " + c.path + " HTTP/1.1\r\nHost: " + ts.domain + "\r\n\r\n")); err != nil {
					errs <- err
					return
				}
				body, err := mergeReadResponseBody(br)
				if err != nil {
					errs <- fmt.Errorf("conn %d request %d %s: %w", id, n, c.path, err)
					return
				}
				if !bytes.Equal(body, c.want) {
					errs <- fmt.Errorf("conn %d request %d %s: body differs from the source (len %d)", id, n, c.path, len(body))
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if !bytes.Equal(shared, sharedWant) {
		t.Fatal("the shared BytesNoCopy buffer was modified by the server")
	}
}

func TestMergeTLSMutableSealOnlyForOwnedBodies(t *testing.T) {
	big := mergeSharedPattern(mergeSharedBodyLen, 1)
	var resp Response
	resp.Bytes(big)
	if !resp.ownsBodyBuffer(resp.bodyBytesUnsafe()) {
		t.Fatal("a copied Bytes body must take the mutable seal fast path")
	}
	if !resp.ownsBodyBuffer(resp.bodyBytesUnsafe()[4096:8192]) {
		t.Fatal("a progressive chunk of a copied body must take the mutable seal fast path")
	}
	if resp.ownsBodyBuffer(big) {
		t.Fatal("a caller buffer that is not the response's own body was treated as owned")
	}
	resp.Reset()
	resp.BytesNoCopy(big)
	if resp.ownsBodyBuffer(resp.bodyBytesUnsafe()) {
		t.Fatal("a BytesNoCopy body must use the copying seal")
	}
	resp.Reset()
	resp.referenceBody(big)
	if resp.ownsBodyBuffer(resp.bodyBytesUnsafe()) {
		t.Fatal("a cache-hit body must use the copying seal")
	}
	resp.Reset()
	resp.setBodyNoCopy(big, "text/plain")
	resp.fileBody = true
	if resp.ownsBodyBuffer(resp.bodyBytesUnsafe()) {
		t.Fatal("a static-cache body must use the copying seal")
	}
	resp.Reset()
	resp.String(string(big))
	if resp.ownsBodyBuffer(resp.bodyBytesUnsafe()) {
		t.Fatal("a string body must use the copying seal")
	}
}
