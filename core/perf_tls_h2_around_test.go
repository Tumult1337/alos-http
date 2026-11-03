//go:build linux && amd64

package core

import (
	"bytes"
	"io"
	"strconv"
	"testing"
)

func perfTLSAroundBody(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>9)
	}
	return b
}

func TestPerfTLSH2DataSealedAroundBodyMatches(t *testing.T) {
	sizes := []int{
		h2DirectSealMinBody,
		h2SealedDataMax*2 - 1,
		h2SealedDataMax * 2,
		h2SealedDataMax*3 + 7,
		70000,
		256 << 10,
	}
	ts := newTestServer(t, testServerOptions{TLS: true, Routes: func(r *Router) {
		r.GET("/around/:n", func(req *Request, resp *Response) {
			n, _ := strconv.Atoi(req.ParamValue("n"))
			resp.Bytes(perfTLSAroundBody(n))
		})
	}})
	cl := ts.client(t, "h2")
	for round := 0; round < 2; round++ {
		for _, n := range sizes {
			resp, err := cl.Get(ts.url("/around/" + strconv.Itoa(n)))
			if err != nil {
				t.Fatalf("size %d: %v", n, err)
			}
			got, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatalf("size %d: read: %v", n, err)
			}
			if resp.ProtoMajor != 2 {
				t.Fatalf("size %d: proto %s, want HTTP/2", n, resp.Proto)
			}
			if !bytes.Equal(got, perfTLSAroundBody(n)) {
				t.Fatalf("size %d: body mismatch (got %d bytes)", n, len(got))
			}
		}
	}
}
