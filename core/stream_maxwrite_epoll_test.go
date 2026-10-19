//go:build linux && amd64

package core

import (
	"io"
	"testing"
	"time"
)

func TestH2StreamMaxWriteSizeEpoll(t *testing.T) {
	const maxWrite = 1024
	addr := freeLoopbackAddr(t)
	srv := New(Config{Addr: addr, LogRequests: false, MaxConnsPerIP: -1, Listeners: 1, MaxWriteSize: maxWrite})
	results := make(chan [2]error, 1)
	srv.Router.GET("/capped", func(req *Request, resp *Response) {
		sw := resp.EnsureStreamWriter()
		if sw == nil {
			resp.Status(500).String("no stream writer")
			return
		}
		resp.SetStreamer(sw)
		var errs [2]error
		if errs[0] = sw.WriteHeader(200, nil, "application/octet-stream"); errs[0] == nil {
			errs[0] = sw.WriteChunk(make([]byte, maxWrite))
			errs[1] = sw.WriteChunk(make([]byte, 1))
		}
		_ = sw.Close()
		results <- errs
	})
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { stopServer(srv) })
	waitForProxy(t, addr)

	resp, err := h2cClient().Get("http://" + addr + "/capped")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("response over HTTP/%d, want HTTP/2", resp.ProtoMajor)
	}
	select {
	case errs := <-results:
		if errs[0] != nil {
			t.Fatalf("write within MaxWriteSize failed: %v", errs[0])
		}
		if errs[1] != ErrBodyTooLarge {
			t.Fatalf("write past MaxWriteSize returned %v, want ErrBodyTooLarge", errs[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
}
