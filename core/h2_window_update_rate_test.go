//go:build linux && amd64

package core

import (
	"io"
	"strconv"
	"strings"
	"testing"
)

const (
	floodTestStreamedBytes   = 64 << 20
	bufferedUnderCapBytes    = 10 << 20
	bufferedOverCapBytes     = 48 << 20
	enhanceYourCalmErrorText = "ENHANCE_YOUR_CALM"
)

func TestH2FastClientWindowUpdatesAreNotTreatedAsAFlood(t *testing.T) {
	addr := startStreamServer(t, true, nil)
	status, sum, n, proto := fetchStreamSum(t, h2TLSClient(), "https://"+addr+"/stream/"+strconv.Itoa(floodTestStreamedBytes))
	if proto != "HTTP/2.0" || status != 200 || n != floodTestStreamedBytes || sum != streamPatternSum(floodTestStreamedBytes) {
		t.Fatalf("proto=%s status=%d bytes=%d", proto, status, n)
	}
}

func bufferedBodyServer(t *testing.T, size int) string {
	t.Helper()
	addr := freeLoopbackAddr(t)
	srv := New(Config{
		Addr: addr, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1, Listeners: 1,
		Certs: []CertConfig{{Domain: "stream.test", Source: CertSelfSigned}},
	})
	body := make([]byte, size)
	srv.Router.GET("/big", func(req *Request, resp *Response) { resp.Status(200).Bytes(body) })
	go func() { _ = srv.ListenAndServeTLS() }()
	t.Cleanup(func() { stopServer(srv) })
	waitForProxy(t, addr)
	return addr
}

func TestH2BufferedBodyLargerThanTheStreamWindowIsDeliveredIntact(t *testing.T) {
	addr := bufferedBodyServer(t, bufferedUnderCapBytes)
	resp, err := h2TLSClient().Get("https://" + addr + "/big")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || n != bufferedUnderCapBytes || resp.ProtoMajor != 2 {
		t.Fatalf("proto=%s bytes=%d err=%v, want %d bytes over HTTP/2", resp.Proto, n, err, bufferedUnderCapBytes)
	}
}

func TestH2BufferedBodyOverThePendingCapIsResetCleanly(t *testing.T) {
	addr := bufferedBodyServer(t, bufferedOverCapBytes)
	cl := h2TLSClient()
	resp, err := cl.Get("https://" + addr + "/big")
	if err == nil {
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), enhanceYourCalmErrorText) {
		t.Fatalf("err=%v, want a stream reset with %s (a TLS record error means a frame went out unencrypted)", err, enhanceYourCalmErrorText)
	}
	small, err := cl.Get("https://" + addr + "/missing")
	if err != nil {
		t.Fatalf("the connection did not survive the reset of one stream: %v", err)
	}
	small.Body.Close()
}
