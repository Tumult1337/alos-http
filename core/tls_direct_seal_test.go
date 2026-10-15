//go:build linux && amd64

package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestTLSDirectSealMatchesFrozenBaseBuilder(t *testing.T) {
	cs := &SupportedSuites[1]
	secret := bytes.Repeat([]byte{5}, cs.HashLen)
	for _, method := range []string{"GET", "HEAD"} {
		for _, size := range []int{0, 100, 16383, 16384, 16385, 40000, 100000} {
			for _, text := range []bool{false, true} {
				body := bytes.Repeat([]byte{'q'}, size)
				req := &Request{Method: method}
				var c epollConn
				c.tls = true
				c.appWriter, _ = NewTrafficAEAD(cs.HashFn, secret, cs)
				if text {
					c.resp.Status(200).String(string(body))
				} else {
					c.resp.Status(200).Bytes(body)
				}
				c.resp.lazyReq = req
				c.writeBuf = []byte("prefix")
				c.h1WriteResponse(true)
				ref, _ := NewTrafficAEAD(cs.HashFn, secret, cs)
				want := baseBuildTLSAppDataRecords([]byte("prefix"), ref, appendPlainResponseMode(&c.resp, nil, true, true))
				if !bytes.Equal(c.writeBuf, want) {
					t.Fatalf("method=%s size=%d text=%v: sealed output differs (got %d want %d bytes)", method, size, text, len(c.writeBuf), len(want))
				}
				var c2 epollConn
				c2.tls = true
				c2.appWriter, _ = NewTrafficAEAD(cs.HashFn, secret, cs)
				c2.resp = c.resp
				out := c2.h1AppendResponse([]byte("PENDING"), false)
				c2.h1OutEnd(out)
				ref2, _ := NewTrafficAEAD(cs.HashFn, secret, cs)
				want2 := baseBuildTLSAppDataRecords(nil, ref2, appendPlainResponseMode(&c.resp, []byte("PENDING"), false, true))
				if !bytes.Equal(c2.writeBuf, want2) {
					t.Fatalf("inline method=%s size=%d text=%v: sealed output differs", method, size, text)
				}
			}
		}
	}
}

func baseBuildTLSAppDataRecords(dst []byte, writer *TrafficAEAD, payload []byte) []byte {
	if writer == nil {
		return dst
	}
	const maxContent = MaxRecordPayload - 1
	if len(payload) == 0 {
		return dst
	}
	records := (len(payload) + maxContent - 1) / maxContent
	dst = ensureTailCap(dst, len(payload)+records*(tlsRecordHeaderLen+1+writer.Overhead()))
	scratch := acquirePooledBuf(&tlsScratchPool)
	if cap(scratch) < MaxRecordPayload {
		scratch = make([]byte, 0, MaxRecordPayload)
	}
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > maxContent {
			chunk = chunk[:maxContent]
		}
		payload = payload[len(chunk):]
		inner := scratch[:len(chunk)+1]
		copy(inner, chunk)
		inner[len(chunk)] = 0x17
		dst = appendTLSInnerRecord(dst, writer, inner)
	}
	releasePooledBuf(&tlsScratchPool, scratch, MaxRecordSize)
	return dst
}

func TestTLS12LargeResponseBodyIsComplete(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	srv := New(Config{
		Addr: addr, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1, Listeners: 1,
		Certs: []CertConfig{{Domain: "tls12.test", Source: CertSelfSigned}},
	})
	bodies := map[string][]byte{}
	for name, size := range map[string]int{"/16k": 16 << 10, "/64k": 64 << 10} {
		body := make([]byte, size)
		for i := range body {
			body[i] = byte(i * 7)
		}
		bodies[name] = body
		srv.Router.GET(name, func(req *Request, resp *Response) { resp.Status(200).Bytes(body) })
	}
	go func() { _ = srv.ListenAndServeTLS() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	waitForProxy(t, addr)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "tls12.test", MaxVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for path, want := range bodies {
		for rep := 0; rep < 3; rep++ {
			resp, err := client.Get("https://" + addr + path)
			if err != nil {
				t.Fatalf("%s rep %d: %v", path, rep, err)
			}
			if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS12 {
				t.Fatalf("%s rep %d: connection is not TLS 1.2", path, rep)
			}
			got, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatalf("%s rep %d: read body: %v", path, rep, err)
			}
			if resp.StatusCode != 200 || !bytes.Equal(got, want) {
				t.Fatalf("%s rep %d: status=%d len=%d want %d", path, rep, resp.StatusCode, len(got), len(want))
			}
		}
	}
}
