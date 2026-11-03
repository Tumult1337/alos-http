//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"strconv"
	"testing"
)

const (
	perfTLSPlaintextBody = "Hello, World!"
	perfTLSUserID        = "12345"
	perfTLSBody64K       = 64 << 10
	perfTLSBody1M        = 1 << 20
	perfTLSClientBufSize = 64 << 10
)

var (
	perfTLSBytes64K = bytes.Repeat([]byte{'k'}, perfTLSBody64K)
	perfTLSBytes1M  = bytes.Repeat([]byte{'m'}, perfTLSBody1M)
)

func perfTLSRoutes(r *Router) {
	r.GET("/plaintext", func(req *Request, resp *Response) { resp.Status(200).String(perfTLSPlaintextBody) })
	r.GET("/user/:id", func(req *Request, resp *Response) { resp.Status(200).String(req.ParamValue("id")) })
	r.GET("/bytes/64k", func(req *Request, resp *Response) { resp.Status(200).Bytes(perfTLSBytes64K) })
	r.GET("/bytes/1m", func(req *Request, resp *Response) { resp.Status(200).Bytes(perfTLSBytes1M) })
}

func perfTLSQuietLogs(b *testing.B) {
	prevOut := log.Writer()
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(prevOut) })
}

func perfTLSServer(b *testing.B) *testServer {
	perfTLSQuietLogs(b)
	return newTestServer(b, testServerOptions{TLS: true, Routes: perfTLSRoutes})
}

func perfTLSClientConfig(ts *testServer, version uint16) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ts.domain,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         version,
		MaxVersion:         version,
		CurvePreferences:   []tls.CurveID{tls.X25519},
	}
}

var perfContentLengthPrefix = []byte("content-length:")

func perfReadResponseBodyLen(br *bufio.Reader) (int, error) {
	bodyLen := -1
	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			return 0, err
		}
		if len(line) <= 2 {
			break
		}
		if len(line) > len(perfContentLengthPrefix) && bytes.EqualFold(line[:len(perfContentLengthPrefix)], perfContentLengthPrefix) {
			n, perr := strconv.Atoi(string(bytes.TrimSpace(line[len(perfContentLengthPrefix):])))
			if perr != nil {
				return 0, perr
			}
			bodyLen = n
		}
	}
	if bodyLen < 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if _, err := br.Discard(bodyLen); err != nil {
		return 0, err
	}
	return bodyLen, nil
}

func perfTLSRoundTrip(b *testing.B, version uint16, path string, wantBody int) {
	ts := perfTLSServer(b)
	conn, err := tls.Dial("tcp4", ts.addr, perfTLSClientConfig(ts, version))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	request := []byte("GET " + path + " HTTP/1.1\r\nHost: " + ts.domain + "\r\n\r\n")
	br := bufio.NewReaderSize(conn, perfTLSClientBufSize)
	exchange := func() {
		if _, err := conn.Write(request); err != nil {
			b.Fatal(err)
		}
		got, err := perfReadResponseBodyLen(br)
		if err != nil {
			b.Fatal(err)
		}
		if got != wantBody {
			b.Fatalf("body %d bytes, want %d", got, wantBody)
		}
	}
	for i := 0; i < 4; i++ {
		exchange()
	}
	b.SetBytes(int64(wantBody))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exchange()
	}
}

func BenchmarkPerfTLS13RoundTripW1(b *testing.B) {
	perfTLSRoundTrip(b, tls.VersionTLS13, "/plaintext", len(perfTLSPlaintextBody))
}

func BenchmarkPerfTLS13RoundTripW3(b *testing.B) {
	perfTLSRoundTrip(b, tls.VersionTLS13, "/user/"+perfTLSUserID, len(perfTLSUserID))
}

func BenchmarkPerfTLS13RoundTripW5a64K(b *testing.B) {
	perfTLSRoundTrip(b, tls.VersionTLS13, "/bytes/64k", perfTLSBody64K)
}

func BenchmarkPerfTLS13RoundTripW5b1M(b *testing.B) {
	perfTLSRoundTrip(b, tls.VersionTLS13, "/bytes/1m", perfTLSBody1M)
}

func BenchmarkPerfTLS12RoundTripW1(b *testing.B) {
	perfTLSRoundTrip(b, tls.VersionTLS12, "/plaintext", len(perfTLSPlaintextBody))
}

func BenchmarkPerfTLS12RoundTripW3(b *testing.B) {
	perfTLSRoundTrip(b, tls.VersionTLS12, "/user/"+perfTLSUserID, len(perfTLSUserID))
}

func BenchmarkPerfTLS12RoundTripW5a64K(b *testing.B) {
	perfTLSRoundTrip(b, tls.VersionTLS12, "/bytes/64k", perfTLSBody64K)
}

func BenchmarkPerfTLS12RoundTripW5b1M(b *testing.B) {
	perfTLSRoundTrip(b, tls.VersionTLS12, "/bytes/1m", perfTLSBody1M)
}

func perfTLSChurn(b *testing.B, version uint16, curve tls.CurveID) {
	ts := perfTLSServer(b)
	cfg := perfTLSClientConfig(ts, version)
	cfg.CurvePreferences = []tls.CurveID{curve}
	request := []byte("GET /plaintext HTTP/1.1\r\nHost: " + ts.domain + "\r\nConnection: close\r\n\r\n")
	br := bufio.NewReaderSize(nil, perfTLSClientBufSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		raw, err := net.Dial("tcp4", ts.addr)
		if err != nil {
			b.Fatal(err)
		}
		conn := tls.Client(raw, cfg)
		if _, err := conn.Write(request); err != nil {
			b.Fatal(err)
		}
		br.Reset(conn)
		if got, err := perfReadResponseBodyLen(br); err != nil || got != len(perfTLSPlaintextBody) {
			b.Fatalf("body %d bytes, err %v", got, err)
		}
		_ = conn.Close()
	}
}

func BenchmarkPerfTLS13ChurnW10X25519(b *testing.B) {
	perfTLSChurn(b, tls.VersionTLS13, tls.X25519)
}

func BenchmarkPerfTLS13ChurnW10P256(b *testing.B) {
	perfTLSChurn(b, tls.VersionTLS13, tls.CurveP256)
}

func BenchmarkPerfTLS12ChurnW10X25519(b *testing.B) {
	perfTLSChurn(b, tls.VersionTLS12, tls.X25519)
}
