//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
)

var gateReqBrowser = []byte("GET /dashboard/shop?tab=orders&page=2 HTTP/1.1\r\n" +
	"Host: alos.gg\r\n" +
	"Connection: keep-alive\r\n" +
	"sec-ch-ua: \"Chromium\";v=\"141\", \"Google Chrome\";v=\"141\", \"Not?A_Brand\";v=\"99\"\r\n" +
	"sec-ch-ua-mobile: ?0\r\n" +
	"sec-ch-ua-platform: \"Windows\"\r\n" +
	"Upgrade-Insecure-Requests: 1\r\n" +
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36\r\n" +
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n" +
	"Sec-Fetch-Site: same-origin\r\n" +
	"Sec-Fetch-Mode: navigate\r\n" +
	"Sec-Fetch-User: ?1\r\n" +
	"Sec-Fetch-Dest: document\r\n" +
	"Referer: https://alos.gg/dashboard\r\n" +
	"Accept-Encoding: gzip, deflate, br, zstd\r\n" +
	"Accept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\n" +
	"Cookie: session=4f9c2a7e1b8d4c6aa0e3f5b7c9d1e2f4; theme=dark; lang=en; consent=1\r\n" +
	"Priority: u=0, i\r\n" +
	"If-None-Match: \"5d8c72a5edda8d6a\"\r\n" +
	"\r\n")

var gateH2BrowserHeaders = [][2]string{
	{":method", "GET"},
	{":scheme", "https"},
	{":authority", "alos.gg"},
	{":path", "/dashboard/shop?tab=orders&page=2"},
	{"sec-ch-ua", "\"Chromium\";v=\"141\", \"Google Chrome\";v=\"141\", \"Not?A_Brand\";v=\"99\""},
	{"sec-ch-ua-mobile", "?0"},
	{"sec-ch-ua-platform", "\"Windows\""},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"},
	{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
	{"sec-fetch-site", "same-origin"},
	{"sec-fetch-mode", "navigate"},
	{"sec-fetch-user", "?1"},
	{"sec-fetch-dest", "document"},
	{"referer", "https://alos.gg/dashboard"},
	{"accept-encoding", "gzip, deflate, br, zstd"},
	{"accept-language", "en-GB,en-US;q=0.9,en;q=0.8"},
	{"cookie", "session=4f9c2a7e1b8d4c6aa0e3f5b7c9d1e2f4; theme=dark; lang=en; consent=1"},
	{"priority", "u=0, i"},
}

func gateParseH1(b *testing.B, raw []byte) {
	req := &Request{Headers: make([][2]string, 0, 32)}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for i := 0; i < b.N; i++ {
		req.resetFastH1()
		if _, _, _, _, _, _, _, ok := ParseH1RequestHead(raw, req, 8192, 128); !ok {
			b.Fatal("parse failed")
		}
	}
}

func BenchmarkGateH1ParseTypical(b *testing.B) { gateParseH1(b, benchReqTypical) }

func BenchmarkGateH1ParseBrowser(b *testing.B) { gateParseH1(b, gateReqBrowser) }

func BenchmarkGateH1ParsePost(b *testing.B) { gateParseH1(b, benchReqPost) }

func BenchmarkGateRouterStatic(b *testing.B) {
	router := benchRouter()
	req := &Request{Headers: make([][2]string, 0, 16)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchH = router.Lookup("GET", "/api/products/buy", req)
	}
}

func BenchmarkGateRouterParam(b *testing.B) {
	router := NewRouter()
	h := func(req *Request, resp *Response) {}
	router.GET("/route/:id", h)
	router.GET("/users/:uid/orders/:oid", h)
	router.GET("/static/*filepath", h)
	router.Build()
	req := &Request{Headers: make([][2]string, 0, 16)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchH = router.Lookup("GET", "/users/42/orders/9001", req)
	}
}

func BenchmarkGateHPACKDecodeRequest(b *testing.B) {
	var enc HpackEncoder
	for _, h := range gateH2BrowserHeaders {
		enc.EncodeHeader(h[0], h[1])
	}
	block := enc.Buf
	dec := NewHpackDecoder()
	headers := make([][2]string, 0, 32)
	b.ReportAllocs()
	b.SetBytes(int64(len(block)))
	for i := 0; i < b.N; i++ {
		out, _, err := dec.DecodeRequest(headers[:0], block)
		if err != nil {
			b.Fatal(err)
		}
		headers = out
	}
}

func BenchmarkGateQUICShortOpen(b *testing.B) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	keys, _, err := quicDeriveInitialKeys(dcid)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1100)
	for i := range payload {
		payload[i] = byte(i)
	}
	const pn = 1000
	packet := quicBuildShortPacket(nil, dcid, payload, pn, pn-1, keys, 0)
	scratch := make([]byte, len(packet))
	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	for i := 0; i < b.N; i++ {
		copy(scratch, packet)
		hdr, perr := quicParseShortHeader(scratch, len(dcid))
		if perr != nil {
			b.Fatal(perr)
		}
		if _, derr := quicDecryptPacket(scratch, &hdr, keys, pn-1); derr != nil {
			b.Fatal(derr)
		}
	}
}

func BenchmarkGateTLS13HandshakeLoopback(b *testing.B) {
	prevOut := log.Writer()
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(prevOut) })
	ts := newTestServer(b, testServerOptions{TLS: true})
	cfg := &tls.Config{
		InsecureSkipVerify: true, ServerName: ts.domain, NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		raw, err := net.Dial("tcp4", ts.addr)
		if err != nil {
			b.Fatal(err)
		}
		c := tls.Client(raw, cfg)
		if err := c.Handshake(); err != nil {
			b.Fatal(err)
		}
		_ = c.Close()
	}
}

func BenchmarkGateTLS12Seal(b *testing.B) { BenchmarkTLS12SealRecord(b) }

func BenchmarkGateTLS12Open(b *testing.B) { BenchmarkTLS12OpenRecord(b) }

func BenchmarkGateProxySerialize(b *testing.B) { BenchmarkProxyRequestSerialize(b) }

func BenchmarkGateProxyResponseHead(b *testing.B) { BenchmarkProxyResponseHead(b) }

func BenchmarkGateCacheHit(b *testing.B) {
	body := strings.Repeat("c", 2048)
	handler := Cache(CacheConfig{})(func(req *Request, resp *Response) {
		resp.Status(200).HTML(body)
	})
	req := &Request{Method: "GET", Host: "alos.gg", Path: "/cached", Headers: make([][2]string, 0, 8)}
	resp := &Response{}
	handler(req, resp)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.resetFastH1()
		handler(req, resp)
	}
}

func BenchmarkGateFullPipelineH1(b *testing.B) {
	router := benchRouter()
	req := &Request{Headers: make([][2]string, 0, 32)}
	resp := &Response{}
	body := strings.Repeat("p", 20<<10)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req.resetFastH1()
		ParseH1RequestHead(gateReqBrowser, req, 8192, 128)
		benchH = router.Lookup("GET", req.Path, req)
		resp.resetFastH1()
		resp.HTML(body)
		benchSink = appendPlainResponse(resp, benchBuf[:0])
	}
}

func gateTLS13Writer(b *testing.B) *TrafficAEAD {
	cs := &SupportedSuites[1]
	w, err := NewTrafficAEAD(cs.HashFn, bytes.Repeat([]byte{5}, cs.HashLen), cs)
	if err != nil {
		b.Fatal(err)
	}
	return w
}

func gateTLS13Seal(b *testing.B, size int) {
	w := gateTLS13Writer(b)
	msg := bytes.Repeat([]byte{'x'}, size)
	dst := make([]byte, 0, size+64)
	b.ReportAllocs()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		dst = w.EncryptAppend(dst[:0], msg)
	}
}

func gateTLS13Open(b *testing.B, size int) {
	w, r := gateTLS13Writer(b), gateTLS13Writer(b)
	record := w.EncryptAppend(nil, bytes.Repeat([]byte{'x'}, size))
	scratch := make([]byte, len(record))
	b.ReportAllocs()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		copy(scratch, record)
		r.seq = 0
		if _, err := r.Decrypt(scratch); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGateTLS13Seal64(b *testing.B) { gateTLS13Seal(b, 64) }

func BenchmarkGateTLS13Seal512(b *testing.B) { gateTLS13Seal(b, 512) }

func BenchmarkGateTLS13Seal16383(b *testing.B) { gateTLS13Seal(b, 16383) }

func BenchmarkGateTLS13Open64(b *testing.B) { gateTLS13Open(b, 64) }

func BenchmarkGateTLS13Open512(b *testing.B) { gateTLS13Open(b, 512) }

func gateParsePromoteH1(b *testing.B, raw []byte) {
	req := &Request{Headers: make([][2]string, 0, 32)}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for i := 0; i < b.N; i++ {
		req.resetFastH1()
		end, _, _, _, _, _, _, ok := ParseH1RequestHead(raw, req, 8192, 128)
		if !ok {
			b.Fatal("parse failed")
		}
		req.Host = req.cachedHost
		promoteRequestHead(req, raw[:end])
	}
}

var gateReqCurl = []byte("GET /hello HTTP/1.1\r\nHost: alos.gg\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n")

func BenchmarkGateH1PromoteCurl(b *testing.B) { gateParsePromoteH1(b, gateReqCurl) }

func BenchmarkGateH1PromoteTypical(b *testing.B) { gateParsePromoteH1(b, benchReqTypical) }

func BenchmarkGateH1PromoteBrowser(b *testing.B) { gateParsePromoteH1(b, gateReqBrowser) }

func gateTLSResponse(b *testing.B, size int, tls12 bool) {
	var c epollConn
	c.tls = true
	c.worker = &epollWorker{}
	if tls12 {
		w, _ := newTestTLS12Pair(b)
		c.tls12 = &tls12State{writer: w}
	} else {
		c.appWriter = gateTLS13Writer(b)
	}
	body := bytes.Repeat([]byte{'r'}, size)
	req := &Request{Method: "GET"}
	b.ReportAllocs()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		c.resp.resetFastH1()
		c.resp.lazyReq = req
		c.resp.Status(200).Bytes(body)
		c.writeBuf = c.writeBuf[:0]
		c.h1WriteResponse(true)
	}
}

func BenchmarkGateTLSResp13_1K(b *testing.B) { gateTLSResponse(b, 1<<10, false) }

func BenchmarkGateTLSResp13_16K(b *testing.B) { gateTLSResponse(b, 16<<10, false) }

func BenchmarkGateTLSResp13_64K(b *testing.B) { gateTLSResponse(b, 64<<10, false) }

func BenchmarkGateTLSResp13_256K(b *testing.B) { gateTLSResponse(b, 256<<10, false) }

func BenchmarkGateTLSResp12_16K(b *testing.B) { gateTLSResponse(b, 16<<10, true) }

func BenchmarkGateTLSResp12_32K(b *testing.B) { gateTLSResponse(b, 32<<10, true) }

func BenchmarkGateTLSResp12_64K(b *testing.B) { gateTLSResponse(b, 64<<10, true) }

type gateCountingConn struct {
	net.Conn
	read int
}

func (c *gateCountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read += n
	return n, err
}

func gateAsyncPipelined(b *testing.B, depth int) {
	prevOut := log.Writer()
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(prevOut) })
	ts := newTestServer(b, testServerOptions{Routes: func(r *Router) {
		r.GET("/hello", func(req *Request, resp *Response) { resp.Status(200).String("hello") })
	}})
	request := []byte("GET /hello HTTP/1.1\r\nHost: alos.gg\r\n\r\n")
	probe, err := net.Dial("tcp4", ts.addr)
	if err != nil {
		b.Fatal(err)
	}
	counted := &gateCountingConn{Conn: probe}
	if _, err := probe.Write(request); err != nil {
		b.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(counted), nil)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	_ = probe.Close()
	responseLen := counted.read
	batch := bytes.Repeat(request, depth)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		conn, err := net.Dial("tcp4", ts.addr)
		if err != nil {
			b.Error(err)
			return
		}
		defer conn.Close()
		in := make([]byte, responseLen*depth)
		rounds := 0
		for pb.Next() {
			rounds++
			if _, err := conn.Write(batch); err != nil {
				b.Error(err)
				return
			}
			if _, err := io.ReadFull(conn, in); err != nil {
				b.Error(err)
				return
			}
		}
		if rounds > 0 && !bytes.HasSuffix(in, []byte("hello")) {
			b.Errorf("pipelined responses lost framing: %q", in[max(0, len(in)-80):])
		}
	})
}

func BenchmarkGateH1AsyncPipelined1(b *testing.B) { gateAsyncPipelined(b, 1) }

func BenchmarkGateH1AsyncPipelined16(b *testing.B) { gateAsyncPipelined(b, 16) }

func BenchmarkGateResponseHeaders(b *testing.B) {
	r := benchResp(strings.Repeat("h", 4096))
	r.SetHeaderUnsafe("Cache-Control", "no-store")
	r.SetHeaderUnsafe("X-Request-Id", "4f9c2a7e1b8d4c6a")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = appendPlainResponseHeaders(r, benchBuf[:0])
	}
}
