//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	perfH2Authority       = "perf.test"
	perfH2ClientWindow    = 1<<30 - 1
	perfH2ReadBufSize     = 256 << 10
	perfH2Ceiling         = 5 * time.Second
	perfH2DialPoll        = 10 * time.Millisecond
	perfH2ShutdownGrace   = 150 * time.Millisecond
	perfH2Streams         = 100
	perfH2WarmBatches     = 3
	perfH2PlaintextBody   = "Hello, World!"
	perfH2UserID          = "12345"
	perfH2EchoBodyLen     = 1024
	perfH2Bytes64k        = 64 << 10
	perfH2Bytes1m         = 1 << 20
	perfH2BrowserUA       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	perfH2BrowserLang     = "en-US,en;q=0.9"
	perfH2BrowserSID      = "abc123def456"
	perfH2DefaultAgent    = "h2load nghttp2/1.64.0"
	perfH2FrameHeaderLen  = 9
	perfH2MaxDebugPayload = 64
)

type perfH2Field struct {
	name    string
	value   string
	noIndex bool
}

type perfH2Workload struct {
	name    string
	method  string
	path    string
	headers []perfH2Field
	body    []byte
	respLen int
}

var (
	perfH2Bytes64kBody = bytes.Repeat([]byte{'x'}, perfH2Bytes64k)
	perfH2Bytes1mBody  = bytes.Repeat([]byte{'x'}, perfH2Bytes1m)
	perfH2EchoBody     = bytes.Repeat([]byte{'a'}, perfH2EchoBodyLen)
)

func perfH2BrowserHeaders() []perfH2Field {
	return []perfH2Field{
		{name: "user-agent", value: perfH2BrowserUA},
		{name: "accept", value: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
		{name: "accept-language", value: perfH2BrowserLang},
		{name: "accept-encoding", value: "identity"},
		{name: "cache-control", value: "no-cache"},
		{name: "pragma", value: "no-cache"},
		{name: "referer", value: "https://example.com/"},
		{name: "sec-fetch-dest", value: "document"},
		{name: "sec-fetch-mode", value: "navigate"},
		{name: "sec-fetch-site", value: "none"},
		{name: "sec-fetch-user", value: "?1"},
		{name: "upgrade-insecure-requests", value: "1"},
		{name: "sec-ch-ua", value: `"Chromium";v="141", "Not?A_Brand";v="8"`},
		{name: "sec-ch-ua-mobile", value: "?0"},
		{name: "sec-ch-ua-platform", value: `"Windows"`},
		{name: "cookie", value: "sid=" + perfH2BrowserSID + "; theme=dark; lang=en"},
	}
}

func perfH2DefaultHeaders() []perfH2Field {
	return []perfH2Field{{name: "user-agent", value: perfH2DefaultAgent}}
}

var (
	perfH2W1  = perfH2Workload{name: "W1", method: "GET", path: "/plaintext", headers: perfH2DefaultHeaders(), respLen: len(perfH2PlaintextBody)}
	perfH2W1r = perfH2Workload{name: "W1r", method: "GET", path: "/", headers: perfH2DefaultHeaders(), respLen: len(perfH2PlaintextBody)}
	perfH2W3  = perfH2Workload{name: "W3", method: "GET", path: "/user/" + perfH2UserID, headers: perfH2DefaultHeaders(), respLen: len(perfH2UserID)}
	perfH2W4  = perfH2Workload{name: "W4", method: "POST", path: "/echo", headers: append(perfH2DefaultHeaders(),
		perfH2Field{name: "content-type", value: "application/octet-stream"},
		perfH2Field{name: "content-length", value: strconv.Itoa(perfH2EchoBodyLen), noIndex: true},
	), body: perfH2EchoBody, respLen: len(strconv.Itoa(perfH2EchoBodyLen))}
	perfH2W5a = perfH2Workload{name: "W5a", method: "GET", path: "/bytes/64k", headers: perfH2DefaultHeaders(), respLen: perfH2Bytes64k}
	perfH2W5b = perfH2Workload{name: "W5b", method: "GET", path: "/bytes/1m", headers: perfH2DefaultHeaders(), respLen: perfH2Bytes1m}
	perfH2W8  = perfH2Workload{name: "W8", method: "GET", path: "/browser", headers: perfH2BrowserHeaders(), respLen: len(perfH2BrowserUA + "|" + perfH2BrowserLang + "|" + perfH2BrowserSID)}
)

func perfH2Routes(srv *Server) {
	plaintext := func(req *Request, resp *Response) { resp.String(perfH2PlaintextBody) }
	srv.Router.GET("/plaintext", plaintext)
	srv.Router.GET("/", plaintext)
	srv.Router.GET("/user/:id", func(req *Request, resp *Response) { resp.String(req.ParamValue("id")) })
	srv.Router.POST("/echo", func(req *Request, resp *Response) { resp.String(strconv.Itoa(len(req.Body))) })
	srv.Router.GET("/bytes/64k", func(req *Request, resp *Response) { resp.Bytes(perfH2Bytes64kBody) })
	srv.Router.GET("/bytes/1m", func(req *Request, resp *Response) { resp.Bytes(perfH2Bytes1mBody) })
	srv.Router.GET("/browser", func(req *Request, resp *Response) {
		resp.String(req.Header("User-Agent") + "|" + req.Header("Accept-Language") + "|" + req.Cookie("sid"))
	})
}

func perfH2ServerConfig(addr string, useTLS bool) Config {
	cfg := Config{Addr: addr, PlainHTTP: !useTLS, HTTPAddr: "-", MaxConnsPerIP: -1, Listeners: 1}
	if useTLS {
		cfg.Certs = []CertConfig{{Domain: perfH2Authority, Source: CertSelfSigned}}
	}
	return cfg
}

func perfH2WaitPort(tb testing.TB, addr string) {
	tb.Helper()
	deadline := turbo.Deadline(perfH2Ceiling)
	for turbo.Until(deadline) > 0 {
		if c, err := net.DialTimeout("tcp", addr, perfH2ShutdownGrace); err == nil {
			_ = c.Close()
			return
		}
		turbo.Sleep(perfH2DialPoll)
	}
	tb.Fatalf("perf h2 server %s never came up", addr)
}

func perfH2Launch(tb testing.TB, useTLS bool) (string, *Server) {
	tb.Helper()
	addr := freeLoopbackAddr(tb)
	srv := New(perfH2ServerConfig(addr, useTLS))
	perfH2Routes(srv)
	serve := srv.ListenAndServe
	if useTLS {
		serve = srv.ListenAndServeTLS
	}
	go func() { _ = serve() }()
	perfH2WaitPort(tb, addr)
	return addr, srv
}

var perfH2Shared struct {
	mu    sync.Mutex
	addrs [2]string
}

func perfH2SharedServer(b *testing.B, useTLS bool) string {
	b.Helper()
	slot := 0
	if useTLS {
		slot = 1
	}
	perfH2Shared.mu.Lock()
	defer perfH2Shared.mu.Unlock()
	if perfH2Shared.addrs[slot] == "" {
		perfH2Shared.addrs[slot], _ = perfH2Launch(b, useTLS)
	}
	return perfH2Shared.addrs[slot]
}

func perfH2TestServer(t *testing.T, useTLS bool) string {
	t.Helper()
	addr, srv := perfH2Launch(t, useTLS)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), perfH2ShutdownGrace)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return addr
}

func perfH2StaticPair(name, value string) int {
	for i := 1; i < len(HpackStaticTable); i++ {
		if HpackStaticTable[i][0] == name && HpackStaticTable[i][1] == value {
			return i
		}
	}
	return 0
}

type perfH2BlockPair struct {
	warm   []byte
	steady []byte
}

func perfH2RequestFields(wl perfH2Workload, scheme string) []perfH2Field {
	fields := []perfH2Field{
		{name: ":method", value: wl.method},
		{name: ":scheme", value: scheme},
		{name: ":path", value: wl.path, noIndex: true},
		{name: ":authority", value: perfH2Authority},
	}
	return append(fields, wl.headers...)
}

func perfH2EncodeClientString(enc *HpackEncoder, s string) {
	if huffLen := hpackHuffmanEncodedLen(s); huffLen < len(s) {
		enc.EncodeInt(0x80, 7, uint64(huffLen))
		enc.Buf = hpackHuffmanAppend(enc.Buf, s)
		return
	}
	enc.EncodeInt(0x00, 7, uint64(len(s)))
	enc.Buf = append(enc.Buf, s...)
}

func perfH2EncodeLiteral(enc *HpackEncoder, prefix byte, prefixBits uint8, f perfH2Field) {
	if idx := hpackFindStaticName(f.name); idx > 0 {
		enc.EncodeInt(prefix, prefixBits, uint64(idx))
	} else {
		enc.EncodeInt(prefix, prefixBits, 0)
		perfH2EncodeClientString(enc, f.name)
	}
	perfH2EncodeClientString(enc, f.value)
}

func perfH2EncodeRequest(wl perfH2Workload, scheme string) perfH2BlockPair {
	fields := perfH2RequestFields(wl, scheme)
	inserted := 0
	for _, f := range fields {
		if perfH2StaticPair(f.name, f.value) == 0 && !f.noIndex {
			inserted++
		}
	}
	var warm, steady HpackEncoder
	pos := 0
	for _, f := range fields {
		if idx := perfH2StaticPair(f.name, f.value); idx > 0 {
			warm.EncodeInt(0x80, 7, uint64(idx))
			steady.EncodeInt(0x80, 7, uint64(idx))
			continue
		}
		if f.noIndex {
			perfH2EncodeLiteral(&warm, 0x00, 4, f)
			perfH2EncodeLiteral(&steady, 0x00, 4, f)
			continue
		}
		perfH2EncodeLiteral(&warm, 0x40, 6, f)
		steady.EncodeInt(0x80, 7, uint64(len(HpackStaticTable)+inserted-1-pos))
		pos++
	}
	return perfH2BlockPair{warm: warm.Buf, steady: steady.Buf}
}

type perfH2Batch struct {
	buf      []byte
	chunkLen int
	idOffs   []int
}

func perfH2BuildBatch(block []byte, body []byte, streams int) perfH2Batch {
	var chunk []byte
	idOffs := []int{5}
	headerFlags := byte(H2FlagEndHeaders)
	if len(body) == 0 {
		headerFlags |= H2FlagEndStream
	}
	chunk = appendH2Frame(chunk, H2FrameHeaders, headerFlags, 1, block)
	if len(body) > 0 {
		idOffs = append(idOffs, len(chunk)+5)
		chunk = appendH2Frame(chunk, H2FrameData, H2FlagEndStream, 1, body)
	}
	buf := make([]byte, 0, len(chunk)*streams)
	for range streams {
		buf = append(buf, chunk...)
	}
	return perfH2Batch{buf: buf, chunkLen: len(chunk), idOffs: idOffs}
}

type perfH2Client struct {
	fail    func(format string, args ...any)
	conn    net.Conn
	r       *bufio.Reader
	hdr     [perfH2FrameHeaderLen]byte
	debug   [perfH2MaxDebugPayload]byte
	nextID  uint32
	unacked int
	pending []byte
	batch   perfH2Batch
	respLen int
}

func perfH2Dial(tb testing.TB, addr string, useTLS bool) *perfH2Client {
	tb.Helper()
	raw, err := net.DialTimeout("tcp", addr, perfH2Ceiling)
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	conn := raw
	if useTLS {
		tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: perfH2Authority, NextProtos: []string{"h2"}})
		if err := tc.Handshake(); err != nil {
			_ = raw.Close()
			tb.Fatalf("tls handshake: %v", err)
		}
		if proto := tc.ConnectionState().NegotiatedProtocol; proto != "h2" {
			_ = tc.Close()
			tb.Fatalf("negotiated %q, want h2", proto)
		}
		conn = tc
	}
	cl := &perfH2Client{fail: tb.Fatalf, conn: conn, r: bufio.NewReaderSize(conn, perfH2ReadBufSize), nextID: 1}
	tb.Cleanup(func() { _ = conn.Close() })
	hello := append([]byte(nil), H2ClientPreface[:]...)
	settings := binary.BigEndian.AppendUint16(nil, H2SettingInitialWindowSize)
	settings = binary.BigEndian.AppendUint32(settings, perfH2ClientWindow)
	hello = appendH2Frame(hello, H2FrameSettings, 0, 0, settings)
	hello = appendH2WindowUpdateFrame(hello, 0, perfH2ClientWindow-H2DefaultWindowSize)
	cl.write(hello)
	for {
		typ, flags, n := cl.readHeader()
		cl.discard(n)
		if typ == H2FrameSettings && flags&H2FlagAck == 0 {
			break
		}
	}
	cl.write(appendH2SettingsAckFrame(nil))
	return cl
}

func (cl *perfH2Client) write(b []byte) {
	if _, err := cl.conn.Write(b); err != nil {
		cl.fail("write: %v", err)
	}
}

func (cl *perfH2Client) readHeader() (byte, byte, int) {
	if _, err := io.ReadFull(cl.r, cl.hdr[:]); err != nil {
		cl.fail("read frame header: %v", err)
	}
	n := int(cl.hdr[0])<<16 | int(cl.hdr[1])<<8 | int(cl.hdr[2])
	return cl.hdr[3], cl.hdr[4], n
}

func (cl *perfH2Client) discard(n int) {
	if _, err := cl.r.Discard(n); err != nil {
		cl.fail("discard %d: %v", n, err)
	}
}

func (cl *perfH2Client) failFrame(typ byte, n int) {
	got := min(n, len(cl.debug))
	_, _ = io.ReadFull(cl.r, cl.debug[:got])
	cl.fail("server sent frame type %d on stream %d: % x", typ, binary.BigEndian.Uint32(cl.hdr[5:9])&0x7fffffff, cl.debug[:got])
}

func (cl *perfH2Client) prepare(wl perfH2Workload, block []byte, streams int) {
	cl.batch = perfH2BuildBatch(block, wl.body, streams)
	cl.respLen = wl.respLen
}

func (cl *perfH2Client) roundTrip(streams int) {
	b := &cl.batch
	for i := range streams {
		for _, off := range b.idOffs {
			binary.BigEndian.PutUint32(b.buf[i*b.chunkLen+off:], cl.nextID)
		}
		cl.nextID += 2
	}
	if len(cl.pending) > 0 {
		cl.write(cl.pending)
		cl.pending = cl.pending[:0]
	}
	cl.write(b.buf[:streams*b.chunkLen])
	cl.await(streams)
}

func (cl *perfH2Client) await(streams int) {
	ended, data := 0, 0
	for ended < streams {
		typ, flags, n := cl.readHeader()
		switch typ {
		case H2FrameData:
			data += n
			cl.discard(n)
			if flags&H2FlagEndStream != 0 {
				ended++
			}
		case H2FrameHeaders:
			cl.discard(n)
			if flags&H2FlagEndStream != 0 {
				ended++
			}
		case H2FrameRSTStream, H2FrameGoAway:
			cl.failFrame(typ, n)
		default:
			cl.discard(n)
		}
	}
	if want := streams * cl.respLen; data != want {
		cl.fail("received %d DATA bytes for %d streams, want %d", data, streams, want)
	}
	cl.unacked += data
	if cl.unacked >= perfH2ClientWindow/2 {
		cl.pending = appendH2WindowUpdateFrame(cl.pending, 0, uint32(cl.unacked))
		cl.unacked = 0
	}
}

func perfH2Scheme(useTLS bool) string {
	if useTLS {
		return "https"
	}
	return "http"
}

func perfH2Ready(tb testing.TB, addr string, useTLS bool, wl perfH2Workload, streams int) *perfH2Client {
	tb.Helper()
	blocks := perfH2EncodeRequest(wl, perfH2Scheme(useTLS))
	cl := perfH2Dial(tb, addr, useTLS)
	cl.prepare(wl, blocks.warm, 1)
	cl.roundTrip(1)
	cl.prepare(wl, blocks.steady, streams)
	for range perfH2WarmBatches {
		cl.roundTrip(streams)
	}
	return cl
}

func benchPerfH2(b *testing.B, useTLS bool, wl perfH2Workload, streams int) {
	addr := perfH2SharedServer(b, useTLS)
	cl := perfH2Ready(b, addr, useTLS, wl, streams)
	b.SetBytes(int64(wl.respLen))
	b.ReportAllocs()
	b.ResetTimer()
	for done := 0; done < b.N; {
		n := min(streams, b.N-done)
		cl.roundTrip(n)
		done += n
	}
}

func benchPerfH2Matrix(b *testing.B, useTLS bool, wl perfH2Workload) {
	b.Run("streams=1", func(b *testing.B) { benchPerfH2(b, useTLS, wl, 1) })
	b.Run("streams=100", func(b *testing.B) { benchPerfH2(b, useTLS, wl, perfH2Streams) })
}

func BenchmarkPerfH2cW1Plaintext(b *testing.B)   { benchPerfH2Matrix(b, false, perfH2W1) }
func BenchmarkPerfH2cW1rRoot(b *testing.B)       { benchPerfH2Matrix(b, false, perfH2W1r) }
func BenchmarkPerfH2cW3UserParam(b *testing.B)   { benchPerfH2Matrix(b, false, perfH2W3) }
func BenchmarkPerfH2cW4Post1K(b *testing.B)      { benchPerfH2Matrix(b, false, perfH2W4) }
func BenchmarkPerfH2cW8Browser(b *testing.B)     { benchPerfH2Matrix(b, false, perfH2W8) }
func BenchmarkPerfH2cW5aBytes64K(b *testing.B)   { benchPerfH2Matrix(b, false, perfH2W5a) }
func BenchmarkPerfH2cW5bBytes1M(b *testing.B)    { benchPerfH2Matrix(b, false, perfH2W5b) }
func BenchmarkPerfH2TLSW1Plaintext(b *testing.B) { benchPerfH2Matrix(b, true, perfH2W1) }
func BenchmarkPerfH2TLSW1rRoot(b *testing.B)     { benchPerfH2Matrix(b, true, perfH2W1r) }
func BenchmarkPerfH2TLSW3UserParam(b *testing.B) { benchPerfH2Matrix(b, true, perfH2W3) }
func BenchmarkPerfH2TLSW4Post1K(b *testing.B)    { benchPerfH2Matrix(b, true, perfH2W4) }
func BenchmarkPerfH2TLSW8Browser(b *testing.B)   { benchPerfH2Matrix(b, true, perfH2W8) }
func BenchmarkPerfH2TLSW5aBytes64K(b *testing.B) { benchPerfH2Matrix(b, true, perfH2W5a) }
func BenchmarkPerfH2TLSW5bBytes1M(b *testing.B)  { benchPerfH2Matrix(b, true, perfH2W5b) }
