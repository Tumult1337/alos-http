//go:build linux && amd64

package core

import (
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	quicFixH3FrameUnexpected      = 0x0105
	quicFixRepeatedBlocks         = 64
	quicFixAdvertisedFieldSection = 16384
)

type quicFixH3Routes struct {
	okHits     atomic.Int32
	adminHits  atomic.Int32
	fieldCount atomic.Int32
	trailers   atomic.Value
}

func (r *quicFixH3Routes) route(router *Router) {
	router.GET("/ok", func(req *Request, resp *Response) {
		r.okHits.Add(1)
		r.fieldCount.Store(int32(len(req.Headers)))
		resp.Status(200).String("ok")
	})
	router.GET("/public", func(req *Request, resp *Response) {
		resp.Status(200).String("public")
	})
	router.GET("/admin", func(req *Request, resp *Response) {
		r.adminHits.Add(1)
		resp.Status(200).String("admin")
	})
	router.POST("/upload", func(req *Request, resp *Response) {
		var names []string
		for _, f := range req.Trailers() {
			names = append(names, f[0]+"="+f[1])
		}
		r.trailers.Store(strings.Join(names, ","))
		resp.Status(200).String(strconv.Itoa(len(req.Body)))
	})
}

func quicFixQPACKBlock(fields ...[2]string) []byte {
	var enc QPACKEncoder
	enc.encodeRequiredInsertCount()
	for _, f := range fields {
		enc.EncodeHeader(f[0], f[1])
	}
	return enc.Bytes()
}

func quicFixGET(path string, extra ...[2]string) []byte {
	fields := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "a.test"}, {":path", path}}
	return quicFixQPACKBlock(append(fields, extra...)...)
}

func quicFixStreamData(p *quicTestPeer, streamID uint64) []byte {
	var frames []quicStreamFrame
	for _, f := range p.sent().streams {
		if f.streamID == streamID {
			frames = append(frames, f)
		}
	}
	sort.Slice(frames, func(a, b int) bool { return frames[a].offset < frames[b].offset })
	var data []byte
	for _, f := range frames {
		if end := f.offset + uint64(len(f.data)); end > uint64(len(data)) {
			data = append(data[:f.offset], f.data...)
		}
	}
	return data
}

func quicFixResponseStatus(t *testing.T, p *quicTestPeer, streamID uint64) int {
	t.Helper()
	p.awaitFin(streamID)
	reader := h3FrameReader{data: quicFixStreamData(p, streamID)}
	frameType, payload, ok := reader.next()
	if !ok || frameType != h3FrameHeaders {
		t.Fatalf("stream %d response does not start with HEADERS", streamID)
	}
	var dec QPACKDecoder
	fields, err := dec.Decode(payload)
	if err != nil {
		t.Fatalf("decode response headers: %v", err)
	}
	for _, f := range fields {
		if f[0] == ":status" {
			code, convErr := strconv.Atoi(f[1])
			if convErr != nil {
				t.Fatalf("bad :status %q", f[1])
			}
			return code
		}
	}
	t.Fatalf("response has no :status: %v", fields)
	return 0
}

func quicFixSendRequest(p *quicTestPeer, streamID uint64, frames ...[]byte) {
	var data []byte
	for _, f := range frames {
		data = append(data, f...)
	}
	p.send(quicStreamBytes(streamID, 0, data, true))
}

func TestQUICFixH3RejectsMalformedRequestFields(t *testing.T) {
	routes := &quicFixH3Routes{}
	p := newQUICFixPeer(t, routes.route)
	base := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "a.test"}}
	withPath := func(path string, extra ...[2]string) [][2]string {
		return append(append(append([][2]string(nil), base...), [2]string{":path", path}), extra...)
	}
	cases := []struct {
		name   string
		fields [][2]string
	}{
		{"CRLF in a header value", withPath("/ok", [2]string{"x-a", "1\r\n\r\nGET /smuggled HTTP/1.1\r\nhost: a.test"})},
		{"LF in a header value", withPath("/ok", [2]string{"x-a", "1\nx-b: 2"})},
		{"NUL in a header value", withPath("/ok", [2]string{"x-a", "1\x002"})},
		{"leading space in a value", withPath("/ok", [2]string{"x-a", " 1"})},
		{"uppercase header name", withPath("/ok", [2]string{"X-Upper", "1"})},
		{"empty header name", withPath("/ok", [2]string{"", "1"})},
		{"connection header", withPath("/ok", [2]string{"connection", "close"})},
		{"transfer-encoding header", withPath("/ok", [2]string{"transfer-encoding", "chunked"})},
		{"te other than trailers", withPath("/ok", [2]string{"te", "gzip"})},
		{"unknown pseudo-header", withPath("/ok", [2]string{":foo", "bar"})},
		{"duplicate :path", withPath("/ok", [2]string{":path", "/admin"})},
		{"pseudo-header after a regular field", append(append([][2]string(nil), base[:2]...), [2]string{"x-a", "1"}, [2]string{":authority", "a.test"}, [2]string{":path", "/ok"})},
		{"missing :scheme", [][2]string{{":method", "GET"}, {":authority", "a.test"}, {":path", "/ok"}}},
		{"space in :method", [][2]string{{":method", "GET /admin HTTP/1.1\r\nx:"}, {":scheme", "https"}, {":authority", "a.test"}, {":path", "/ok"}}},
		{"non-token :method", [][2]string{{":method", "G(ET"}, {":scheme", "https"}, {":authority", "a.test"}, {":path", "/ok"}}},
		{"empty :path", withPath("")},
		{"relative :path", withPath("ok")},
		{"space in the query", withPath("/ok?a=1 HTTP/1.1")},
		{"tab in the path", withPath("/ok\tx")},
		{"DEL in the query", withPath("/ok?a=\x7f")},
		{"asterisk :path for GET", withPath("*")},
		{"bad :authority", [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "a.test/../x"}, {":path", "/ok"}}},
		{"conflicting content-length", withPath("/ok", [2]string{"content-length", "1"}, [2]string{"content-length", "2"})},
	}
	for i, tc := range cases {
		streamID := uint64(i * 4)
		quicFixSendRequest(p, streamID, h3AppendHeadersFrame(nil, quicFixQPACKBlock(tc.fields...)))
		if got := quicFixResponseStatus(t, p, streamID); got != 400 {
			t.Errorf("%s: status %d, want 400", tc.name, got)
		}
	}
	if hits := routes.okHits.Load() + routes.adminHits.Load(); hits != 0 {
		t.Fatalf("%d malformed requests reached a handler", hits)
	}
}

func TestQUICFixH3ValidRequestStillServed(t *testing.T) {
	routes := &quicFixH3Routes{}
	p := newQUICFixPeer(t, routes.route)
	block := quicFixGET("/ok?x=1", [2]string{"te", "trailers"}, [2]string{"user-agent", "quic-fix"})
	for i := uint64(0); i < 3; i++ {
		quicFixSendRequest(p, i*4, h3AppendHeadersFrame(nil, block))
		if got := quicFixResponseStatus(t, p, i*4); got != 200 {
			t.Fatalf("request %d: status %d, want 200", i, got)
		}
	}
	if got := routes.okHits.Load(); got != 3 {
		t.Fatalf("handler ran %d times, want 3", got)
	}
	if got := routes.fieldCount.Load(); got != 2 {
		t.Fatalf("handler saw %d regular fields, want 2", got)
	}
}

func TestQUICFixH3RepeatedHeaderBlockCannotInflateFields(t *testing.T) {
	routes := &quicFixH3Routes{}
	p := newQUICFixPeer(t, routes.route)
	fields := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "a.test"}, {":path", "/ok"}}
	for i := 0; i < 100; i++ {
		fields = append(fields, [2]string{"x-filler", "v"})
	}
	headers := h3AppendHeadersFrame(nil, quicFixQPACKBlock(fields...))
	quicFixSendRequest(p, 0, headers)
	if got := quicFixResponseStatus(t, p, 0); got != 200 {
		t.Fatalf("priming request: status %d, want 200", got)
	}
	var repeated []byte
	for i := 0; i < quicFixRepeatedBlocks; i++ {
		repeated = append(repeated, headers...)
	}
	routes.okHits.Store(0)
	p.send(quicStreamBytes(4, 0, repeated, true))
	if got := quicFixResponseStatus(t, p, 4); got != 400 {
		t.Errorf("status %d, want 400 for a repeated request header section", got)
	}
	if got := routes.okHits.Load(); got != 0 {
		t.Fatalf("a stream of %d cached HEADERS blocks reached the handler with %d fields", quicFixRepeatedBlocks, routes.fieldCount.Load())
	}
}

func TestQUICFixH3OversizedFieldSectionRejected(t *testing.T) {
	routes := &quicFixH3Routes{}
	p := newQUICFixPeer(t, routes.route)
	big := strings.Repeat("v", quicFixAdvertisedFieldSection/4)
	block := quicFixGET("/ok", [2]string{"x-a", big}, [2]string{"x-b", big}, [2]string{"x-c", big}, [2]string{"x-d", big})
	quicFixSendRequest(p, 0, h3AppendHeadersFrame(nil, block))
	if got := quicFixResponseStatus(t, p, 0); got != 431 {
		t.Fatalf("status %d, want 431", got)
	}
	if routes.okHits.Load() != 0 {
		t.Fatal("an oversized field section reached the handler")
	}
}

func TestQUICFixH3TrailersCannotOverrideTarget(t *testing.T) {
	routes := &quicFixH3Routes{}
	p := newQUICFixPeer(t, routes.route)
	quicFixSendRequest(p, 0,
		h3AppendHeadersFrame(nil, quicFixGET("/public")),
		h3AppendDataFrame(nil, nil),
		h3AppendHeadersFrame(nil, quicFixQPACKBlock([2]string{":path", "/admin"}, [2]string{":method", "GET"})))
	if got := quicFixResponseStatus(t, p, 0); got != 400 {
		t.Fatalf("status %d, want 400 for pseudo-headers in trailers", got)
	}
	if routes.adminHits.Load() != 0 {
		t.Fatal("trailing HEADERS rerouted the request to /admin")
	}
}

func TestQUICFixH3TrailersDeliveredSeparately(t *testing.T) {
	routes := &quicFixH3Routes{}
	p := newQUICFixPeer(t, routes.route)
	head := quicFixQPACKBlock([2]string{":method", "POST"}, [2]string{":scheme", "https"}, [2]string{":authority", "a.test"}, [2]string{":path", "/upload"}, [2]string{"content-length", "5"})
	quicFixSendRequest(p, 0,
		h3AppendHeadersFrame(nil, head),
		h3AppendDataFrame(nil, []byte("hello")),
		h3AppendHeadersFrame(nil, quicFixQPACKBlock([2]string{"x-checksum", "abc"})))
	if got := quicFixResponseStatus(t, p, 0); got != 200 {
		t.Fatalf("status %d, want 200", got)
	}
	if got, _ := routes.trailers.Load().(string); got != "x-checksum=abc" {
		t.Fatalf("handler trailers %q, want x-checksum=abc", got)
	}
}

func TestQUICFixH3ContentLengthMismatchRejected(t *testing.T) {
	routes := &quicFixH3Routes{}
	p := newQUICFixPeer(t, routes.route)
	head := quicFixQPACKBlock([2]string{":method", "POST"}, [2]string{":scheme", "https"}, [2]string{":authority", "a.test"}, [2]string{":path", "/upload"}, [2]string{"content-length", "10"})
	quicFixSendRequest(p, 0, h3AppendHeadersFrame(nil, head), h3AppendDataFrame(nil, []byte("abc")))
	if got := quicFixResponseStatus(t, p, 0); got != 400 {
		t.Fatalf("status %d, want 400 when DATA (3) disagrees with content-length (10)", got)
	}
}

func TestQUICFixH3HeadersAfterTrailersIsFrameUnexpected(t *testing.T) {
	p := newQUICFixPeer(t, (&quicFixH3Routes{}).route)
	trailers := h3AppendHeadersFrame(nil, quicFixQPACKBlock([2]string{"x-checksum", "abc"}))
	quicFixSendRequest(p, 0, h3AppendHeadersFrame(nil, quicFixGET("/ok")), trailers, trailers)
	p.awaitClose(quicFixH3FrameUnexpected)
}

func TestQUICFixH3DataBeforeHeadersIsFrameUnexpected(t *testing.T) {
	p := newQUICFixPeer(t, (&quicFixH3Routes{}).route)
	quicFixSendRequest(p, 0, h3AppendDataFrame(nil, []byte("x")), h3AppendHeadersFrame(nil, quicFixGET("/ok")))
	p.awaitClose(quicFixH3FrameUnexpected)
}

func TestQUICFixQPACKRejectsDynamicTableReferences(t *testing.T) {
	cases := []struct {
		name  string
		block []byte
	}{
		{"non-zero required insert count", []byte{0x01, 0x00, 0xC0 | 17}},
		{"negative base", []byte{0x00, 0x80, 0xC0 | 17}},
		{"indexed dynamic reference", []byte{0x00, 0x00, 0x80}},
		{"literal with dynamic name reference", []byte{0x00, 0x00, 0x40, 0x01, 'x'}},
		{"indexed post-base reference", []byte{0x00, 0x00, 0x10}},
		{"literal with post-base name reference", []byte{0x00, 0x00, 0x00, 0xC0 | 17}},
	}
	var dec QPACKDecoder
	for _, tc := range cases {
		fields, err := dec.Decode(tc.block)
		if err == nil {
			t.Errorf("%s: decoded %q without error, want QPACK decompression failure", tc.name, fields)
		}
	}
	fields, err := dec.Decode(quicFixGET("/ok"))
	if err != nil || len(fields) != 4 {
		t.Fatalf("static-only block: fields=%q err=%v", fields, err)
	}
}

func TestQUICFixHPACKSizeUpdateOnlyAtBlockStart(t *testing.T) {
	const (
		indexedMethodGET = 0x82
		indexedPathRoot  = 0x84
		indexedHTTPS     = 0x87
		sizeUpdateZero   = 0x20
	)
	late := []byte{indexedMethodGET, sizeUpdateZero, indexedHTTPS, indexedPathRoot}
	early := []byte{sizeUpdateZero, indexedMethodGET, indexedHTTPS, indexedPathRoot}
	if _, err := NewHpackDecoder().DecodeInto(nil, late); err == nil {
		t.Error("DecodeInto accepted a dynamic table size update after a field line")
	}
	if _, _, err := NewHpackDecoder().DecodeIntoRequest(nil, late); err == nil {
		t.Error("DecodeIntoRequest accepted a dynamic table size update after a field line")
	}
	if _, err := NewHpackDecoder().DecodeRequestMeta(late); err == nil {
		t.Error("DecodeRequestMeta accepted a dynamic table size update after a field line")
	}
	if _, err := NewHpackDecoder().DecodeInto(nil, early); err != nil {
		t.Errorf("DecodeInto rejected a leading size update: %v", err)
	}
	if _, err := NewHpackDecoder().DecodeRequestMeta(early); err != nil {
		t.Errorf("DecodeRequestMeta rejected a leading size update: %v", err)
	}
}

func TestQUICFixH3ResponseHeadersFilteredAndDeduplicated(t *testing.T) {
	headers := [][2]string{
		{"Connection", "close"},
		{"Keep-Alive", "timeout=5"},
		{"Transfer-Encoding", "chunked"},
		{"Upgrade", "h2c"},
		{"Content-Length", "5"},
		{"Content-Type", "text/html"},
		{"Server", "custom"},
		{"Server", "second"},
		{"X-Kept", "yes"},
	}
	bp := qpackEncodeResponseHeaders(200, "text/plain", 5, headers, "alos")
	var dec QPACKDecoder
	fields, err := dec.Decode(*bp)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	values := map[string]string{}
	for _, f := range fields {
		counts[f[0]]++
		values[f[0]] = f[1]
	}
	for _, banned := range []string{"connection", "keep-alive", "transfer-encoding", "upgrade"} {
		if counts[banned] != 0 {
			t.Errorf("connection-specific field %q forwarded on HTTP/3", banned)
		}
	}
	for _, single := range []string{"content-length", "content-type", "server"} {
		if counts[single] != 1 {
			t.Errorf("%q emitted %d times, want 1", single, counts[single])
		}
	}
	if values["server"] != "custom" || values["content-type"] != "text/plain" || values["x-kept"] != "yes" {
		t.Errorf("unexpected values: server=%q content-type=%q x-kept=%q", values["server"], values["content-type"], values["x-kept"])
	}
	plain := qpackEncodeResponseHeaders(200, "", -1, [][2]string{{"Content-Type", "a/b"}, {"Content-Type", "c/d"}, {"Content-Length", "3"}}, "alos")
	fields, err = dec.Decode(*plain)
	if err != nil {
		t.Fatal(err)
	}
	counts = map[string]int{}
	for _, f := range fields {
		counts[f[0]]++
	}
	if counts["content-type"] != 1 || counts["content-length"] != 1 || counts["server"] != 1 {
		t.Errorf("handler-only headers: counts %v, want one content-type, content-length and server", counts)
	}
}
