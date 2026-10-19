//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const wsTestIOTimeout = 2 * time.Second

var wsTestMaskKey = [4]byte{0x11, 0x22, 0x33, 0x44}

func wsClientFrame(first byte, payload []byte) []byte {
	frame := wsAppendFrameHeader(nil, first, len(payload))
	frame[1] |= 0x80
	frame = append(frame, wsTestMaskKey[:]...)
	start := len(frame)
	frame = append(frame, payload...)
	maskXOR(frame[start:], wsTestMaskKey)
	return frame
}

func wsClientDeflate(t testing.TB, msg []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(msg)
	_ = fw.Flush()
	return bytes.TrimSuffix(buf.Bytes(), wsSyncFlushMarker)
}

func wsClientInflate(t testing.TB, payload []byte) []byte {
	t.Helper()
	out, err := io.ReadAll(flate.NewReader(io.MultiReader(bytes.NewReader(payload), bytes.NewReader(wsInflateTail))))
	if err != nil {
		t.Fatalf("client inflate: %v", err)
	}
	return out
}

type wsServerFrame struct {
	first   byte
	payload []byte
}

func (f wsServerFrame) opcode() byte     { return f.first & 0x0F }
func (f wsServerFrame) compressed() bool { return f.first&wsRSV1 != 0 }

func wsReadServerFrame(r io.Reader) (wsServerFrame, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return wsServerFrame{}, err
	}
	n := uint64(hdr[1] & 0x7F)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsServerFrame{}, err
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsServerFrame{}, err
		}
		n = binary.BigEndian.Uint64(ext[:])
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return wsServerFrame{}, err
	}
	return wsServerFrame{first: hdr[0], payload: payload}, nil
}

func wsCloseCode(f wsServerFrame) uint16 {
	if f.opcode() != wsOpClose || len(f.payload) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(f.payload)
}

type wsPipe struct {
	server *WSConn
	client net.Conn
	reader *bufio.Reader
}

func newWSPipe(t *testing.T, opts WSUpgradeOptions, headers ...[2]string) *wsPipe {
	t.Helper()
	req := newTestReq()
	req.Headers = append(req.Headers, headers...)
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = serverSide.Close(); _ = clientSide.Close() })
	_ = serverSide.SetDeadline(time.Unix(0, turbo.UnixNano()+int64(wsTestIOTimeout)))
	_ = clientSide.SetDeadline(time.Unix(0, turbo.UnixNano()+int64(wsTestIOTimeout)))
	ws := newNegotiatedWSConn(req, opts)
	ws.conn = serverSide
	return &wsPipe{server: ws, client: clientSide, reader: bufio.NewReader(clientSide)}
}

func (p *wsPipe) send(t *testing.T, frames ...[]byte) {
	t.Helper()
	go func() {
		for _, f := range frames {
			if _, err := p.client.Write(f); err != nil {
				return
			}
		}
	}()
}

func (p *wsPipe) collectServerFrames() <-chan []wsServerFrame {
	out := make(chan []wsServerFrame, 1)
	go func() {
		var frames []wsServerFrame
		for {
			f, err := wsReadServerFrame(p.reader)
			if err != nil {
				out <- frames
				return
			}
			frames = append(frames, f)
		}
	}()
	return out
}

var wsDeflateOffer = [2]string{"sec-websocket-extensions", "permessage-deflate; client_max_window_bits"}

func TestWSSubprotocolSelection(t *testing.T) {
	supported := []string{"chat.v2", "chat.v1"}
	cases := []struct {
		headers [][2]string
		want    string
	}{
		{[][2]string{{"sec-websocket-protocol", "chat.v1, chat.v2"}}, "chat.v2"},
		{[][2]string{{"sec-websocket-protocol", "chat.v1"}}, "chat.v1"},
		{[][2]string{{"sec-websocket-protocol", "mqtt"}, {"Sec-WebSocket-Protocol", " chat.v1 "}}, "chat.v1"},
		{[][2]string{{"sec-websocket-protocol", "Chat.V2"}}, ""},
		{[][2]string{{"sec-websocket-protocol", "mqtt, wamp"}}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := wsSelectSubprotocol(c.headers, supported); got != c.want {
			t.Errorf("%q: selected %q, want %q", c.headers, got, c.want)
		}
	}
	if got := wsSelectSubprotocol([][2]string{{"sec-websocket-protocol", "chat.v1"}}, nil); got != "" {
		t.Errorf("no server subprotocols selected %q", got)
	}
}

func TestWSDeflateOfferNegotiation(t *testing.T) {
	cases := map[string]bool{
		"permessage-deflate":                                                         true,
		"Permessage-Deflate":                                                         true,
		"permessage-deflate; client_max_window_bits":                                 true,
		"permessage-deflate; client_max_window_bits=10":                              true,
		"permessage-deflate; client_max_window_bits=\"9\"":                           true,
		"permessage-deflate; server_no_context_takeover; client_no_context_takeover": true,
		"permessage-deflate; server_max_window_bits=15":                              true,
		"permessage-deflate; server_max_window_bits=\"15\"":                          true,
		"x-webkit-deflate-frame, permessage-deflate":                                 true,
		"permessage-deflate; server_max_window_bits=10, permessage-deflate":          true,
		"permessage-deflate; server_max_window_bits=10":                              false,
		"permessage-deflate; server_max_window_bits":                                 false,
		"permessage-deflate; client_max_window_bits=16":                              false,
		"permessage-deflate; client_max_window_bits=08":                              false,
		"permessage-deflate; client_max_window_bits=7":                               false,
		"permessage-deflate; server_no_context_takeover=1":                           false,
		"permessage-deflate; client_no_context_takeover; client_no_context_takeover": false,
		"permessage-deflate; mystery":                                                false,
		"permessage-deflate;":                                                        false,
		"x-webkit-deflate-frame":                                                     false,
		"":                                                                           false,
	}
	for offer, want := range cases {
		if got := wsClientOffersDeflate([][2]string{{"sec-websocket-extensions", offer}}); got != want {
			t.Errorf("%q: accepted=%v, want %v", offer, got, want)
		}
	}
	split := [][2]string{{"sec-websocket-extensions", "x-foo"}, {"Sec-WebSocket-Extensions", "permessage-deflate"}}
	if !wsClientOffersDeflate(split) {
		t.Error("offer in a second header line was missed")
	}
}

func TestWSNegotiatedHandshakeHeaders(t *testing.T) {
	req := newTestReq()
	req.Headers = append(req.Headers, [2]string{"sec-websocket-protocol", "graphql-ws"}, wsDeflateOffer)
	ws := newNegotiatedWSConn(req, WSUpgradeOptions{Subprotocols: []string{"graphql-ws"}, Compression: true})
	got := string(ws.appendNegotiatedHeaders(nil))
	want := "Sec-WebSocket-Protocol: graphql-ws\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n"
	if got != want || ws.Subprotocol() != "graphql-ws" || ws.compressionLevel != wsDefaultCompressionLevel {
		t.Fatalf("headers %q subprotocol %q level %d", got, ws.Subprotocol(), ws.compressionLevel)
	}
	for _, c := range []struct {
		opts    WSUpgradeOptions
		headers [][2]string
	}{
		{WSUpgradeOptions{Compression: false}, [][2]string{wsDeflateOffer}},
		{WSUpgradeOptions{Compression: true}, nil},
		{WSUpgradeOptions{Subprotocols: []string{"a"}}, [][2]string{{"sec-websocket-protocol", "b"}}},
	} {
		req := newTestReq()
		req.Headers = append(req.Headers, c.headers...)
		if got := newNegotiatedWSConn(req, c.opts).appendNegotiatedHeaders(nil); len(got) != 0 {
			t.Errorf("%+v %q: unexpected headers %q", c.opts, c.headers, got)
		}
	}
	req = newTestReq()
	req.Headers = append(req.Headers, wsDeflateOffer)
	if lvl := newNegotiatedWSConn(req, WSUpgradeOptions{Compression: true, CompressionLevel: 9}).compressionLevel; lvl != 9 {
		t.Errorf("CompressionLevel 9 became %d", lvl)
	}
	if lvl := newNegotiatedWSConn(req, WSUpgradeOptions{Compression: true, CompressionLevel: 42}).compressionLevel; lvl != wsDefaultCompressionLevel {
		t.Errorf("CompressionLevel 42 became %d", lvl)
	}
	if size := newNegotiatedWSConn(req, WSUpgradeOptions{MaxMessageSize: 1234}).MaxMessageSize; size != 1234 {
		t.Errorf("MaxMessageSize %d", size)
	}
}

func TestWSCompressedRoundTrip(t *testing.T) {
	p := newWSPipe(t, WSUpgradeOptions{Compression: true}, wsDeflateOffer)
	frames := p.collectServerFrames()
	big := []byte(strings.Repeat("compress me please ", 40))
	p.send(t,
		wsClientFrame(0x80|wsRSV1|wsOpText, wsClientDeflate(t, big)),
		wsClientFrame(0x80|wsOpBinary, []byte("raw")),
		wsClientFrame(0x80|wsRSV1|wsOpText, wsClientDeflate(t, []byte("second message, fresh window"))),
	)
	for i, want := range [][]byte{big, []byte("raw"), []byte("second message, fresh window")} {
		op, msg, err := p.server.ReadMessage()
		if err != nil || !bytes.Equal(msg, want) {
			t.Fatalf("message %d: op %d err %v got %q", i, op, err, msg)
		}
		if err := p.server.WriteMessage(op, msg); err != nil {
			t.Fatal(err)
		}
	}
	_ = p.server.Close()
	got := <-frames
	if len(got) != 4 {
		t.Fatalf("server sent %d frames, want 3 echoes and a close", len(got))
	}
	if !got[0].compressed() || !bytes.Equal(wsClientInflate(t, got[0].payload), big) || len(got[0].payload) >= len(big) {
		t.Errorf("large echo: compressed=%v, %d bytes", got[0].compressed(), len(got[0].payload))
	}
	if got[1].compressed() || string(got[1].payload) != "raw" {
		t.Errorf("small echo should be sent uncompressed: %+v", got[1])
	}
	if got[3].opcode() != wsOpClose || got[3].compressed() {
		t.Errorf("close frame %+v", got[3])
	}
}

func TestWSCompressedFragmentsAndEmptyFirstFragment(t *testing.T) {
	p := newWSPipe(t, WSUpgradeOptions{Compression: true}, wsDeflateOffer)
	go func() { _, _ = io.Copy(io.Discard, p.reader) }()
	msg := []byte(strings.Repeat("fragmented and compressed ", 20))
	compressed := wsClientDeflate(t, msg)
	third := len(compressed) / 3
	p.send(t,
		wsClientFrame(wsRSV1|wsOpText, compressed[:third]),
		wsClientFrame(0x80|wsOpPing, []byte("mid")),
		wsClientFrame(wsOpContinuation, compressed[third:2*third]),
		wsClientFrame(0x80|wsOpContinuation, compressed[2*third:]),
		wsClientFrame(wsOpText, nil),
		wsClientFrame(0x80|wsOpContinuation, []byte("after an empty first fragment")),
	)
	if _, got, err := p.server.ReadMessage(); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("fragmented compressed message: err %v, %q", err, got)
	}
	if _, got, err := p.server.ReadMessage(); err != nil || string(got) != "after an empty first fragment" {
		t.Fatalf("empty first fragment: err %v, %q", err, got)
	}
}

func TestWSDeflateBlocksAfterFinalBlock(t *testing.T) {
	first, second := []byte(strings.Repeat("alpha ", 30)), []byte(strings.Repeat("alpha beta ", 30))
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = fw.Write(first)
	_ = fw.Close()
	fw2, _ := flate.NewWriterDict(&buf, flate.BestCompression, first)
	_, _ = fw2.Write(second)
	_ = fw2.Flush()
	payload := bytes.TrimSuffix(buf.Bytes(), wsSyncFlushMarker)
	got, status := wsInflate(payload, 1<<20)
	if status != 0 || !bytes.Equal(got, append(append([]byte(nil), first...), second...)) {
		t.Fatalf("status %d, %d bytes", status, len(got))
	}
}

func TestWSRSVViolations(t *testing.T) {
	cases := []struct {
		name  string
		opts  WSUpgradeOptions
		frame []byte
	}{
		{"rsv1-without-negotiation", WSUpgradeOptions{}, wsClientFrame(0x80|wsRSV1|wsOpText, []byte("x"))},
		{"rsv1-on-ping", WSUpgradeOptions{Compression: true}, wsClientFrame(0x80|wsRSV1|wsOpPing, nil)},
		{"rsv2", WSUpgradeOptions{Compression: true}, wsClientFrame(0x80|0x20|wsOpText, []byte("x"))},
		{"rsv1-on-continuation", WSUpgradeOptions{Compression: true}, append(wsClientFrame(wsOpText, []byte("a")), wsClientFrame(0x80|wsRSV1|wsOpContinuation, []byte("b"))...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newWSPipe(t, c.opts, wsDeflateOffer)
			go func() { _, _ = io.Copy(io.Discard, p.reader) }()
			p.send(t, c.frame)
			if _, _, err := p.server.ReadMessage(); !errors.Is(err, ErrWebSocketProtocol) {
				t.Fatalf("err %v, want ErrWebSocketProtocol", err)
			}
		})
	}
	p := newWSPipe(t, WSUpgradeOptions{Compression: true}, wsDeflateOffer)
	frames := p.collectServerFrames()
	p.send(t, wsClientFrame(0x80|wsRSV1|wsOpBinary, []byte{0xff, 0xff, 0xff, 0xff, 0xff}))
	if _, _, err := p.server.ReadMessage(); !errors.Is(err, ErrWebSocketProtocol) {
		t.Fatalf("corrupt deflate data: err %v", err)
	}
	if got := <-frames; len(got) != 1 || wsCloseCode(got[0]) != wsStatusInvalidPayload {
		t.Fatalf("corrupt deflate data: server frames %+v, want one close 1007", got)
	}
}

func TestWSDeflateBomb(t *testing.T) {
	const inflatedSize = 100 << 20
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = fw.Write(make([]byte, inflatedSize))
	_ = fw.Flush()
	bomb := bytes.TrimSuffix(buf.Bytes(), wsSyncFlushMarker)
	if len(bomb) > 128<<10 {
		t.Fatalf("bomb is %d bytes", len(bomb))
	}
	p := newWSPipe(t, WSUpgradeOptions{Compression: true, MaxMessageSize: 1 << 20}, wsDeflateOffer)
	frames := p.collectServerFrames()
	frame := wsClientFrame(0x80|wsRSV1|wsOpBinary, bomb)
	start := turbo.Now()
	p.send(t, frame)
	_, msg, err := p.server.ReadMessage()
	elapsed := turbo.Since(start)
	if !errors.Is(err, ErrBodyTooLarge) || msg != nil {
		t.Fatalf("err %v, %d bytes", err, len(msg))
	}
	if elapsed > 150*time.Millisecond {
		t.Errorf("bomb took %v to reject", elapsed)
	}
	if got := <-frames; len(got) != 1 || wsCloseCode(got[0]) != wsStatusMessageTooBig {
		t.Fatalf("server frames %+v, want exactly one close 1009", got)
	}
}

func TestWSOversizeFrameClosesWith1009Once(t *testing.T) {
	p := newWSPipe(t, WSUpgradeOptions{MaxMessageSize: 16})
	frames := p.collectServerFrames()
	p.send(t, wsClientFrame(0x80|wsOpBinary, make([]byte, 17)))
	if _, _, err := p.server.ReadMessage(); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("err %v", err)
	}
	if got := <-frames; len(got) != 1 || wsCloseCode(got[0]) != wsStatusMessageTooBig {
		t.Fatalf("server frames %+v, want exactly one close 1009", got)
	}
}

func TestWSCloseEchoSentOnce(t *testing.T) {
	p := newWSPipe(t, WSUpgradeOptions{})
	frames := p.collectServerFrames()
	p.send(t, wsClientFrame(0x80|wsOpClose, []byte{0x03, 0xe8, 'b', 'y', 'e'}))
	if _, _, err := p.server.ReadMessage(); err != io.EOF {
		t.Fatalf("err %v", err)
	}
	_ = p.server.Close()
	if got := <-frames; len(got) != 1 || wsCloseCode(got[0]) != 1000 {
		t.Fatalf("server frames %+v, want exactly one close 1000", got)
	}
}

func BenchmarkWSWriteCompressed(b *testing.B) {
	msg := []byte(strings.Repeat(`{"type":"update","id":42,"payload":"abcdefgh"}`, 20))
	for _, level := range []int{0, flate.BestSpeed} {
		b.Run("level-"+string(rune('0'+level)), func(b *testing.B) {
			serverSide, clientSide := net.Pipe()
			defer serverSide.Close()
			defer clientSide.Close()
			go func() { _, _ = io.Copy(io.Discard, clientSide) }()
			ws := &WSConn{conn: serverSide, compressionLevel: level}
			b.SetBytes(int64(len(msg)))
			b.ReportAllocs()
			for b.Loop() {
				_ = ws.WriteMessage(wsOpText, msg)
			}
		})
	}
}

func FuzzPermessageDeflate(f *testing.F) {
	f.Add([]byte("hello hello hello hello"), []byte{0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00})
	f.Add([]byte{}, []byte{0x00})
	f.Add(bytes.Repeat([]byte{0}, 4096), []byte{0xff, 0xff})
	const limit = 1 << 16
	f.Fuzz(func(t *testing.T, plain, raw []byte) {
		if len(plain) <= limit {
			level := flate.BestSpeed + len(plain)%flate.BestCompression
			got, status := wsInflate(wsDeflate(nil, plain, level), limit)
			if status != 0 || !bytes.Equal(got, plain) {
				t.Fatalf("round trip at level %d: status %d, %d bytes for %d", level, status, len(got), len(plain))
			}
		}
		got, status := wsInflate(append([]byte(nil), raw...), limit)
		if status == 0 && len(got) > limit {
			t.Fatalf("inflated %d bytes past the %d limit", len(got), limit)
		}
		if status != 0 && got != nil {
			t.Fatalf("status %d with output", status)
		}
	})
}
