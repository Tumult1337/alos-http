//go:build linux && amd64

package core

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/turbo"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WSOriginMode controls how UpgradeWebSocket validates the Origin header to
// prevent Cross-Site WebSocket Hijacking. WSOriginSameOrigin is the default
// (the zero value): cross-site handshakes carrying an Origin are rejected.
// WSOriginAllowlist checks against WebSocketAllowedOrigins. WSOriginOff disables
// the check entirely and must be selected explicitly.
type WSOriginMode int

const (
	// WSOriginSameOrigin rejects handshakes whose Origin host differs from
	// the request Host. It is the zero value and default.
	WSOriginSameOrigin WSOriginMode = iota
	// WSOriginAllowlist accepts only origins listed in WebSocketAllowedOrigins.
	WSOriginAllowlist
	// WSOriginOff disables Origin checking entirely.
	WSOriginOff
)

func wsOriginHost(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 && strings.IndexByte(s, ']') < i {
		s = s[:i]
	}
	return strings.ToLower(s)
}

func checkWebSocketOrigin(req *Request) bool {
	var mode WSOriginMode
	var allowed []string
	if req.server != nil {
		mode = req.server.config.WebSocketOriginMode
		allowed = req.server.config.WebSocketAllowedOrigins
	}
	if mode == WSOriginOff {
		return true
	}
	origin := req.Header("origin")
	if origin == "" {
		return true
	}
	switch mode {
	case WSOriginSameOrigin:
		return wsOriginHost(origin) == wsOriginHost(req.Host)
	case WSOriginAllowlist:
		for _, a := range allowed {
			if EqualFoldASCII(origin, a) {
				return true
			}
		}
		return false
	}
	return true
}

const (
	wsOpContinuation byte = 0x0
	wsOpText         byte = 0x1
	wsOpBinary       byte = 0x2
	wsOpClose        byte = 0x8
	wsOpPing         byte = 0x9
	wsOpPong         byte = 0xA
)

const wsStatusGoingAway uint16 = 1001
const wsStatusProtocolError uint16 = 1002
const wsStatusNoStatus uint16 = 1005
const wsStatusPolicyViolation uint16 = 1008
const wsStatusAbnormal uint16 = 1006
const wsStatusInvalidPayload uint16 = 1007
const wsStatusMessageTooBig uint16 = 1009
const wsStatusInternalError uint16 = 1011
const wsStatusTryAgainLater uint16 = 1013
const wsMaxFrameHeaderLen = 10
const wsMaxControlPayload = 125
const wsDefaultReadTimeout = 120 * time.Second
const wsDefaultWriteTimeout = 30 * time.Second
const wsDefaultMaxMessageSize = 4 * 1024 * 1024
const wsFrameReadChunk = 64 << 10
const wsReadBufSize = 4 << 10
const wsDeadlineSlackShift = 3
const wsPingMinInterval = int64(100 * time.Millisecond)
const wsPingWindow = int64(10 * time.Second)
const wsPingWindowMax = 100

var errWSEventDriven = &staticError{"websocket: operation unavailable on an event-driven connection"}
var errWSWriteQueueFull = &staticError{"websocket: write queue full"}
var errWSBudgetExhausted = &staticError{"websocket: message buffer budget exhausted"}

// WSConn is a server-side WebSocket connection (RFC 6455). Obtain one with ServeWebSocket (or UpgradeWebSocket) inside a route handler, then exchange data with ReadMessage and WriteMessage (or WriteText / WriteBinary).
type WSConn struct {
	conn             net.Conn
	closed           atomic.Bool
	readTimeout      time.Duration
	writeTimeout     time.Duration
	writeMu          sync.Mutex
	lastPing         atomic.Int64
	pingCount        atomic.Uint32
	MaxMessageSize   int
	subprotocol      string
	compressionLevel int

	closeCode     atomic.Uint32
	rawWrites     atomic.Bool
	ev            *wsLoopConn
	rbuf          []byte
	rpos          int
	rend          int
	readArmedAt   atomic.Int64
	writeArmedAt  int64
	writeDeadline bool
	drain         wsDrainConn
	server        *Server
	bodyReserved  atomic.Int64
}

type WSUpgradeOptions struct {
	Subprotocols     []string
	Compression      bool
	CompressionLevel int
	MaxMessageSize   int64
}

type WSEventHandler struct {
	OnMessage func(ws *WSConn, opcode byte, msg []byte)
	OnClose   func(ws *WSConn, code uint16)
}

type wsDrainConn struct {
	net.Conn
	ws *WSConn
}

func (d *wsDrainConn) Read(p []byte) (int, error) {
	ws := d.ws
	if ws.rpos < ws.rend {
		n := copy(p, ws.rbuf[ws.rpos:ws.rend])
		ws.rpos += n
		return n, nil
	}
	return d.Conn.Read(p)
}

func (d *wsDrainConn) Write(p []byte) (int, error) {
	d.ws.rawWrites.Store(true)
	return d.Conn.Write(p)
}

func (d *wsDrainConn) SetWriteDeadline(t time.Time) error {
	d.ws.rawWrites.Store(true)
	return d.Conn.SetWriteDeadline(t)
}

func (d *wsDrainConn) SetDeadline(t time.Time) error {
	d.ws.rawWrites.Store(true)
	d.ws.readArmedAt.Store(0)
	return d.Conn.SetDeadline(t)
}

func (d *wsDrainConn) SetReadDeadline(t time.Time) error {
	d.ws.readArmedAt.Store(0)
	return d.Conn.SetReadDeadline(t)
}

func wsAcceptKey(clientKey string) string {
	var buf [96]byte
	n := copy(buf[:], clientKey)
	n += copy(buf[n:], wsGUID)
	sum := sha1.Sum(buf[:n])
	var b64 [28]byte
	base64.StdEncoding.Encode(b64[:], sum[:])
	return string(b64[:])
}

// UpgradeWebSocket performs the WebSocket handshake (RFC 6455) on the current request, validating the Upgrade, Connection, Sec-WebSocket-Key, and Sec-WebSocket-Version headers and the Origin per the server's WSOriginMode, then hijacks the connection. It returns a *WSConn on success, or nil if the handshake failed (an error response has already been written).
//
// After a successful upgrade the handler must return promptly and service the connection on its own goroutine: handlers run inline on a shared pool of worker event loops, so a handler that blocks reading the socket pins a worker for the connection's lifetime. Prefer ServeWebSocket, which does this.
//
// Example: ws := UpgradeWebSocket(req, resp); if ws == nil { return }
// Example: if ws := UpgradeWebSocket(req, resp); ws != nil { go handle(ws) }
func UpgradeWebSocket(req *Request, resp *Response) *WSConn {
	return UpgradeWebSocketWith(req, resp, WSUpgradeOptions{})
}

func UpgradeWebSocketWith(req *Request, resp *Response, opts WSUpgradeOptions) *WSConn {
	if req.h2WebSocket {
		return upgradeH2WebSocket(req, resp, opts)
	}
	wsKey, ok := wsCheckH1Upgrade(req, resp)
	if !ok {
		return nil
	}

	conn := req.HijackConn()
	if conn == nil {
		resp.Status(500).String("connection hijack failed")
		return nil
	}

	conn.SetReadDeadline(time.Time{})
	conn.SetWriteDeadline(time.Time{})

	ws := newNegotiatedWSConn(req, opts)

	var buf [256]byte
	b := ws.appendSwitchingProtocols(buf[:0], wsAcceptKey(wsKey))

	if err := writeFull(conn, b); err != nil {
		conn.Close()
		return nil
	}

	if sw := resp.ensureSW(); sw != nil {
		resp.SetStreamer(sw)
	}

	ws.attachConn(conn)
	return ws
}

func wsCheckH1Upgrade(req *Request, resp *Response) (string, bool) {
	upgradeHdr := req.Header("upgrade")
	if !EqualFoldASCII(upgradeHdr, "websocket") {
		resp.Status(400).String("not a websocket request")
		return "", false
	}

	wsKey := req.Header("sec-websocket-key")
	if wsKey == "" {
		resp.Status(400).String("missing Sec-WebSocket-Key")
		return "", false
	}
	decodedKey, err := base64.StdEncoding.DecodeString(wsKey)
	if err != nil || len(decodedKey) != 16 {
		resp.Status(400).String("invalid Sec-WebSocket-Key")
		return "", false
	}

	connHdr := req.Header("connection")
	if !containsTokenFold(connHdr, "upgrade") {
		resp.Status(400).String("missing Connection: Upgrade")
		return "", false
	}

	if !wsVersionAndOriginAccepted(req, resp) {
		return "", false
	}
	return wsKey, true
}

func (ws *WSConn) appendSwitchingProtocols(b []byte, acceptKey string) []byte {
	b = append(b, "HTTP/1.1 101 Switching Protocols\r\n"...)
	b = append(b, "Upgrade: websocket\r\n"...)
	b = append(b, "Connection: Upgrade\r\n"...)
	b = append(b, "Sec-WebSocket-Accept: "...)
	b = append(b, acceptKey...)
	b = append(b, "\r\n"...)
	b = ws.appendNegotiatedHeaders(b)
	return append(b, "\r\n"...)
}

func (ws *WSConn) attachConn(conn net.Conn) {
	ws.conn = conn
	ws.drain = wsDrainConn{Conn: conn, ws: ws}
}

func wsVersionAndOriginAccepted(req *Request, resp *Response) bool {
	if req.Header("sec-websocket-version") != "13" {
		resp.Status(426).
			SetHeader("Sec-WebSocket-Version", "13").
			String("unsupported WebSocket version")
		return false
	}
	if !checkWebSocketOrigin(req) {
		resp.Status(403).String("forbidden websocket origin")
		return false
	}
	return true
}

func upgradeH2WebSocket(req *Request, resp *Response, opts WSUpgradeOptions) *WSConn {
	if !wsVersionAndOriginAccepted(req, resp) {
		return nil
	}
	body := req.BodyStream()
	if body == nil {
		resp.Status(400).String("websocket stream already closed by the client")
		return nil
	}
	sw := resp.EnsureStreamWriter()
	if sw == nil {
		resp.Status(500).String("websocket stream unavailable")
		return nil
	}
	ws := newNegotiatedWSConn(req, opts)
	if err := sw.WriteHeader(200, ws.negotiatedHeaders(), ""); err != nil {
		return nil
	}
	if err := sw.Flush(); err != nil {
		return nil
	}
	resp.SetStreamer(sw)
	conn := newH2StreamConn(body, sw, req.RemoteAddr)
	req.h2Tunnel = conn
	ws.attachConn(conn)
	return ws
}

func newNegotiatedWSConn(req *Request, opts WSUpgradeOptions) *WSConn {
	ws := &WSConn{
		readTimeout:    wsDefaultReadTimeout,
		writeTimeout:   wsDefaultWriteTimeout,
		MaxMessageSize: wsDefaultMaxMessageSize,
		subprotocol:    wsSelectSubprotocol(req.Headers, opts.Subprotocols),
		server:         req.server,
	}
	if req.server != nil {
		ws.readTimeout = optionalDuration(req.server.config.WSReadTimeout, wsDefaultReadTimeout)
		ws.writeTimeout = optionalDuration(req.server.config.WSWriteTimeout, wsDefaultWriteTimeout)
	}
	if opts.MaxMessageSize > 0 {
		ws.MaxMessageSize = int(min(opts.MaxMessageSize, int64(math.MaxInt)))
	}
	if opts.Compression && wsClientOffersDeflate(req.Headers) {
		ws.compressionLevel = wsNormalizeCompressionLevel(opts.CompressionLevel)
	}
	return ws
}

func (ws *WSConn) negotiatedHeaders() [][2]string {
	var headers [][2]string
	if ws.subprotocol != "" {
		headers = append(headers, [2]string{"Sec-WebSocket-Protocol", ws.subprotocol})
	}
	if ws.compressionLevel != 0 {
		headers = append(headers, [2]string{"Sec-WebSocket-Extensions", wsDeflateAcceptance})
	}
	return headers
}

func (ws *WSConn) appendNegotiatedHeaders(b []byte) []byte {
	for _, h := range ws.negotiatedHeaders() {
		b = append(b, h[0]...)
		b = append(b, ": "...)
		b = append(b, h[1]...)
		b = append(b, "\r\n"...)
	}
	return b
}

func (ws *WSConn) Subprotocol() string { return ws.subprotocol }

// ServeWebSocket upgrades the request and runs fn on a new goroutine, returning immediately so the dispatching worker is released; the connection is closed when fn returns. It reports false if the upgrade failed (an error response has already been written). This is the safe way to host a WebSocket — see the UpgradeWebSocket note about handlers that block on the socket.
// An HTTP/2 (RFC 8441) session counts against MaxConns and keeps its per-IP slot until fn returns; when MaxConns is reached the request gets 503.
//
// Example: ServeWebSocket(req, resp, func(ws *WSConn) { for { _, msg, err := ws.ReadMessage(); if err != nil { return }; ws.WriteText(string(msg)) } })
// Example: if !ServeWebSocket(req, resp, handleWS) { return }
func ServeWebSocket(req *Request, resp *Response, fn func(*WSConn)) bool {
	return ServeWebSocketWith(req, resp, WSUpgradeOptions{}, fn)
}

func ServeWebSocketWith(req *Request, resp *Response, opts WSUpgradeOptions, fn func(*WSConn)) bool {
	srv := req.server
	tracked := req.h2WebSocket && srv != nil
	if tracked && !srv.tryTrackConn() {
		resp.Status(503).String("Service Unavailable")
		return false
	}
	ws := UpgradeWebSocketWith(req, resp, opts)
	if ws == nil {
		if tracked {
			srv.releaseTrackedConn()
		}
		return false
	}
	tunnel, _ := ws.conn.(*h2StreamConn)
	tunnel.retainSlots()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				srv.reportPanic(nil, r)
			}
			ws.Close()
			tunnel.releaseSlots()
			if tracked {
				srv.releaseTrackedConn()
			}
		}()
		fn(ws)
	}()
	return true
}

func ServeWebSocketEvents(req *Request, resp *Response, opts WSUpgradeOptions, h WSEventHandler) bool {
	if req.connTakenOver || req.hijacked {
		resp.Status(500).String("connection already taken over")
		return false
	}
	if c := epollWSEventTarget(req); c != nil {
		wsKey, ok := wsCheckH1Upgrade(req, resp)
		if !ok {
			return false
		}
		ws := newNegotiatedWSConn(req, opts)
		c.prepareWSEvents(req, ws, h, wsAcceptKey(wsKey))
		return true
	}
	srv := req.server
	return ServeWebSocketWith(req, resp, opts, func(ws *WSConn) { serveWSEventsBlocking(srv, ws, h) })
}

func wsDeliverMessage(srv *Server, ws *WSConn, h *WSEventHandler, op byte, msg []byte) {
	defer func() {
		if r := recover(); r != nil {
			srv.reportPanic(nil, r)
			ws.closeWithStatus(wsStatusInternalError)
		}
	}()
	h.OnMessage(ws, op, msg)
}

func wsDeliverClose(srv *Server, ws *WSConn, h *WSEventHandler) {
	if h.OnClose == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			srv.reportPanic(nil, r)
		}
	}()
	code := uint16(ws.closeCode.Load())
	if code == 0 {
		code = wsStatusAbnormal
	}
	h.OnClose(ws, code)
}

func serveWSEventsBlocking(srv *Server, ws *WSConn, h WSEventHandler) {
	var buf []byte
	for {
		op, msg, err := ws.readMessageReserved(buf[:0])
		if err != nil {
			ws.releaseMessageBytes()
			ws.noteCloseCode(wsStatusAbnormal)
			_, tunneled := ws.conn.(*h2StreamConn)
			closeHeld := h.OnClose != nil && srv != nil && !tunneled
			if closeHeld {
				srv.activeConns.Add(1)
			}
			ws.Close()
			wsDeliverClose(srv, ws, &h)
			if closeHeld {
				srv.releaseTrackedConn()
			}
			return
		}
		if cap(msg) <= wsFrameReadChunk {
			buf = msg
		}
		if h.OnMessage != nil {
			wsDeliverMessage(srv, ws, &h, op, msg)
		}
		ws.releaseMessageBytes()
	}
}

func (ws *WSConn) reserveMessageBytes(n int) bool {
	if ws.server.tryReserveConnBodyBytes(&ws.bodyReserved, n) {
		return true
	}
	ws.closeWithStatus(wsStatusTryAgainLater)
	return false
}

func (ws *WSConn) releaseMessageBytes() {
	ws.server.releaseConnBodyBytes(&ws.bodyReserved, ws.bodyReserved.Load())
}

// NetConn returns the underlying hijacked connection, e.g. to set per-write deadlines so a dead peer cannot block WriteMessage forever.
func (ws *WSConn) NetConn() net.Conn {
	if ws.conn == nil {
		return nil
	}
	if ws.drain.ws == nil {
		ws.drain = wsDrainConn{Conn: ws.conn, ws: ws}
	}
	return &ws.drain
}

// ReadMessage reads and reassembles the next WebSocket message, returning its opcode (0x1 text, 0x2 binary), payload, and any error. Close frames are answered and reported as io.EOF, and ping frames are answered with a pong automatically.
func (ws *WSConn) ReadMessage() (byte, []byte, error) {
	return ws.ReadMessageInto(nil)
}

func (ws *WSConn) ReadMessageInto(dst []byte) (byte, []byte, error) {
	if ws.ev != nil {
		return 0, nil, errWSEventDriven
	}
	op, msg, err := ws.readMessageReserved(dst)
	ws.releaseMessageBytes()
	return op, msg, err
}

func (ws *WSConn) readMessageReserved(dst []byte) (byte, []byte, error) {
	var msgOpcode byte
	assembled := dst[:0]
	inMessage, msgCompressed := false, false

	for {
		ws.armReadDeadline()
		if err := ws.fill(2); err != nil {
			return 0, nil, err
		}
		b0, b1 := ws.rbuf[ws.rpos], ws.rbuf[ws.rpos+1]
		ws.rpos += 2

		fin := b0&0x80 != 0
		opcode := b0 & 0x0F
		if err := ws.vetFrameHead(b0, b1, inMessage); err != nil {
			return 0, nil, err
		}

		if opcode >= wsOpClose {
			payload, err := ws.readFramePayload(nil, b1, false)
			if err != nil {
				return 0, nil, err
			}
			if opcode == wsOpClose {
				if err := ws.handleCloseFrame(payload); err != nil {
					return 0, nil, err
				}
				return opcode, payload, io.EOF
			}
			if opcode == wsOpPing {
				if err := ws.handlePing(payload); err != nil {
					return 0, nil, err
				}
			}
			continue
		}

		if !inMessage {
			msgOpcode = opcode
			msgCompressed = b0&wsRSV1 != 0
			inMessage = true
		}

		var err error
		assembled, err = ws.readFramePayload(assembled, b1, true)
		if err != nil {
			return 0, nil, err
		}

		if fin {
			msg, err := ws.completeMessage(msgOpcode, msgCompressed, assembled)
			if err != nil {
				return 0, nil, err
			}
			return msgOpcode, msg, nil
		}
	}
}

func (ws *WSConn) vetFrameHead(b0, b1 byte, inMessage bool) error {
	opcode := b0 & 0x0F
	if rsv := b0 & wsRSVMask; rsv != 0 &&
		(rsv != wsRSV1 || ws.compressionLevel == 0 || opcode == wsOpContinuation || opcode >= wsOpClose) {
		ws.failBare()
		return ErrWebSocketProtocol
	}
	if b1&0x80 == 0 {
		ws.failBare()
		return ErrWebSocketProtocol
	}
	if opcode >= wsOpClose {
		if b0&0x80 == 0 || b1&0x7F > wsMaxControlPayload || opcode > wsOpPong {
			ws.closeWithStatus(wsStatusProtocolError)
			return ErrWebSocketProtocol
		}
		return nil
	}
	if opcode > wsOpBinary {
		ws.closeWithStatus(wsStatusProtocolError)
		return ErrWebSocketProtocol
	}
	if inMessage != (opcode == wsOpContinuation) {
		ws.failBare()
		return ErrWebSocketProtocol
	}
	return nil
}

func (ws *WSConn) vetPayloadLength(payloadLen int64, assembled int) error {
	if payloadLen < 0 {
		ws.failBare()
		return ErrBodyTooLarge
	}
	if payloadLen > ws.maxMessageSize()-int64(assembled) {
		ws.closeWithStatus(wsStatusMessageTooBig)
		return ErrBodyTooLarge
	}
	return nil
}

func (ws *WSConn) handleCloseFrame(payload []byte) error {
	if len(payload) == 1 {
		ws.closeWithStatus(wsStatusProtocolError)
		return ErrWebSocketProtocol
	}
	if len(payload) >= 2 {
		code := binary.BigEndian.Uint16(payload[:2])
		if !wsValidCloseCode(code) {
			ws.closeWithStatus(wsStatusProtocolError)
			return ErrWebSocketProtocol
		}
		if !validUTF8(payload[2:]) {
			ws.closeWithStatus(wsStatusInvalidPayload)
			return ErrWebSocketProtocol
		}
		ws.closeWithPayload(payload[:2])
		return nil
	}
	ws.Close()
	return nil
}

func (ws *WSConn) handlePing(payload []byte) error {
	now := turbo.UnixNano()
	last := ws.lastPing.Swap(now)
	if last != 0 && now-last < wsPingMinInterval {
		ws.closeWithStatus(wsStatusProtocolError)
		return ErrWebSocketProtocol
	}
	if last == 0 || now-last > wsPingWindow {
		ws.pingCount.Store(1)
	} else if ws.pingCount.Add(1) > wsPingWindowMax {
		ws.closeWithStatus(wsStatusProtocolError)
		return ErrWebSocketProtocol
	}
	ws.WriteMessage(wsOpPong, payload)
	return nil
}

func (ws *WSConn) completeMessage(opcode byte, compressed bool, assembled []byte) ([]byte, error) {
	if compressed {
		inflated, status := wsInflate(assembled, ws.maxMessageSize())
		switch status {
		case wsStatusMessageTooBig:
			ws.closeWithStatus(status)
			return nil, ErrBodyTooLarge
		case wsStatusInvalidPayload:
			ws.closeWithStatus(status)
			return nil, ErrWebSocketProtocol
		}
		if !ws.reserveMessageBytes(len(inflated)) {
			return nil, errWSBudgetExhausted
		}
		assembled = inflated
	}
	if opcode == wsOpText && !validUTF8(assembled) {
		ws.closeWithStatus(wsStatusInvalidPayload)
		return nil, ErrWebSocketProtocol
	}
	return assembled, nil
}

func (ws *WSConn) armReadDeadline() {
	if ws.readTimeout <= 0 {
		return
	}
	want := turbo.UnixNano() + int64(ws.readTimeout)
	if armed := ws.readArmedAt.Load(); armed != 0 && armed <= want && want-armed < int64(ws.readTimeout)>>wsDeadlineSlackShift {
		return
	}
	ws.conn.SetReadDeadline(time.Unix(0, want))
	ws.readArmedAt.Store(want)
}

func (ws *WSConn) fill(n int) error {
	if ws.rend-ws.rpos >= n {
		return nil
	}
	if ws.rbuf == nil {
		ws.rbuf = make([]byte, wsReadBufSize)
	}
	if ws.rpos > 0 {
		ws.rend = copy(ws.rbuf, ws.rbuf[ws.rpos:ws.rend])
		ws.rpos = 0
	}
	for {
		m, err := ws.conn.Read(ws.rbuf[ws.rend:])
		ws.rend += m
		if ws.rend >= n {
			return nil
		}
		if err != nil {
			if err == io.EOF && ws.rend > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
}

func (ws *WSConn) readFull(p []byte) error {
	if buffered := ws.rend - ws.rpos; buffered > 0 {
		n := copy(p, ws.rbuf[ws.rpos:ws.rend])
		ws.rpos += n
		p = p[n:]
	}
	if len(p) == 0 {
		return nil
	}
	if len(p) >= wsReadBufSize {
		_, err := io.ReadFull(ws.conn, p)
		return err
	}
	if err := ws.fill(len(p)); err != nil {
		return err
	}
	ws.rpos += copy(p, ws.rbuf[ws.rpos:ws.rend])
	return nil
}

func wsValidCloseCode(code uint16) bool {
	switch {
	case code >= 3000 && code <= 4999:
		return true
	case code == 1000 || code == 1001 || code == 1002 || code == 1003 ||
		code == 1007 || code == 1008 || code == 1009 || code == 1010 || code == 1011:
		return true
	default:
		return false
	}
}

func (ws *WSConn) noteCloseCode(code uint16) {
	ws.closeCode.CompareAndSwap(0, uint32(code))
}

func (ws *WSConn) failBare() {
	ws.noteCloseCode(wsStatusProtocolError)
	ws.Close()
}

func (ws *WSConn) closeWithStatus(code uint16) {
	var payload [2]byte
	binary.BigEndian.PutUint16(payload[:], code)
	ws.closeWithPayload(payload[:])
}

func (ws *WSConn) closeWithPayload(payload []byte) error {
	if !ws.closed.CompareAndSwap(false, true) {
		return nil
	}
	if len(payload) >= 2 {
		ws.noteCloseCode(binary.BigEndian.Uint16(payload))
	}
	if ev := ws.ev; ev != nil {
		ev.writeClose(payload)
		return nil
	}
	_ = ws.WriteMessage(wsOpClose, payload)
	return ws.conn.Close()
}

func (ws *WSConn) readFramePayload(dst []byte, secondByte byte, buffered bool) ([]byte, error) {
	payloadLen := int64(secondByte & 0x7F)

	switch payloadLen {
	case 126:
		if err := ws.fill(2); err != nil {
			return nil, err
		}
		payloadLen = int64(binary.BigEndian.Uint16(ws.rbuf[ws.rpos:]))
		ws.rpos += 2
	case 127:
		if err := ws.fill(8); err != nil {
			return nil, err
		}
		payloadLen = int64(binary.BigEndian.Uint64(ws.rbuf[ws.rpos:]))
		ws.rpos += 8
	}

	if err := ws.vetPayloadLength(payloadLen, len(dst)); err != nil {
		return nil, err
	}

	if err := ws.fill(4); err != nil {
		return nil, err
	}
	var maskKey [4]byte
	copy(maskKey[:], ws.rbuf[ws.rpos:ws.rpos+4])
	ws.rpos += 4

	start := len(dst)
	for remaining := payloadLen; remaining > 0; {
		step := int(min(remaining, max(wsFrameReadChunk, int64(len(dst)-start))))
		if buffered && !ws.reserveMessageBytes(step) {
			return nil, errWSBudgetExhausted
		}
		dst = slices.Grow(dst, step)
		if err := ws.readFull(dst[len(dst) : len(dst)+step]); err != nil {
			return nil, err
		}
		dst = dst[:len(dst)+step]
		remaining -= int64(step)
	}

	maskXOR(dst[start:], maskKey)
	return dst, nil
}

// WriteMessage writes a single WebSocket frame with the given opcode and payload; prefer WriteText or WriteBinary for ordinary messages.
//
// Example: ws.WriteMessage(0x1, []byte("hi"))
// Example: ws.WriteMessage(0x2, payload)
func (ws *WSConn) WriteMessage(opcode byte, data []byte) error {
	if ev := ws.ev; ev != nil {
		return ev.write(opcode, data)
	}
	if ws.compressesMessage(opcode, data) {
		return ws.writeCompressed(opcode, data)
	}
	bp := MediumBufPool.Get().(*[]byte)
	buf := wsAppendFrameHeader((*bp)[:0], 0x80|opcode, len(data))
	buf = append(buf, data...)
	err := ws.writeFrame(buf)
	*bp = buf[:0]
	putBoxedBufCapped(&MediumBufPool, bp, largeBufPoolMaxCap)
	return err
}

func (ws *WSConn) compressesMessage(opcode byte, data []byte) bool {
	return ws.compressionLevel != 0 && (opcode == wsOpText || opcode == wsOpBinary) && len(data) >= wsCompressMinSize
}

func (ws *WSConn) appendCompressedFrame(dst []byte, opcode byte, data []byte) []byte {
	base := len(dst)
	dst = append(dst, make([]byte, wsMaxFrameHeaderLen)...)
	dst = wsDeflate(dst, data, ws.compressionLevel)
	var header [wsMaxFrameHeaderLen]byte
	h := wsAppendFrameHeader(header[:0], 0x80|wsRSV1|opcode, len(dst)-base-wsMaxFrameHeaderLen)
	shift := wsMaxFrameHeaderLen - len(h)
	copy(dst[base+shift:], h)
	if shift > 0 {
		copy(dst[base:], dst[base+shift:])
		dst = dst[:len(dst)-shift]
	}
	return dst
}

func (ws *WSConn) writeCompressed(opcode byte, data []byte) error {
	bp := LargeBufPool.Get().(*[]byte)
	buf := append((*bp)[:0], make([]byte, wsMaxFrameHeaderLen)...)
	buf = wsDeflate(buf, data, ws.compressionLevel)
	var header [wsMaxFrameHeaderLen]byte
	h := wsAppendFrameHeader(header[:0], 0x80|wsRSV1|opcode, len(buf)-wsMaxFrameHeaderLen)
	start := wsMaxFrameHeaderLen - len(h)
	copy(buf[start:], h)
	err := ws.writeFrame(buf[start:])
	*bp = buf[:0]
	putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
	return err
}

func (ws *WSConn) writeFrame(frame []byte) error {
	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()
	if ws.rawWrites.Load() {
		if ws.writeTimeout > 0 {
			ws.conn.SetWriteDeadline(time.Unix(0, turbo.UnixNano()+int64(ws.writeTimeout)))
		}
		err := writeFull(ws.conn, frame)
		ws.conn.SetWriteDeadline(time.Time{})
		ws.writeDeadline = false
		return err
	}
	ws.armWriteDeadline()
	return writeFull(ws.conn, frame)
}

func (ws *WSConn) armWriteDeadline() {
	if ws.writeTimeout <= 0 {
		if ws.writeDeadline {
			ws.conn.SetWriteDeadline(time.Time{})
			ws.writeDeadline = false
		}
		return
	}
	want := turbo.UnixNano() + int64(ws.writeTimeout)
	if armed := ws.writeArmedAt; ws.writeDeadline && armed <= want && want-armed < int64(ws.writeTimeout)>>wsDeadlineSlackShift {
		return
	}
	ws.conn.SetWriteDeadline(time.Unix(0, want))
	ws.writeArmedAt = want
	ws.writeDeadline = true
}

func wsAppendFrameHeader(dst []byte, first byte, payloadLen int) []byte {
	switch {
	case payloadLen <= 125:
		return append(dst, first, byte(payloadLen))
	case payloadLen <= 65535:
		return append(dst, first, 126, byte(payloadLen>>8), byte(payloadLen))
	default:
		return append(dst, first, 127,
			byte(payloadLen>>56), byte(payloadLen>>48), byte(payloadLen>>40), byte(payloadLen>>32),
			byte(payloadLen>>24), byte(payloadLen>>16), byte(payloadLen>>8), byte(payloadLen))
	}
}

// WriteText sends a text WebSocket frame.
//
// Example: ws.WriteText("hello client")
// Example: ws.WriteText(fmt.Sprintf("count=%d", n))
func (ws *WSConn) WriteText(msg string) error {
	return ws.WriteMessage(wsOpText, UnsafeBytes(msg))
}

// WriteBinary sends a binary WebSocket frame.
//
// Example: ws.WriteBinary([]byte{0x01, 0x02})
// Example: ws.WriteBinary(buf)
func (ws *WSConn) WriteBinary(data []byte) error {
	return ws.WriteMessage(wsOpBinary, data)
}

// Ping sends a WebSocket ping frame; a conforming client replies with a pong automatically.
func (ws *WSConn) Ping() error {
	return ws.WriteMessage(wsOpPing, nil)
}

// Close sends a close frame and closes the underlying connection. It is safe to call multiple times.
func (ws *WSConn) Close() error {
	ws.noteCloseCode(wsStatusNoStatus)
	return ws.closeWithPayload(nil)
}

// SetDeadline sets the read and write deadline on the underlying connection.
//
// Example: ws.SetDeadline(time.Now().Add(30 * time.Second))
// Example: ws.SetDeadline(time.Time{})
func (ws *WSConn) SetDeadline(t time.Time) error {
	if ws.ev != nil {
		return errWSEventDriven
	}
	ws.writeMu.Lock()
	ws.writeDeadline = false
	ws.writeMu.Unlock()
	ws.readArmedAt.Store(0)
	return ws.conn.SetDeadline(t)
}

// SetReadTimeout sets the idle read timeout applied before each frame read; a value <= 0 disables it. The default prevents a stalled peer from pinning the connection's goroutine indefinitely.
//
// Example: ws.SetReadTimeout(60 * time.Second)
// Example: ws.SetReadTimeout(0)
func (ws *WSConn) SetReadTimeout(d time.Duration) {
	ws.readTimeout = d
}

// SetWriteTimeout sets the timeout applied to each frame write; a value <= 0
// disables it.
//
// Example: ws.SetWriteTimeout(15 * time.Second)
// Example: ws.SetWriteTimeout(0)
func (ws *WSConn) SetWriteTimeout(d time.Duration) {
	ws.writeTimeout = d
}

func (ws *WSConn) maxMessageSize() int64 {
	if ws.MaxMessageSize <= 0 {
		return int64(wsDefaultMaxMessageSize)
	}
	return int64(ws.MaxMessageSize)
}

func containsTokenFold(header, token string) bool {
	for header != "" {
		var part string
		if i := indexOf(header, ','); i >= 0 {
			part = header[:i]
			header = header[i+1:]
		} else {
			part = header
			header = ""
		}
		part = UnsafeString(trimOWS(UnsafeBytes(part)))
		if EqualFoldASCII(part, token) {
			return true
		}
	}
	return false
}

func indexOf(s string, c byte) int {
	return strings.IndexByte(s, c)
}

// Uint32Hash64 mixes the bits of v through a multiply-xorshift finalizer and
// returns a well-distributed pseudo-random value derived from v.
func Uint32Hash64(v uint64) uint64 {
	x := v
	x = ((x >> 16) ^ x) * 0x45d9f3b
	x = ((x >> 16) ^ x) * 0x45d9f3b
	x = (x >> 16) ^ x
	return x
}

func wsMaskWord(maskKey [4]byte) uint64 {
	const repeatLow32 = 1<<32 | 1
	return uint64(binary.LittleEndian.Uint32(maskKey[:])) * repeatLow32
}

func maskXORSWAR(payload []byte, maskKey [4]byte) {
	if len(payload) == 0 {
		return
	}
	maskWord := wsMaskWord(maskKey)

	n := len(payload)
	i := 0
	for ; i+8 <= n; i += 8 {
		v := binary.LittleEndian.Uint64(payload[i:])
		binary.LittleEndian.PutUint64(payload[i:], v^maskWord)
	}
	for ; i < n; i++ {
		payload[i] ^= maskKey[i&3]
	}
}
