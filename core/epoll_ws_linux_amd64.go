//go:build linux && amd64

package core

import (
	"encoding/binary"
	"net"
	"sync"
	"unsafe"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	wsOutHighWater     = 256 << 10
	wsOutLowWater      = 64 << 10
	wsRetainedMsgLimit = 64 << 10
	wsTLSReadBufCap    = MaxRecordSize + tlsRecordHeaderLen + plainReadMinFree
	wsDirectSendMin    = 4 << 10
)

type wsCallbackKind uint8

const (
	wsCallbackMessage wsCallbackKind = iota
	wsCallbackClose
)

type wsLoopConn struct {
	ws     *WSConn
	h      WSEventHandler
	accept string

	c             *epollConn
	w             *epollWorker
	ipKey         string
	readDeadline  int64
	writeDeadline int64
	closing       bool

	inFrame       bool
	frameFin      bool
	frameOp       byte
	remaining     int64
	mask          [4]byte
	maskOff       int
	inMessage     bool
	msgOp         byte
	msgCompressed bool
	msg           []byte
	ctrlN         int
	ctrl          [wsMaxControlPayload]byte

	cbPending bool
	closeDue  bool
	cbKind    wsCallbackKind
	cbOp      byte
	cbMsg     []byte
	cbRoute   *inlineRoute
	inlineSeq uint64
	cbAsyncFn func()
	doneNext  *wsLoopConn
	wakeNext  *wsLoopConn

	mu          sync.Mutex
	outbox      []byte
	outLimit    int
	queued      bool
	holding     bool
	closeQueued bool
	dead        bool
	direct      bool
	directFD    int
	directSent  uint64
}

func epollWSEventTarget(req *Request) *epollConn {
	if req.h2WebSocket {
		return nil
	}
	c, ok := req.swFactory.(*epollConn)
	if !ok || req != &c.req {
		return nil
	}
	return c
}

func (c *epollConn) prepareWSEvents(req *Request, ws *WSConn, h WSEventHandler, accept string) {
	ev := &wsLoopConn{ws: ws, h: h, accept: accept}
	ws.ev = ev
	req.connTakenOver = true
	c.wsPending = ev
}

func (w *epollWorker) finishWSUpgrade(c *epollConn, gen uint32, ev *wsLoopConn) {
	ev.w = w
	c.wsPending = nil
	c.releaseH1BodyBudget()
	if c.inFlight > 0 {
		c.inFlight--
	}
	c.req.attachConn = nil
	c.req.conn = nil
	c.req.StreamWriter = nil
	srv := w.server
	if srv.trustedProxies.active && srv.perIPLimiter != nil {
		ev.ipKey = extractIP(c.req.RemoteAddr)
	}
	if c.generation != gen || c.fd < 0 {
		w.wsAbandon(ev)
		if c.fd < 0 && c.inFlight == 0 {
			w.pool.put(c)
		}
		return
	}
	c.dispatching = false
	c.resp.resetFastH1()
	ev.c = c
	ev.outLimit = w.maxPendingWrite
	ev.readDeadline = deadlineFrom(int64(ev.ws.readTimeout))
	c.ws = ev
	w.wsLive++
	w.watchInline()
	var head [256]byte
	if c.writeBuf == nil {
		c.writeBuf = acquireIOBuf()
	}
	w.clientAppend(c, ev.ws.appendSwitchingProtocols(head[:0], ev.accept))
	c.deadline = ev.readDeadline
	if !w.flush(c) || c.fd < 0 {
		return
	}
	w.resumeConn(c)
}

func wsReadBufLimit(maxRead int) int {
	if maxRead > 0 && maxRead < wsTLSReadBufCap {
		return maxRead
	}
	return wsTLSReadBufCap
}

func (c *epollConn) wsGrowReadBuf(maxRead int) bool {
	size := wsReadBufLimit(maxRead)
	if cap(c.readBuf) >= size {
		return false
	}
	grown := make([]byte, size)
	copy(grown, c.readBuf[:c.readN])
	c.readBuf = grown
	return true
}

func (w *epollWorker) wsAbandon(ev *wsLoopConn) {
	ev.mu.Lock()
	ev.dead = true
	ev.outbox = nil
	ev.mu.Unlock()
	ev.ws.closed.Store(true)
	if ev.ipKey != "" {
		w.server.perIPLimiter.release(ev.ipKey)
		ev.ipKey = ""
	}
	if ev.cbPending {
		ev.closeDue = true
		return
	}
	ev.ws.releaseMessageBytes()
	ev.msg = nil
	w.queueWSClose(ev)
}

func (w *epollWorker) wsTeardown(c *epollConn) {
	ev := c.ws
	c.ws = nil
	c.tunnelPaused = false
	w.wsLive--
	if ev.ws.closed.CompareAndSwap(false, true) {
		ev.ws.noteCloseCode(wsStatusAbnormal)
		w.wsSendFinalClose(c)
	}
	w.wsAbandon(ev)
}

func (w *epollWorker) wsSendFinalClose(c *epollConn) {
	if c.writeBuf == nil {
		c.writeBuf = acquireIOBuf()
	}
	bareClose := [2]byte{0x80 | wsOpClose, 0}
	w.clientAppend(c, bareClose[:])
	if c.writeSent < len(c.writeBuf) {
		_, _ = socketSend(c.fd, c.writeBuf[c.writeSent:])
	}
}

func (w *epollWorker) wsGoingAway(c *epollConn) {
	ev := c.ws
	if ev.closing || ev.ws.closed.Load() {
		return
	}
	ev.ws.closeWithStatus(wsStatusGoingAway)
}

func (w *epollWorker) wsQuietDeadline(c *epollConn) int64 {
	if c.ws != nil {
		return c.ws.deadline(false)
	}
	return deadlineFrom(w.idleTO)
}

func (w *epollWorker) wsOutDeadline(c *epollConn) int64 {
	ev := c.ws
	if ev == nil {
		if w.writeTO > 0 {
			return deadlineFrom(w.writeTO)
		}
		return c.deadline
	}
	ev.writeDeadline = deadlineFrom(int64(ev.ws.writeTimeout))
	return ev.deadline(true)
}

func (ev *wsLoopConn) deadline(outPending bool) int64 {
	r, wd := ev.readDeadline, ev.writeDeadline
	if ev.cbPending {
		r = 0
	}
	if !outPending || wd == 0 || (r != 0 && r <= wd) {
		return r
	}
	return wd
}

func (w *epollWorker) wsResumeIfDrained(c *epollConn) {
	if len(c.writeBuf)-c.writeSent > wsOutLowWater {
		return
	}
	c.tunnelPaused = false
	c.h1ResumeDue = true
	w.markFlush(c)
}

func (ev *wsLoopConn) write(opcode byte, data []byte) error {
	ws := ev.ws
	ev.mu.Lock()
	if ev.dead || ev.closeQueued {
		ev.mu.Unlock()
		return net.ErrClosed
	}
	start := len(ev.outbox)
	if ws.compressesMessage(opcode, data) {
		ev.outbox = ws.appendCompressedFrame(ev.outbox, opcode, data)
	} else if !ev.sendDirect(opcode, data) {
		ev.outbox = wsAppendFrameHeader(ev.outbox, 0x80|opcode, len(data))
		ev.outbox = append(ev.outbox, data...)
	}
	if ev.outLimit > 0 && len(ev.outbox) > ev.outLimit {
		ev.outbox = ev.outbox[:start]
		ev.mu.Unlock()
		ws.closeWithStatus(wsStatusPolicyViolation)
		return errWSWriteQueueFull
	}
	wake := ev.claimWake()
	ev.mu.Unlock()
	if wake {
		ev.w.pushWSWake(ev)
	}
	return nil
}

func (ev *wsLoopConn) writeClose(payload []byte) {
	ev.mu.Lock()
	if ev.dead || ev.closeQueued {
		ev.mu.Unlock()
		return
	}
	ev.outbox = wsAppendFrameHeader(ev.outbox, 0x80|wsOpClose, len(payload))
	ev.outbox = append(ev.outbox, payload...)
	ev.closeQueued = true
	wake := ev.claimWake()
	ev.mu.Unlock()
	if wake {
		ev.w.pushWSWake(ev)
	}
}

func (ev *wsLoopConn) claimWake() bool {
	if ev.queued || ev.holding || ev.w == nil {
		return false
	}
	ev.queued = true
	return true
}

func (w *epollWorker) pushWSWake(ev *wsLoopConn) {
	for {
		head := w.wsWake.Load()
		ev.wakeNext = head
		if w.wsWake.CompareAndSwap(head, ev) {
			break
		}
	}
	w.taskPending.Store(true)
	if w.parked.Load() {
		w.wakeForShutdown()
	}
}

func (w *epollWorker) runWSWakes() {
	for ev := w.wsWake.Swap(nil); ev != nil; {
		next := ev.wakeNext
		ev.wakeNext = nil
		w.wsFlushOutbox(ev)
		ev = next
	}
}

func (w *epollWorker) wsFlushOutbox(ev *wsLoopConn) {
	c := ev.c
	if c == nil || c.ws != ev || c.fd < 0 {
		ev.mu.Lock()
		ev.queued = false
		ev.outbox = nil
		ev.mu.Unlock()
		return
	}
	if c.writeBuf == nil {
		c.writeBuf = acquireIOBuf()
	}
	ev.mu.Lock()
	ev.queued = false
	if len(ev.outbox) > 0 {
		w.clientAppend(c, ev.outbox)
		ev.outbox = ev.recycledOutbox()
	}
	closeQueued := ev.closeQueued
	ev.mu.Unlock()
	if closeQueued {
		ev.closing = true
		c.closeAfter = true
	}
	w.markFlush(c)
}

func (ev *wsLoopConn) recycledOutbox() []byte {
	if cap(ev.outbox) > wsRetainedMsgLimit {
		return nil
	}
	return ev.outbox[:0]
}

func (ev *wsLoopConn) sendDirect(opcode byte, data []byte) bool {
	if !ev.direct || len(ev.outbox) != 0 || len(data) < wsDirectSendMin ||
		(ev.outLimit > 0 && len(data)+wsMaxFrameHeaderLen > ev.outLimit) {
		return false
	}
	var hdr [wsMaxFrameHeaderLen]byte
	h := wsAppendFrameHeader(hdr[:0], 0x80|opcode, len(data))
	n, err := wsSendFrame(ev.directFD, h, data)
	if err != nil || n <= 0 {
		ev.direct = false
		return false
	}
	ev.directSent += uint64(n)
	if n < len(h) {
		ev.outbox = append(ev.outbox, h[n:]...)
		n = 0
	} else {
		n -= len(h)
	}
	if n < len(data) {
		ev.outbox = append(ev.outbox, data[n:]...)
		ev.direct = false
	}
	return true
}

func wsSendFrame(fd int, hdr, payload []byte) (int, error) {
	var iov [2]unix.Iovec
	iov[0].Base = &hdr[0]
	iov[0].SetLen(len(hdr))
	iov[1].Base = &payload[0]
	iov[1].SetLen(len(payload))
	var msg unix.Msghdr
	msg.Iov = &iov[0]
	msg.SetIovlen(len(iov))
	return socketSendmsg(fd, &msg)
}

func (ev *wsLoopConn) holdWakes(c *epollConn, out []byte) {
	ev.mu.Lock()
	ev.holding = true
	ev.setDirect(c, out)
	ev.mu.Unlock()
}

func (ev *wsLoopConn) setDirect(c *epollConn, out []byte) {
	ev.direct = !c.tls && len(out) == c.writeSent && len(c.bodyOut) == 0
	ev.directFD = c.fd
}

func (ev *wsLoopConn) takeOutbox(c *epollConn, out []byte, release bool) []byte {
	ev.mu.Lock()
	switch {
	case len(ev.outbox) == 0:
	case len(out) == 0 && cap(out) >= len(ev.outbox):
		out, ev.outbox = ev.outbox, out
	default:
		out = append(out, ev.outbox...)
		ev.outbox = ev.recycledOutbox()
	}
	if ev.closeQueued {
		ev.closing = true
	}
	if release {
		ev.holding = false
		ev.direct = false
	} else {
		ev.setDirect(c, out)
	}
	if ev.directSent > 0 {
		c.worker.bytesOut += ev.directSent
		ev.directSent = 0
	}
	ev.mu.Unlock()
	return out
}

func (c *epollConn) wsCallbackPending() bool {
	return c.ws != nil && c.ws.cbPending
}

func (c *epollConn) wsServe(out []byte) ([]byte, int) {
	ev := c.ws
	if ev.cbPending {
		return out, h1StepDispatched
	}
	ev.holdWakes(c, out)
	completed := false
	for !ev.closing && !ev.cbPending {
		if c.h1PendingWrite(out) > wsOutHighWater {
			c.tunnelPaused = true
			break
		}
		data := c.h1Unread()
		if len(data) == 0 {
			break
		}
		var done bool
		if ev.inFrame {
			done = ev.continueFrame(c, data)
		} else {
			var ok bool
			done, ok = ev.startFrame(c, data)
			if !ok {
				break
			}
		}
		if done {
			completed = true
			if len(c.h1Unread()) == 0 {
				break
			}
			out = ev.takeOutbox(c, out, false)
		}
	}
	out = ev.takeOutbox(c, out, true)
	if completed {
		ev.readDeadline = deadlineFrom(int64(ev.ws.readTimeout))
	}
	c.deadline = ev.deadline(c.outArmed)
	switch {
	case ev.closing:
		return out, h1StepClose
	case c.tunnelPaused, ev.cbPending:
		return out, h1StepDispatched
	}
	return out, h1StepNeedInput
}

func (ev *wsLoopConn) startFrame(c *epollConn, data []byte) (done, ok bool) {
	if len(data) < 2 {
		return false, false
	}
	ws := ev.ws
	b0, b1 := data[0], data[1]
	extEnd := 2
	switch b1 & 0x7F {
	case 126:
		extEnd = 4
	case 127:
		extEnd = 10
	}
	if err := ws.vetFrameHead(b0, b1, ev.inMessage); err != nil {
		return true, true
	}
	if len(data) < extEnd {
		return false, false
	}
	payloadLen := int64(b1 & 0x7F)
	switch extEnd {
	case 4:
		payloadLen = int64(binary.BigEndian.Uint16(data[2:]))
	case 10:
		payloadLen = int64(binary.BigEndian.Uint64(data[2:]))
	}
	opcode := b0 & 0x0F
	control := opcode >= wsOpClose
	assembled := len(ev.msg)
	if control {
		assembled = 0
	}
	if err := ws.vetPayloadLength(payloadLen, assembled); err != nil {
		return true, true
	}
	hdrLen := extEnd + 4
	if len(data) < hdrLen {
		return false, false
	}
	if int64(len(data)-hdrLen) < payloadLen && ev.awaitsWholeFrame(c, b0, hdrLen, payloadLen) {
		return false, false
	}
	copy(ev.mask[:], data[extEnd:hdrLen])
	c.h1Advance(hdrLen)
	data = data[hdrLen:]
	fin := b0&0x80 != 0
	if !control && !ev.inMessage {
		ev.inMessage = true
		ev.msgOp = opcode
		ev.msgCompressed = b0&wsRSV1 != 0
	}
	if int64(len(data)) >= payloadLen {
		payload := data[:payloadLen]
		maskXOR(payload, ev.mask)
		c.h1Advance(int(payloadLen))
		if control {
			ev.controlFrame(opcode, payload)
			return true, true
		}
		if !ev.appendMessage(payload) {
			return true, true
		}
		if fin {
			ev.finishMessage(ev.msg)
		}
		return true, true
	}
	ev.inFrame = true
	ev.frameFin = fin
	ev.frameOp = opcode
	ev.remaining = payloadLen
	ev.maskOff = 0
	ev.ctrlN = 0
	ev.continueFrame(c, data)
	return false, true
}

func (ev *wsLoopConn) awaitsWholeFrame(c *epollConn, b0 byte, hdrLen int, payloadLen int64) bool {
	if c.tls || ev.inMessage || b0&0x80 == 0 || b0&wsRSV1 != 0 || b0&0x0F >= wsOpClose {
		return false
	}
	return int64(hdrLen)+payloadLen <= int64(wsReadBufLimit(c.worker.server.effectiveReadCap())-plainReadMinFree)
}

func (ev *wsLoopConn) continueFrame(c *epollConn, data []byte) bool {
	take := len(data)
	if int64(take) > ev.remaining {
		take = int(ev.remaining)
	}
	chunk := data[:take]
	if ev.frameOp < wsOpClose && !ev.ws.reserveMessageBytes(take) {
		ev.closing = true
		return true
	}
	wsMaskAt(chunk, ev.mask, ev.maskOff)
	ev.maskOff += take
	if ev.frameOp >= wsOpClose {
		ev.ctrlN += copy(ev.ctrl[ev.ctrlN:], chunk)
	} else {
		ev.msg = append(ev.msg, chunk...)
	}
	c.h1Advance(take)
	ev.remaining -= int64(take)
	if ev.remaining > 0 {
		return false
	}
	ev.inFrame = false
	if ev.frameOp >= wsOpClose {
		ev.controlFrame(ev.frameOp, ev.ctrl[:ev.ctrlN])
	} else if ev.frameFin {
		ev.finishMessage(ev.msg)
	}
	return true
}

func wsMaskAt(b []byte, key [4]byte, off int) {
	if r := off & 3; r != 0 {
		key = [4]byte{key[r], key[(r+1)&3], key[(r+2)&3], key[(r+3)&3]}
	}
	maskXOR(b, key)
}

func (ev *wsLoopConn) controlFrame(opcode byte, payload []byte) {
	ws := ev.ws
	switch opcode {
	case wsOpClose:
		_ = ws.handleCloseFrame(payload)
	case wsOpPing:
		_ = ws.handlePing(payload)
	}
}

func (ev *wsLoopConn) appendMessage(payload []byte) bool {
	if !ev.ws.reserveMessageBytes(len(payload)) {
		ev.closing = true
		return false
	}
	ev.msg = append(ev.msg, payload...)
	return true
}

func (ev *wsLoopConn) finishMessage(assembled []byte) {
	ws := ev.ws
	op, compressed := ev.msgOp, ev.msgCompressed
	ev.inMessage = false
	ev.msgCompressed = false
	msg, err := ws.completeMessage(op, compressed, assembled)
	if err != nil || ev.h.OnMessage == nil {
		ev.releaseMessage()
		return
	}
	ev.cbOp = op
	ev.cbMsg = msg
	ev.w.queueWSCallback(ev, wsCallbackMessage)
}

func (ev *wsLoopConn) releaseMessage() {
	ev.ws.releaseMessageBytes()
	if cap(ev.msg) > wsRetainedMsgLimit {
		ev.msg = nil
	} else {
		ev.msg = ev.msg[:0]
	}
}

func funcCodeIdentity[F any](fn F) uintptr {
	closure := *(*unsafe.Pointer)(unsafe.Pointer(&fn))
	if closure == nil {
		return 0
	}
	return *(*uintptr)(closure)
}

func (ev *wsLoopConn) callbackIdentity(kind wsCallbackKind) uintptr {
	if kind == wsCallbackClose {
		return funcCodeIdentity(ev.h.OnClose)
	}
	return funcCodeIdentity(ev.h.OnMessage)
}

func (w *epollWorker) watchInline() {
	if w.inlineWatched {
		return
	}
	w.inlineWatched = true
	w.server.inlineWatch.add(w)
}

func (w *epollWorker) queueWSClose(ev *wsLoopConn) {
	if ev.h.OnClose == nil {
		return
	}
	w.queueWSCallback(ev, wsCallbackClose)
}

func (w *epollWorker) queueWSCallback(ev *wsLoopConn, kind wsCallbackKind) {
	ev.cbKind = kind
	ev.cbPending = true
	w.wsCallbacks++
	id := ev.callbackIdentity(kind)
	if route, demoted := w.server.Router.demotedInline(id); demoted {
		ev.cbRoute = route
		w.spawned++
		w.handlers.run(ev.callbackRunner())
		return
	}
	w.inlineQ = append(w.inlineQ, inlineTask{ws: ev, route: id})
}

func (ev *wsLoopConn) callbackRunner() func() {
	if ev.cbAsyncFn == nil {
		ev.cbAsyncFn = ev.runCallbackAsync
	}
	return ev.cbAsyncFn
}

func (ev *wsLoopConn) runCallbackAsync() { ev.runCallback(false) }

func (ev *wsLoopConn) runCallback(inline bool) {
	w := ev.w
	route := ev.cbRoute
	var start int64
	if route != nil {
		start = turbo.Now()
	}
	returned := false
	defer func() {
		if route != nil {
			w.server.Router.observeDemoted(route, turbo.Since(start))
		}
		if inline {
			w.endInlineHandler(&ev.inlineSeq, !returned)
		}
		w.pushWSDone(ev)
	}()
	if ev.cbKind == wsCallbackClose {
		wsDeliverClose(w.server, ev.ws, &ev.h)
	} else {
		wsDeliverMessage(w.server, ev.ws, &ev.h, ev.cbOp, ev.cbMsg)
	}
	returned = true
}

func (w *epollWorker) pushWSDone(ev *wsLoopConn) {
	for {
		head := w.wsDone.Load()
		ev.doneNext = head
		if w.wsDone.CompareAndSwap(head, ev) {
			break
		}
	}
	w.taskPending.Store(true)
	if w.parked.Load() {
		w.wakeForShutdown()
	}
}

func (w *epollWorker) runWSDone() {
	for ev := w.wsDone.Swap(nil); ev != nil; {
		next := ev.doneNext
		ev.doneNext = nil
		w.finishWSCallback(ev)
		ev = next
	}
}

func (w *epollWorker) finishWSCallback(ev *wsLoopConn) {
	ev.cbPending = false
	ev.cbMsg = nil
	ev.cbRoute = nil
	w.wsCallbacks--
	if ev.cbKind == wsCallbackClose {
		return
	}
	ev.releaseMessage()
	if ev.closeDue {
		ev.closeDue = false
		ev.msg = nil
		w.queueWSClose(ev)
		return
	}
	c := ev.c
	if c == nil || c.ws != ev || c.fd < 0 {
		return
	}
	ev.readDeadline = deadlineFrom(int64(ev.ws.readTimeout))
	c.deadline = ev.deadline(c.outArmed)
	if c.peerHup {
		c.readPending = true
	}
	c.compactH1ReadBuffer()
	c.h1ResumeDue = true
	w.markFlush(c)
}
