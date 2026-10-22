//go:build linux && amd64

package core

import (
	"bufio"
	"math/bits"
	"sync"
	"sync/atomic"
	"unsafe"
	"weak"
)

// RecordBufPool pools byte slices sized to hold a maximum-size TLS record plus its 5-byte header.
var RecordBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, MaxRecordSize+5); return &b },
}

// SmallBufPool pools 512-byte scratch buffers.
var SmallBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 512); return &b },
}

// MediumBufPool pools 4096-byte scratch buffers.
var MediumBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 4096); return &b },
}

// LargeBufPool pools 32768-byte scratch buffers.
const largeBufPoolMaxCap = 1 << 20

var LargeBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 32768); return &b },
}

// HdrBufPool pools 5-byte buffers sized for a TLS record header.
var HdrBufPool = sync.Pool{
	New: func() any { b := make([]byte, 5); return &b },
}

// RequestPool pools reusable Request objects.
var RequestPool = sync.Pool{
	New: func() any {
		return &Request{
			Headers: make([][2]string, 0, 16),
			Body:    make([]byte, 0, 1024),
		}
	},
}

// ResponsePool pools reusable Response objects.
var ResponsePool = sync.Pool{
	New: func() any {
		return &Response{
			Headers: make([][2]string, 0, 8),
			body:    make([]byte, 0, 4096),
		}
	},
}

func releaseRequestToPool(r *Request) {
	if r == nil {
		return
	}
	r.Reset()
	RequestPool.Put(r)
}

func releaseResponseToPool(r *Response) {
	if r == nil {
		return
	}
	r.Reset()
	ResponsePool.Put(r)
}

// WriteBufPool pools byte slices sized for a maximum-size TLS record, used for outgoing writes.
var WriteBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, MaxRecordSize); return &b },
}

// StreamPool pools reusable H2Stream objects.
var StreamPool = sync.Pool{
	New: func() any { return &H2Stream{} },
}

// FileReadBufPool pools 65536-byte buffers used for file read operations.
var FileReadBufPool = sync.Pool{
	New: func() any { b := make([]byte, 65536); return &b },
}

// H1StreamWriterPool pools reusable H1StreamWriter objects.
var H1StreamWriterPool = sync.Pool{
	New: func() any { return &H1StreamWriter{} },
}

// PlainH1StreamWriterPool pools reusable PlainH1StreamWriter objects.
var PlainH1StreamWriterPool = sync.Pool{
	New: func() any { return &PlainH1StreamWriter{} },
}

// H2FramePool pools reusable H2Frame objects.
var H2FramePool = sync.Pool{
	New: func() any {
		return &H2Frame{
			Payload: make([]byte, 0, 1024),
		}
	},
}

// BufReaderPool pools bufio.Reader instances sized with a 65536-byte buffer.
var BufReaderPool = sync.Pool{
	New: func() any { return bufio.NewReaderSize(nil, 65536) },
}

const (
	connReadBufDefaultCap  = 8192
	connWriteBufDefaultCap = 16384
	connBodyBufDefaultCap  = 4096
	connBufPoolMaxCap      = 256 << 10
)

var connReadBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, connReadBufDefaultCap); return &b },
}

var connWriteBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, connWriteBufDefaultCap); return &b },
}

var connBodyBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, connBodyBufDefaultCap); return &b },
}

var bufBoxPool = sync.Pool{
	New: func() any { return new([]byte) },
}

func acquirePooledBuf(pool *sync.Pool) []byte {
	bp := pool.Get().(*[]byte)
	buf := (*bp)[:0]
	*bp = nil
	bufBoxPool.Put(bp)
	return buf
}

func putBoxedBufCapped(pool *sync.Pool, bp *[]byte, maxCap int) {
	if cap(*bp) > maxCap {
		return
	}
	*bp = (*bp)[:0]
	pool.Put(bp)
}

func releasePooledBuf(pool *sync.Pool, buf []byte, maxCap int) {
	if cap(buf) == 0 || cap(buf) > maxCap {
		return
	}
	bp := bufBoxPool.Get().(*[]byte)
	*bp = buf[:0]
	pool.Put(bp)
}

const (
	epollReadBufCap        = 8192
	epollReadBufPoolMaxCap = 3 * epollReadBufCap
)

var epollReadBufPool = sync.Pool{
	New: func() any { b := make([]byte, epollReadBufCap); return &b },
}

var tlsScratchPool = sync.Pool{
	New: func() any { b := make([]byte, 0, MaxRecordPayload); return &b },
}

// HpackDecoderPool pools reusable HPACK decoders.
var HpackDecoderPool = sync.Pool{
	New: func() any { return NewHpackDecoder() },
}

var clientHelloPool = sync.Pool{
	New: func() any { return &ParsedClientHello{} },
}

const (
	epollIOBufCap        = 2048
	epollIOBufPoolMaxCap = 128 << 10
)

var epollIOBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, epollIOBufCap); return &b },
}

func acquireIOBuf() []byte {
	return acquirePooledBuf(&epollIOBufPool)
}

func releaseIOBuf(b []byte) {
	if cap(b) > epollIOBufPoolMaxCap {
		largeBufs.put(b)
		return
	}
	releasePooledBuf(&epollIOBufPool, b, epollIOBufPoolMaxCap)
}

func growIOBuf(b []byte, extra int) []byte {
	need := len(b) + extra
	if extra <= 0 || need <= cap(b) || need <= epollIOBufPoolMaxCap {
		return b
	}
	return append(largeBufs.get(need), b...)
}

const bodyPoolMinCap = 32 << 10

func appendPooled(dst, src []byte) []byte {
	need := len(dst) + len(src)
	if need <= cap(dst) || need < bodyPoolMinCap {
		return append(dst, src...)
	}
	return append(append(largeBufs.get(need), dst...), src...)
}

func recycleBodyBuf(buf []byte) []byte {
	if cap(buf) <= bufferShrinkThreshold {
		return buf[:0]
	}
	releaseIOBuf(buf)
	return nil
}

const (
	largeBufMinShift      = 15
	largeBufMaxShift      = 22
	largeBufStepsPerShift = 4
	largeBufClassCount    = (largeBufMaxShift-largeBufMinShift)*largeBufStepsPerShift + 1
	largeBufMaxPerClass   = 4096
)

func largeBufClassSize(class int) int {
	shift := largeBufMinShift + class/largeBufStepsPerShift
	step := class % largeBufStepsPerShift
	return 1<<shift + step<<(shift-2)
}

func largeBufClassAtLeast(n int) int {
	switch {
	case n <= 1<<largeBufMinShift:
		return 0
	case n > 1<<largeBufMaxShift:
		return -1
	}
	shift := bits.Len(uint(n-1)) - 1
	step := (n - 1<<shift + 1<<(shift-2) - 1) >> (shift - 2)
	return (shift-largeBufMinShift)*largeBufStepsPerShift + step
}

func largeBufClassAtMost(n int) int {
	switch {
	case n < 1<<largeBufMinShift:
		return -1
	case n >= 1<<largeBufMaxShift:
		return largeBufClassCount - 1
	}
	shift := bits.Len(uint(n)) - 1
	step := (n - 1<<shift) >> (shift - 2)
	return (shift-largeBufMinShift)*largeBufStepsPerShift + step
}

type weakLargeBuf struct {
	data weak.Pointer[byte]
	size int
}

const (
	largeBufStrongMaxCap = 128 << 10
	largeBufStrongBudget = 4 << 20
)

type largeBufPool struct {
	mu          sync.Mutex
	maxPerClass int
	strongBytes int
	getBytes    atomic.Uint64
	strong      [largeBufClassCount][][]byte
	classes     [largeBufClassCount][]weakLargeBuf
}

var largeBufs = largeBufPool{maxPerClass: largeBufMaxPerClass}

const (
	largeQuietRatio = 16
	largeNudgeTries = 6
)

type largeBufNudge struct {
	last, peak uint64
	tries      int
}

func (n *largeBufNudge) observe(total uint64) bool {
	recent := total - n.last
	n.last = total
	n.peak = max(n.peak, recent)
	return n.peak > 0 && recent < n.peak/largeQuietRatio
}

func (n *largeBufNudge) settle() { n.peak, n.tries = 0, 0 }

func (n *largeBufNudge) retrying() bool { return n.tries > 0 }

func (n *largeBufNudge) retry() {
	n.tries++
	if n.tries >= largeNudgeTries {
		n.settle()
	}
}

func (p *largeBufPool) get(n int) []byte {
	class := largeBufClassAtLeast(n)
	if class < 0 {
		return make([]byte, 0, n)
	}
	p.getBytes.Add(uint64(n))
	p.mu.Lock()
	list := p.classes[class]
	for len(list) > 0 {
		e := list[len(list)-1]
		list[len(list)-1] = weakLargeBuf{}
		list = list[:len(list)-1]
		if data := e.data.Value(); data != nil {
			p.classes[class] = list
			p.mu.Unlock()
			return unsafe.Slice(data, e.size)[:0]
		}
	}
	p.classes[class] = list
	if held := p.strong[class]; len(held) > 0 {
		b := held[len(held)-1]
		held[len(held)-1] = nil
		p.strong[class] = held[:len(held)-1]
		p.strongBytes -= cap(b)
		p.mu.Unlock()
		return b[:0]
	}
	p.mu.Unlock()
	return make([]byte, 0, largeBufClassSize(class))
}

func (p *largeBufPool) put(b []byte) bool {
	class := largeBufClassAtMost(cap(b))
	if class < 0 || cap(b) != largeBufClassSize(class) {
		return false
	}
	if cap(b) <= largeBufStrongMaxCap {
		p.mu.Lock()
		if p.strongBytes+cap(b) <= largeBufStrongBudget {
			p.strong[class] = append(p.strong[class], b[:0])
			p.strongBytes += cap(b)
			p.mu.Unlock()
			return true
		}
		p.mu.Unlock()
	}
	entry := weakLargeBuf{data: weak.Make(unsafe.SliceData(b)), size: cap(b)}
	p.mu.Lock()
	if len(p.classes[class]) >= p.maxPerClass {
		p.classes[class] = dropCollectedLargeBufs(p.classes[class])
	}
	if len(p.classes[class]) < p.maxPerClass {
		p.classes[class] = append(p.classes[class], entry)
	}
	p.mu.Unlock()
	return true
}

func dropCollectedLargeBufs(list []weakLargeBuf) []weakLargeBuf {
	live := list[:0]
	for _, e := range list {
		if e.data.Value() != nil {
			live = append(live, e)
		}
	}
	clear(list[len(live):])
	return live
}

func acquireEpollReadBuf() []byte {
	bp := epollReadBufPool.Get().(*[]byte)
	b := *bp
	*bp = nil
	bufBoxPool.Put(bp)
	if cap(b) < epollReadBufCap {
		b = make([]byte, epollReadBufCap)
	}
	return b[:cap(b)]
}

func releaseEpollReadBuf(b []byte) {
	if cap(b) == 0 || cap(b) > epollReadBufPoolMaxCap {
		return
	}
	bp := bufBoxPool.Get().(*[]byte)
	*bp = b
	epollReadBufPool.Put(bp)
}
