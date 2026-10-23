//go:build linux && amd64

package core

import (
	"math/bits"
	"unsafe"
)

const promoteArenaChunk = 16 << 10

const (
	internedGET     = "GET"
	internedPOST    = "POST"
	internedPUT     = "PUT"
	internedDELETE  = "DELETE"
	internedPATCH   = "PATCH"
	internedHEAD    = "HEAD"
	internedOPTIONS = "OPTIONS"
	internedHTTP10  = "HTTP/1.0"
	internedHTTP11  = "HTTP/1.1"
)

func isInternedString(s string) bool {
	data := unsafe.StringData(s)
	switch len(s) {
	case 3:
		return data == unsafe.StringData(internedGET) || data == unsafe.StringData(internedPUT)
	case 4:
		return data == unsafe.StringData(internedPOST) || data == unsafe.StringData(internedHEAD)
	case 5:
		return data == unsafe.StringData(internedPATCH)
	case 6:
		return data == unsafe.StringData(internedDELETE)
	case 7:
		return data == unsafe.StringData(internedOPTIONS)
	case 8:
		return data == unsafe.StringData(internedHTTP11) || data == unsafe.StringData(internedHTTP10)
	}
	return false
}

func sameStringBytes(a, b string) bool {
	return len(a) == len(b) && unsafe.StringData(a) == unsafe.StringData(b)
}

func (r *Request) setOwnedRemoteAddr(addr string) {
	r.RemoteAddr = addr
	r.ownedRemoteAddr = addr
}

func (r *Request) promoteAlloc(n int) []byte {
	switch {
	case r.promoteBuf == nil:
		r.promoteBuf = make([]byte, n)
		r.promoteOff = 0
	case r.promoteOff+n > len(r.promoteBuf):
		r.promoteBuf = make([]byte, max(n, promoteArenaChunk))
		r.promoteOff = 0
	}
	start := r.promoteOff
	r.promoteOff += n
	return r.promoteBuf[start : start+n : start+n]
}

type promoteArena struct {
	buf []byte
	off int
}

func (a *promoteArena) alloc(n int) []byte {
	if a.off+n > len(a.buf) {
		a.buf = make([]byte, max(n, promoteArenaChunk))
		a.off = 0
	}
	start := a.off
	a.off += n
	return a.buf[start : start+n : start+n]
}

func promoteTake(buf []byte, off int, s string) (string, int) {
	if len(s) == 0 {
		return s, off
	}
	n := copy(buf[off:], s)
	return unsafe.String(&buf[off], n), off + n
}

func promoteRequestStrings(r *Request) {
	if !r.aliasesReadBuf {
		return
	}
	r.aliasesReadBuf = false

	total := len(r.Method) + len(r.Path) + len(r.RawPath) + len(r.Query) + len(r.Proto) +
		len(r.Host) + len(r.RemoteAddr) +
		len(r.cachedCL) + len(r.cachedConn) + len(r.cachedTE) + len(r.cachedHost) +
		len(r.cachedAE) + len(r.cachedOrigin) + len(r.cachedXFF) + len(r.cachedXRI) +
		len(r.cachedAuth) + len(r.cachedUpgrade) + len(r.cachedWSKey) + len(r.cachedWSVer)
	for i := range r.Headers {
		total += len(r.Headers[i][0]) + len(r.Headers[i][1])
	}
	if total == 0 {
		return
	}

	buf := r.promoteAlloc(total)
	off := 0
	r.Method, off = promoteTake(buf, off, r.Method)
	r.Path, off = promoteTake(buf, off, r.Path)
	r.RawPath, off = promoteTake(buf, off, r.RawPath)
	r.Query, off = promoteTake(buf, off, r.Query)
	r.Proto, off = promoteTake(buf, off, r.Proto)
	r.Host, off = promoteTake(buf, off, r.Host)
	r.RemoteAddr, off = promoteTake(buf, off, r.RemoteAddr)
	r.cachedCL, off = promoteTake(buf, off, r.cachedCL)
	r.cachedConn, off = promoteTake(buf, off, r.cachedConn)
	r.cachedTE, off = promoteTake(buf, off, r.cachedTE)
	r.cachedHost, off = promoteTake(buf, off, r.cachedHost)
	r.cachedAE, off = promoteTake(buf, off, r.cachedAE)
	r.cachedOrigin, off = promoteTake(buf, off, r.cachedOrigin)
	r.cachedXFF, off = promoteTake(buf, off, r.cachedXFF)
	r.cachedXRI, off = promoteTake(buf, off, r.cachedXRI)
	r.cachedAuth, off = promoteTake(buf, off, r.cachedAuth)
	r.cachedUpgrade, off = promoteTake(buf, off, r.cachedUpgrade)
	r.cachedWSKey, off = promoteTake(buf, off, r.cachedWSKey)
	r.cachedWSVer, off = promoteTake(buf, off, r.cachedWSVer)
	for i := range r.Headers {
		r.Headers[i][0], off = promoteTake(buf, off, r.Headers[i][0])
		r.Headers[i][1], off = promoteTake(buf, off, r.Headers[i][1])
	}
}

type promoteNamedFields = [7]string

type promoteCachedFields = [12]string

type aliasRebase struct {
	base uintptr
	size uintptr
	dst  unsafe.Pointer
}

func (a *aliasRebase) rebase(s string) (string, bool) {
	off := uintptr(unsafe.Pointer(unsafe.StringData(s))) - a.base
	if off < a.size && a.size-off >= uintptr(len(s)) {
		return unsafe.String((*byte)(unsafe.Add(a.dst, off)), len(s)), true
	}
	return s, len(s) == 0
}

func (a *aliasRebase) promoteAll(r *Request, fields []string) {
	for i := range fields {
		if rebased, done := a.rebase(fields[i]); done {
			fields[i] = rebased
			continue
		}
		fields[i] = r.promoteCopy(fields[i])
	}
}

//go:noinline
func (r *Request) promoteCopy(s string) string {
	own := r.promoteAlloc(len(s))
	copy(own, s)
	return unsafe.String(&own[0], len(s))
}

func promoteRequestHead(r *Request, block []byte) {
	if !r.aliasesReadBuf {
		return
	}
	promoteRequestHeadInto(r, block, r.promoteAlloc(len(block)))
}

func promoteRequestHeadArena(r *Request, block []byte, arena *promoteArena) {
	if !r.aliasesReadBuf {
		return
	}
	promoteRequestHeadInto(r, block, arena.alloc(len(block)))
}

func promoteRequestHeadInto(r *Request, block, buf []byte) {
	r.aliasesReadBuf = false
	copy(buf, block)
	a := aliasRebase{
		base: uintptr(unsafe.Pointer(unsafe.SliceData(block))),
		size: uintptr(len(block)),
		dst:  unsafe.Pointer(unsafe.SliceData(buf)),
	}
	named := (*promoteNamedFields)(unsafe.Pointer(&r.Method))
	if !isInternedString(r.Method) {
		a.promoteAll(r, named[0:1])
	}
	a.promoteAll(r, named[1:4])
	if !isInternedString(r.Proto) {
		a.promoteAll(r, named[4:5])
	}
	a.promoteAll(r, named[5:6])
	if !sameStringBytes(r.RemoteAddr, r.ownedRemoteAddr) {
		a.promoteAll(r, named[6:7])
	}
	cached := (*promoteCachedFields)(unsafe.Pointer(&r.cachedCL))
	for m := r.headerCacheMask; m != 0; m &= m - 1 {
		if i := bits.TrailingZeros32(m); i < len(cached) {
			a.promoteAll(r, cached[i:i+1])
		}
	}
	a.promoteAll(r, unsafe.Slice((*string)(unsafe.Pointer(unsafe.SliceData(r.Headers))), 2*len(r.Headers)))
}
