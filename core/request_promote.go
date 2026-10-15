package core

import "unsafe"

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

var internedStrings = [...]string{
	internedGET, internedPOST, internedPUT, internedDELETE, internedPATCH,
	internedHEAD, internedOPTIONS, internedHTTP10, internedHTTP11,
}

func isInternedString(s string) bool {
	data := unsafe.StringData(s)
	for _, interned := range internedStrings {
		if len(interned) == len(s) && unsafe.StringData(interned) == data {
			return true
		}
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
	if r.promoteBuf == nil || r.promoteOff+n > len(r.promoteBuf) {
		size := promoteArenaChunk
		if n > size {
			size = n
		}
		r.promoteBuf = make([]byte, size)
		r.promoteOff = 0
	}
	start := r.promoteOff
	r.promoteOff += n
	return r.promoteBuf[start : start+n : start+n]
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
	if len(r.aliasBlock) > 0 {
		promoteAliasBlock(r)
		return
	}

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

func promoteAliasBlock(r *Request) {
	block := r.aliasBlock
	r.aliasBlock = nil
	buf := r.promoteAlloc(len(block))
	copy(buf, block)
	base := uintptr(unsafe.Pointer(unsafe.SliceData(block)))
	if !isInternedString(r.Method) {
		r.Method = r.rebaseAliased(r.Method, base, len(block), buf)
	}
	r.Path = r.rebaseAliased(r.Path, base, len(block), buf)
	r.RawPath = r.rebaseAliased(r.RawPath, base, len(block), buf)
	r.Query = r.rebaseAliased(r.Query, base, len(block), buf)
	if !isInternedString(r.Proto) {
		r.Proto = r.rebaseAliased(r.Proto, base, len(block), buf)
	}
	r.Host = r.rebaseAliased(r.Host, base, len(block), buf)
	if !sameStringBytes(r.RemoteAddr, r.ownedRemoteAddr) {
		r.RemoteAddr = r.rebaseAliased(r.RemoteAddr, base, len(block), buf)
	}
	r.cachedCL = r.rebaseAliased(r.cachedCL, base, len(block), buf)
	r.cachedConn = r.rebaseAliased(r.cachedConn, base, len(block), buf)
	r.cachedTE = r.rebaseAliased(r.cachedTE, base, len(block), buf)
	r.cachedHost = r.rebaseAliased(r.cachedHost, base, len(block), buf)
	r.cachedAE = r.rebaseAliased(r.cachedAE, base, len(block), buf)
	r.cachedOrigin = r.rebaseAliased(r.cachedOrigin, base, len(block), buf)
	r.cachedXFF = r.rebaseAliased(r.cachedXFF, base, len(block), buf)
	r.cachedXRI = r.rebaseAliased(r.cachedXRI, base, len(block), buf)
	r.cachedAuth = r.rebaseAliased(r.cachedAuth, base, len(block), buf)
	r.cachedUpgrade = r.rebaseAliased(r.cachedUpgrade, base, len(block), buf)
	r.cachedWSKey = r.rebaseAliased(r.cachedWSKey, base, len(block), buf)
	r.cachedWSVer = r.rebaseAliased(r.cachedWSVer, base, len(block), buf)
	for i := range r.Headers {
		r.Headers[i][0] = r.rebaseAliased(r.Headers[i][0], base, len(block), buf)
		r.Headers[i][1] = r.rebaseAliased(r.Headers[i][1], base, len(block), buf)
	}
}

func (r *Request) rebaseAliased(s string, base uintptr, blockLen int, buf []byte) string {
	if len(s) == 0 {
		return s
	}
	off := uintptr(unsafe.Pointer(unsafe.StringData(s))) - base
	if off < uintptr(blockLen) && off+uintptr(len(s)) <= uintptr(blockLen) {
		return unsafe.String(&buf[off], len(s))
	}
	own := r.promoteAlloc(len(s))
	copy(own, s)
	return unsafe.String(&own[0], len(s))
}
