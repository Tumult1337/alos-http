package core

import (
	"strings"
	"testing"
	"unsafe"
)

const promoteBlockRaw = "PATCHX /a/b/../c?x=1&y=2 HTTP/1.0\r\nHost: h.example\r\nContent-Length: 5\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\nAccept-Encoding: gzip\r\nOrigin: https://o\r\nX-Forwarded-For: 1.2.3.4\r\nX-Real-IP: 5.6.7.8\r\nAuthorization: Bearer t\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k==\r\nSec-WebSocket-Version: 13\r\nCookie: a=b; c=d\r\nX-Empty:\r\n\r\nBODY!GET / HTTP/1.1\r\n\r\n"

func promoteBlockFields(r *Request) []string {
	fields := []string{r.Method, r.Path, r.RawPath, r.Query, r.Proto, r.Host, r.RemoteAddr, r.cachedCL, r.cachedConn, r.cachedTE,
		r.cachedHost, r.cachedAE, r.cachedOrigin, r.cachedXFF, r.cachedXRI, r.cachedAuth, r.cachedUpgrade, r.cachedWSKey, r.cachedWSVer}
	for _, header := range r.Headers {
		fields = append(fields, header[0], header[1])
	}
	return fields
}

func stringInsideBuffer(s string, buf []byte) bool {
	if len(s) == 0 || len(buf) == 0 {
		return false
	}
	start := uintptr(unsafe.Pointer(unsafe.StringData(s)))
	bufStart := uintptr(unsafe.Pointer(&buf[:1][0]))
	return start >= bufStart && start < bufStart+uintptr(cap(buf))
}

func parsePromoteBlockRequest(t *testing.T) (*Request, []byte) {
	t.Helper()
	buf := make([]byte, 4096)
	n := copy(buf, promoteBlockRaw)
	var req Request
	req.resetFastH1()
	_, _, _, _, _, _, _, ok := ParseH1RequestHead(buf[:n], &req, 0, 0)
	if !ok {
		t.Fatal("head did not parse")
	}
	if len(req.aliasBlock) == 0 {
		t.Fatal("aliasBlock is not set")
	}
	req.Host = req.cachedHost
	return &req, buf
}

func overwriteBuffer(buf []byte) {
	for i := range buf {
		buf[i] = '#'
	}
}

func TestPromoteBlockPathKeepsEveryField(t *testing.T) {
	req, buf := parsePromoteBlockRequest(t)
	want := make([]string, 0, 64)
	for _, field := range promoteBlockFields(req) {
		want = append(want, strings.Clone(field))
	}
	promoteRequestStrings(req)
	overwriteBuffer(buf)
	got := promoteBlockFields(req)
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("field %d changed after buffer reuse: %q want %q", i, got[i], want[i])
		}
		if stringInsideBuffer(got[i], buf) {
			t.Errorf("field %d still aliases the read buffer", i)
		}
	}
	if req.Method != "PATCHX" || req.Query != "x=1&y=2" || req.Header("Cookie") != "a=b; c=d" {
		t.Fatalf("unexpected promoted fields: %q %q %q", req.Method, req.Query, req.Header("Cookie"))
	}
	if req.Header("Authorization") != "Bearer t" {
		t.Fatalf("authorization header changed: %q", req.Header("Authorization"))
	}
}

func TestPromoteBlockPathKeepsCookiesAndParams(t *testing.T) {
	req, buf := parsePromoteBlockRequest(t)
	promoteRequestStrings(req)
	req.SetParam("id", req.Path[1:4])
	req.SetParam("q", req.Query)
	cookies := req.Cookies()
	overwriteBuffer(buf)
	if len(cookies) != 2 || cookies[0].Name != "a" || cookies[0].Value != "b" || cookies[1].Name != "c" || cookies[1].Value != "d" {
		t.Fatalf("cookies changed after buffer reuse: %+v", cookies)
	}
	if req.ParamValue("id") != "a/c" || req.ParamValue("q") != "x=1&y=2" {
		t.Fatalf("params changed after buffer reuse: %q %q", req.ParamValue("id"), req.ParamValue("q"))
	}
}

func TestPromoteBlockPathCopiesReadBufferFieldsOutsideHead(t *testing.T) {
	req, buf := parsePromoteBlockRequest(t)
	bodyStart := strings.Index(promoteBlockRaw, "BODY!")
	req.RemoteAddr = unsafe.String(&buf[bodyStart], 3)
	req.Query = unsafe.String(&buf[bodyStart], 5)
	promoteRequestStrings(req)
	overwriteBuffer(buf)
	if req.RemoteAddr != "BOD" {
		t.Fatalf("RemoteAddr changed after buffer reuse: %q", req.RemoteAddr)
	}
	if req.Query != "BODY!" {
		t.Fatalf("Query changed after buffer reuse: %q", req.Query)
	}
}

func TestPromoteBlockPathCopiesFieldsBeforeHeadAndInOtherBuffer(t *testing.T) {
	const prefix = "GET /previous-request HTTP/1.1\r\nHost: p\r\n\r\n"
	if len(prefix) < 33 {
		t.Fatal("prefix is too short")
	}
	buf := make([]byte, 4096)
	headStart := copy(buf, prefix)
	n := headStart + copy(buf[headStart:], promoteBlockRaw)
	var req Request
	req.resetFastH1()
	_, _, _, _, _, _, _, ok := ParseH1RequestHead(buf[headStart:n], &req, 0, 0)
	if !ok {
		t.Fatal("head did not parse")
	}
	if len(req.aliasBlock) == 0 {
		t.Fatal("aliasBlock is not set")
	}
	other := []byte("other-buffer-value")
	req.Query = unsafe.String(&buf[4], 12)
	req.RemoteAddr = unsafe.String(&other[0], len(other))
	wantQuery := strings.Clone(req.Query)
	wantRemote := strings.Clone(req.RemoteAddr)
	promoteRequestStrings(&req)
	overwriteBuffer(buf)
	overwriteBuffer(other)
	if req.Query != wantQuery {
		t.Errorf("Query before head changed after buffer reuse: %q want %q", req.Query, wantQuery)
	}
	if req.RemoteAddr != wantRemote {
		t.Errorf("RemoteAddr in other buffer changed after buffer reuse: %q want %q", req.RemoteAddr, wantRemote)
	}
}

func TestPromoteBlockPathCopiesMethodAndProtoInReadBuffer(t *testing.T) {
	req, buf := parsePromoteBlockRequest(t)
	req.Method = unsafe.String(&buf[0], 3)
	req.Proto = unsafe.String(&buf[len(promoteBlockRaw)-8], 8)
	wantMethod := strings.Clone(req.Method)
	wantProto := strings.Clone(req.Proto)
	promoteRequestStrings(req)
	if stringInsideBuffer(req.Method, buf) || stringInsideBuffer(req.Proto, buf) {
		t.Fatal("Method or Proto still aliases the read buffer")
	}
	overwriteBuffer(buf)
	if req.Method != wantMethod || req.Proto != wantProto {
		t.Fatalf("Method or Proto changed after buffer reuse: %q %q", req.Method, req.Proto)
	}
}

func TestPromoteBlockPathKeepsInternedAndOwnedStrings(t *testing.T) {
	const raw = "GET /p HTTP/1.1\r\nHost: h\r\n\r\n"
	buf := make([]byte, 256)
	n := copy(buf, raw)
	var req Request
	req.resetFastH1()
	if _, _, _, _, _, _, _, ok := ParseH1RequestHead(buf[:n], &req, 0, 0); !ok {
		t.Fatal("head did not parse")
	}
	owned := strings.Clone("203.0.113.9:4242")
	req.setOwnedRemoteAddr(owned)
	method, proto := req.Method, req.Proto
	promoteRequestStrings(&req)
	if !sameStringBytes(req.Method, method) || !sameStringBytes(req.Proto, proto) {
		t.Fatal("interned Method or Proto was copied")
	}
	if !sameStringBytes(req.RemoteAddr, owned) {
		t.Fatal("owned RemoteAddr was copied")
	}
}

func TestPromoteBlockPathCopiesRemoteAddrReplacedAfterOwnedSet(t *testing.T) {
	req, buf := parsePromoteBlockRequest(t)
	req.setOwnedRemoteAddr(strings.Clone("203.0.113.9:4242"))
	xff := strings.Index(promoteBlockRaw, "1.2.3.4")
	req.RemoteAddr = unsafe.String(&buf[xff], 7)
	promoteRequestStrings(req)
	overwriteBuffer(buf)
	if req.RemoteAddr != "1.2.3.4" {
		t.Fatalf("RemoteAddr changed after buffer reuse: %q", req.RemoteAddr)
	}
}

func TestPromoteBlockPathComparesPointersNotContent(t *testing.T) {
	req, buf := parsePromoteBlockRequest(t)
	const address = "203.0.113.9:4242"
	tail := len(promoteBlockRaw)
	methodAt := tail
	protoAt := methodAt + len(internedGET)
	addressAt := protoAt + len(internedHTTP11)
	copy(buf[methodAt:], internedGET)
	copy(buf[protoAt:], internedHTTP11)
	copy(buf[addressAt:], address)
	req.Method = unsafe.String(&buf[methodAt], len(internedGET))
	req.Proto = unsafe.String(&buf[protoAt], len(internedHTTP11))
	req.RemoteAddr = unsafe.String(&buf[addressAt], len(address))
	req.ownedRemoteAddr = strings.Clone(address)
	promoteRequestStrings(req)
	overwriteBuffer(buf)
	if req.Method != internedGET || req.Proto != internedHTTP11 || req.RemoteAddr != address {
		t.Fatalf("fields changed after buffer reuse: %q %q %q", req.Method, req.Proto, req.RemoteAddr)
	}
	for _, field := range []string{req.Method, req.Proto, req.RemoteAddr} {
		if stringInsideBuffer(field, buf) {
			t.Fatalf("field %q still aliases the read buffer", field)
		}
	}
}
