//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

const h2FixInjectedContentType = "text/html\r\nSet-Cookie: injected=1\r\n\x00X: y"

func h2FixAssertNoInjectedHeader(t *testing.T, writer string, head []byte) {
	t.Helper()
	s := string(head)
	if strings.Contains(s, "\r\nSet-Cookie:") || strings.ContainsRune(s, 0) {
		t.Fatalf("%s wrote an unsanitised Content-Type:\n%q", writer, s)
	}
	if !strings.Contains(s, "Content-Type: text/htmlSet-Cookie: injected=1X: y\r\n") {
		t.Fatalf("%s did not keep the sanitised Content-Type:\n%q", writer, s)
	}
}

func TestH2FixH1ContentTypeIsSanitised(t *testing.T) {
	resp := &Response{}
	resp.Status(200).String("ok")
	resp.ContentType = h2FixInjectedContentType
	h2FixAssertNoInjectedHeader(t, "appendPlainResponse", appendPlainResponse(resp, nil))
	built, bp := BuildH1Response(resp)
	h2FixAssertNoInjectedHeader(t, "BuildH1Response", built)
	*bp = (*bp)[:0]
	LargeBufPool.Put(bp)
	h2FixAssertNoInjectedHeader(t, "appendH1StreamHead", appendH1StreamHead(nil, 200, nil, h2FixInjectedContentType, true, false, "ALOS", nil))
	if got := string(appendPlainResponse(&Response{StatusCode: 200, ContentType: "image/png"}, nil)); !strings.Contains(got, "Content-Type: image/png\r\n") {
		t.Fatalf("clean Content-Type altered: %q", got)
	}
}
