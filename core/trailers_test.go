//go:build linux && amd64

package core

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestTrailerFieldForbidden(t *testing.T) {
	forbidden := []string{"host", "Host", "trailer", "TRAILER", "connection", "Connection", "content-length", "Content-Length", "transfer-encoding", "Transfer-Encoding"}
	for _, name := range forbidden {
		if !trailerFieldForbidden(name) {
			t.Errorf("%q allowed", name)
		}
	}
	allowed := []string{"x-checksum", "Grpc-Status", "server-timing", "hostx", "trailers", "content-type", "x", ""}
	for _, name := range allowed {
		if trailerFieldForbidden(name) {
			t.Errorf("%q forbidden", name)
		}
	}
}

func TestSplitTrailerLine(t *testing.T) {
	long := "X-" + strings.Repeat("a", 40)
	valid := []struct{ line, name, value string }{
		{"X-Checksum: 1\r\n", "X-Checksum", "1"},
		{"x-a:\t two words \t\r\n", "x-a", "two words"},
		{"x-empty:\r\n", "x-empty", ""},
		{long + ": " + long + "\r\n", long, long},
	}
	for _, tc := range valid {
		name, value, ok := splitTrailerLine([]byte(tc.line))
		if !ok || string(name) != tc.name || string(value) != tc.value {
			t.Errorf("%q -> %q %q %v", tc.line, name, value, ok)
		}
	}
	invalid := []string{
		"X-A: 1\n",
		"X-A: 1",
		"X-A: a\x01b\r\n",
		"X-A: a\rb\r\n",
		" folded: 1\r\n",
		"X-A : 1\r\n",
		"NoColon\r\n",
		": empty-name\r\n",
		"X(A): 1\r\n",
		"X-A: a\x7fb\r\n",
		long + ": a\x00b" + long + "\r\n",
	}
	for _, line := range invalid {
		if _, _, ok := splitTrailerLine([]byte(line)); ok {
			t.Errorf("accepted %q", line)
		}
	}
}

func decodeAllChunked(t *testing.T, wire string, capture bool) ([]byte, [][2]string, error) {
	t.Helper()
	d := chunkedDecoder{captureTrailers: capture}
	src := []byte(wire)
	var body []byte
	for !d.done() {
		n, data, err := d.next(src)
		if err != nil {
			return nil, nil, err
		}
		if n == 0 {
			return nil, nil, io.ErrUnexpectedEOF
		}
		body = append(body, data...)
		src = src[n:]
	}
	return body, d.trailers, nil
}

func TestChunkedDecoderTrailers(t *testing.T) {
	wire := "5\r\nhello\r\n0\r\nX-Checksum: 1\r\nContent-Length: 9\r\nX-B:  two \r\nHost: evil\r\n\r\n"
	body, trailers, err := decodeAllChunked(t, wire, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Fatalf("body %q", body)
	}
	want := [][2]string{{"X-Checksum", "1"}, {"X-B", "two"}}
	if !reflect.DeepEqual(trailers, want) {
		t.Fatalf("trailers %q, want %q", trailers, want)
	}
	_, trailers, err = decodeAllChunked(t, wire, false)
	if err != nil || trailers != nil {
		t.Fatalf("capture off: trailers %q err %v", trailers, err)
	}
	_, trailers, err = decodeAllChunked(t, "0\r\n\r\n", true)
	if err != nil || trailers != nil {
		t.Fatalf("no trailers: %q %v", trailers, err)
	}
}

func TestChunkedDecoderRejectsMalformedTrailers(t *testing.T) {
	for _, wire := range []string{
		"0\r\nbad line\r\n\r\n",
		"0\r\nX-A: 1\n\r\n",
		"0\r\n folded: x\r\n\r\n",
		"0\r\nX-A: a\x01\r\n\r\n",
		"0\r\nX A: 1\r\n\r\n",
	} {
		for _, capture := range []bool{false, true} {
			if _, _, err := decodeAllChunked(t, wire, capture); !errors.Is(err, errChunkedMalformed) {
				t.Errorf("%q capture=%v: err %v", wire, capture, err)
			}
		}
		if _, status, _ := asyncChunkedComplete([]byte(wire), 0); status != -1 {
			t.Errorf("%q: asyncChunkedComplete status %d, want -1", wire, status)
		}
	}
}

func TestChunkedTrailerSectionStaysBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("0\r\n")
	for b.Len() <= chunkedFramingLineMax {
		b.WriteString("X-Pad: aaaaaaaaaaaaaaaa\r\n")
	}
	b.WriteString("\r\n")
	if _, _, err := decodeAllChunked(t, b.String(), true); !errors.Is(err, errChunkedMalformed) {
		t.Fatalf("oversized trailer section err %v", err)
	}
}

func TestH2TrailerFields(t *testing.T) {
	got, ok := h2TrailerFields([][2]string{{"x-checksum", "1"}, {"content-length", "3"}, {"grpc-status", "0"}})
	want := [][2]string{{"x-checksum", "1"}, {"grpc-status", "0"}}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q ok %v", got, ok)
	}
	for _, bad := range [][2]string{
		{":path", "/x"},
		{"X-Upper", "1"},
		{"x-a", "a\r\nb"},
		{"x-a", "a\x00"},
		{"x-a", " padded"},
		{"connection", "close"},
		{"transfer-encoding", "chunked"},
		{"te", "gzip"},
		{"", "v"},
	} {
		if _, ok := h2TrailerFields([][2]string{{"x-ok", "1"}, bad}); ok {
			t.Errorf("trailer %q accepted", bad)
		}
	}
	if got, ok := h2TrailerFields([][2]string{{"te", "trailers"}}); !ok || len(got) != 1 {
		t.Fatalf("te: trailers rejected: %q %v", got, ok)
	}
	if got, ok := h2TrailerFields(nil); !ok || got != nil {
		t.Fatalf("empty trailers: %q %v", got, ok)
	}
}

func TestBodyReaderTrailers(t *testing.T) {
	b := newBodyReader(func() {})
	b.push([]byte("abc"))
	trailers := [][2]string{{"x-sum", "6"}}
	b.finishWithTrailers(trailers)
	data, err := io.ReadAll(b)
	if err != nil || string(data) != "abc" {
		t.Fatalf("read %q %v", data, err)
	}
	if !reflect.DeepEqual(b.Trailers(), trailers) {
		t.Fatalf("Trailers %q", b.Trailers())
	}

	aborted := newBodyReader(func() {})
	aborted.finish(ErrBodyStreamAborted)
	aborted.finishWithTrailers(trailers)
	if aborted.Trailers() != nil {
		t.Fatal("trailers stored after an aborted body")
	}
}

func TestRequestTrailersAccessor(t *testing.T) {
	trailers := [][2]string{{"x-a", "1"}}
	r := &Request{trailers: trailers}
	if !reflect.DeepEqual(r.Trailers(), trailers) {
		t.Fatalf("buffered Trailers %q", r.Trailers())
	}
	b := newBodyReader(func() {})
	b.finishWithTrailers([][2]string{{"x-b", "2"}})
	r.bodyStream = b
	if got := r.Trailers(); len(got) != 1 || got[0][0] != "x-b" {
		t.Fatalf("streamed Trailers %q", got)
	}
	for _, reset := range []func(*Request){(*Request).Reset, (*Request).resetFastH1} {
		r := &Request{trailers: trailers}
		reset(r)
		if r.Trailers() != nil {
			t.Fatal("reset kept trailers")
		}
	}
}
