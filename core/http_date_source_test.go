//go:build linux && amd64

package core

import (
	"net/http"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/guno1928/turbo"
)

const sharedDateUnix int64 = 1000000000
const sharedDateText = "Sun, 09 Sep 2001 01:46:40 GMT"

func installSharedDate(t *testing.T) {
	t.Helper()
	installDateUnix(t, sharedDateUnix)
}

func installDateUnix(t *testing.T, unix int64) {
	t.Helper()
	previous := currentDateLine.Load()
	currentDateLine.Store(newHTTPDateLine(unix*int64(time.Second), turbo.Now()+int64(time.Hour)))
	t.Cleanup(func() { currentDateLine.Store(previous) })
}

func requireSharedDate(t *testing.T, view string, fields [][2]string) {
	t.Helper()
	if got := dateValues(fields); len(got) != 1 || got[0] != sharedDateText {
		t.Fatalf("%s Date=%q want %q", view, got, sharedDateText)
	}
}

func TestHTTPDateEveryViewReadsSharedEntry(t *testing.T) {
	installSharedDate(t)
	response := &Response{StatusCode: 200}
	requireSharedDate(t, "h1", dateH1Fields(t, appendPlainResponse(&Response{StatusCode: 404}, nil)))
	requireSharedDate(t, "h1-ok", dateH1Fields(t, appendPlainResponse(response, nil)))
	requireSharedDate(t, "h1-stream", dateH1Fields(t, appendH1StreamHead(nil, 200, nil, "", false, true, "ALOS", nil)))
	requireSharedDate(t, "proxy", dateH1Fields(t, appendProxyResponseHead(nil, 200, respHeaders{}, 0, false, "")))

	enc := HpackEncoder{}
	encodeH2ResponseHeaders(&enc, 200, "", 0, nil, "ALOS")
	h2fields, err := newHpackDecoder(4096).Decode(enc.Buf)
	if err != nil {
		t.Fatal(err)
	}
	requireSharedDate(t, "h2", h2fields)

	var table hpackEncTable
	table.reset()
	indexed := HpackEncoder{}
	encodeH2ResponseHeadersIndexed(&indexed, &table, 200, "", 0, nil, "ALOS")
	indexedFields, err := newHpackDecoder(4096).Decode(indexed.Buf)
	if err != nil {
		t.Fatal(err)
	}
	requireSharedDate(t, "h2-indexed", indexedFields)

	bp := qpackEncodeResponseHeaders(200, "", 0, nil, "ALOS")
	var decoder QPACKDecoder
	h3fields, err := decoder.Decode(*bp)
	putBoxedBufCapped(&qpackEncodeBufPool, bp, qpackEncodeBufPoolMaxCap)
	if err != nil {
		t.Fatal(err)
	}
	requireSharedDate(t, "h3", h3fields)

	var parser h1Parser
	parser.addReceiptDate()
	requireSharedDate(t, "receipt", parser.stringHeaders())

	if got := string(appendProxyDate(nil, 200, respHeaders{})); got != "Date: "+sharedDateText+"\r\n" {
		t.Fatalf("appendProxyDate=%q", got)
	}
}

func TestHTTPDateStatusRuleAllProtocols(t *testing.T) {
	for _, status := range []int{100, 101, 199, 600} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			if got := dateValues(dateH1Fields(t, appendPlainResponse(&Response{StatusCode: status}, nil))); len(got) != 0 {
				t.Fatalf("h1 Date=%q", got)
			}
			if got := dateValues(dateH1Fields(t, appendH1StreamHead(nil, status, nil, "", false, true, "ALOS", nil))); len(got) != 0 {
				t.Fatalf("h1-stream Date=%q", got)
			}
			enc := HpackEncoder{}
			encodeH2ResponseHeaders(&enc, status, "", 0, nil, "ALOS")
			fields, err := newHpackDecoder(4096).Decode(enc.Buf)
			if err != nil {
				t.Fatal(err)
			}
			if got := dateValues(fields); len(got) != 0 {
				t.Fatalf("h2 Date=%q", got)
			}
			var table hpackEncTable
			table.reset()
			indexed := HpackEncoder{}
			encodeH2ResponseHeadersIndexed(&indexed, &table, status, "", 0, nil, "ALOS")
			indexedFields, err := newHpackDecoder(4096).Decode(indexed.Buf)
			if err != nil {
				t.Fatal(err)
			}
			if got := dateValues(indexedFields); len(got) != 0 {
				t.Fatalf("h2-indexed Date=%q", got)
			}
			if got := responseDateValue(status, nil); got != "" {
				t.Fatalf("h3 Date=%q", got)
			}
			if got := appendProxyDate(nil, status, respHeaders{}); len(got) != 0 {
				t.Fatalf("proxy Date=%q", got)
			}
		})
	}
}
func TestHTTPDateTextIsOneEntry(t *testing.T) {
	installSharedDate(t)
	entry := currentHTTPDate()
	if entry != currentHTTPDate() {
		t.Fatal("clock returned two entries within one second")
	}
	if got := unsafe.StringData(responseDateValue(200, nil)); got != unsafe.StringData(entry.text) {
		t.Fatal("response Date text is not the entry text")
	}
	if got := responseHeaderValue([]byte("date"), []byte(sharedDateText)); unsafe.StringData(got) != unsafe.StringData(entry.text) {
		t.Fatal("materialized Date does not intern the entry text")
	}
	if &currentH2DateField()[len(h2DateFieldPrefix)] != &entry.h2[len(h2DateFieldPrefix)] {
		t.Fatal("H2 field is not part of the entry")
	}
	if entry.text != sharedDateText || string(entry.line[len(dateHeaderPrefix):httpDateLineLen-2]) != sharedDateText {
		t.Fatalf("entry views disagree: text=%q line=%q", entry.text, entry.line[:])
	}
	if string(entry.h2[len(h2DateFieldPrefix):]) != sharedDateText {
		t.Fatalf("H2 view=%q", entry.h2)
	}
}

func TestHTTPDateH2MemoFollowsEntry(t *testing.T) {
	var table hpackEncTable
	table.reset()
	decoder := newHpackDecoder(4096)
	encodeAt := func(unix int64) string {
		installDateUnix(t, unix)
		enc := HpackEncoder{}
		encodeH2ResponseHeadersIndexed(&enc, &table, 200, "text/plain", 5, nil, "ALOS")
		fields, err := decoder.Decode(enc.Buf)
		if err != nil {
			t.Fatal(err)
		}
		values := dateValues(fields)
		if len(values) != 1 {
			t.Fatalf("Date=%q", values)
		}
		return values[0]
	}
	for range 4 {
		if got := encodeAt(sharedDateUnix); got != sharedDateText {
			t.Fatalf("Date=%q want %q", got, sharedDateText)
		}
	}
	if table.headMemo == nil {
		t.Fatal("memo did not engage")
	}
	next := time.Unix(sharedDateUnix+1, 0).UTC().Format(http.TimeFormat)
	if got := encodeAt(sharedDateUnix + 1); got != next {
		t.Fatalf("memo served Date=%q want %q", got, next)
	}
}
