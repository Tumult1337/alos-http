//go:build linux && amd64

package core

import (
	"bytes"
	"io"
	"net"
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

func TestHTTPDateBuildH1ResponseStatusRule(t *testing.T) {
	for _, status := range []int{100, 199, 600} {
		wire, bp := BuildH1Response(&Response{StatusCode: status})
		fields := dateH1Fields(t, wire)
		putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
		if got := dateValues(fields); len(got) != 0 {
			t.Fatalf("BuildH1Response status=%d Date=%q", status, got)
		}
	}
}

func TestHTTPDateWriteH1ResponseStatusRule(t *testing.T) {
	suite := &SupportedSuites[0]
	fixture := bytes.Repeat([]byte{7}, suite.HashLen)
	for _, status := range []int{199, 600} {
		writer, err := NewTrafficAEAD(suite.HashFn, fixture, suite)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := NewTrafficAEAD(suite.HashFn, fixture, suite)
		if err != nil {
			t.Fatal(err)
		}
		connection := &captureConn{}
		if err := WriteH1Response(connection, writer, &Response{StatusCode: status}); err != nil {
			t.Fatal(err)
		}
		wire := connection.buf
		size := int(wire[3])<<8 | int(wire[4])
		record, err := reader.Decrypt(bytes.Clone(wire[5 : 5+size]))
		if err != nil {
			t.Fatal(err)
		}
		plain := record[:len(record)-1]
		if !bytes.HasPrefix(plain, []byte("HTTP/1.1 "+strconv.Itoa(status))) {
			t.Fatalf("unexpected status line %q", plain)
		}
		if got := dateValues(dateH1Fields(t, plain)); len(got) != 0 {
			t.Fatalf("WriteH1Response status=%d Date=%q", status, got)
		}
	}
}

func TestHTTPDateReceiptStatusRule(t *testing.T) {
	cases := map[int]bool{99: false, 100: false, 101: true, 199: false, 200: true, 599: true, 600: false, 999: false}
	for status, want := range cases {
		parser := h1Parser{status: status}
		if got := parser.wantsReceiptDate(); got != want {
			t.Fatalf("status=%d wantsReceiptDate=%v want %v", status, got, want)
		}
	}
}

var receiptStatusCases = []struct {
	status   int
	wantDate bool
}{
	{200, true}, {404, true}, {599, true}, {600, false}, {999, false},
}

func TestHTTPDateReceiptStatusRuleFastProxyPath(t *testing.T) {
	for _, tc := range receiptStatusCases {
		connection := fpFixH1Conn("HTTP/1.1 " + strconv.Itoa(tc.status) + " X\r\nContent-Length: 0\r\n\r\n")
		connection.cur.req.ensureResponseDate = true
		if done, err := connection.h1.advance(connection); !done || err != nil {
			t.Fatalf("status=%d done=%v err=%v", tc.status, done, err)
		}
		got := dateValues(connection.h1.stringHeaders())
		if tc.wantDate {
			dateRequireCurrent(t, connection.h1.stringHeaders())
		} else if len(got) != 0 {
			t.Fatalf("status=%d forwarded Date=%q", tc.status, got)
		}
	}
}

func TestHTTPDateReceiptStatusRuleUpgradeAnswerPath(t *testing.T) {
	cases := append([]struct {
		status   int
		wantDate bool
	}{{101, true}}, receiptStatusCases...)
	for _, tc := range cases {
		client, backend := net.Pipe()
		go func() {
			defer backend.Close()
			_, _ = io.WriteString(backend, "HTTP/1.1 "+strconv.Itoa(tc.status)+" X\r\nContent-Length: 0\r\n\r\n")
		}()
		var parser h1Parser
		_, _, err := readUpgradeAnswer(client, &parser, "GET", proxyFixIOTimeout)
		client.Close()
		if err != nil {
			t.Fatalf("status=%d err=%v", tc.status, err)
		}
		got := dateValues(parser.stringHeaders())
		if tc.wantDate {
			dateRequireCurrent(t, parser.stringHeaders())
		} else if len(got) != 0 {
			t.Fatalf("status=%d forwarded Date=%q", tc.status, got)
		}
	}
}
