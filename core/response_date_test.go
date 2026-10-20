//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
)

func dateH1Fields(t *testing.T, wire []byte) [][2]string {
	t.Helper()
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(wire)), nil)
	if err != nil {
		t.Fatal(err)
	}
	var fields [][2]string
	for name, values := range response.Header {
		for _, value := range values {
			fields = append(fields, [2]string{name, value})
		}
	}
	return fields
}

func dateValues(fields [][2]string) []string {
	var values []string
	for _, field := range fields {
		if EqualFoldASCII(field[0], "date") {
			values = append(values, field[1])
		}
	}
	return values
}

func dateRequireCurrent(t *testing.T, fields [][2]string) {
	t.Helper()
	values := dateValues(fields)
	if len(values) != 1 {
		t.Fatalf("Date values=%q, want exactly one", values)
	}
	parsed, err := http.ParseTime(values[0])
	if err != nil {
		t.Fatal(err)
	}
	if delta := time.Since(parsed); delta < -time.Second || delta > 5*time.Second {
		t.Fatalf("Date=%q is not current", values[0])
	}
}

func TestResponseDateWireHeads(t *testing.T) {
	for _, status := range []int{200, 204, 206, 301, 304, 400, 404, 431, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			response := &Response{StatusCode: status}
			cases := map[string]func() [][2]string{
				"h1-buffered": func() [][2]string { return dateH1Fields(t, appendPlainResponse(response, nil)) },
				"h1-exported": func() [][2]string {
					wire, bp := BuildH1Response(response)
					fields := dateH1Fields(t, wire)
					putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
					return fields
				},
				"h1-stream": func() [][2]string {
					return dateH1Fields(t, appendH1StreamHead(nil, status, nil, "", false, true, "ALOS", nil))
				},
				"h2-buffered": func() [][2]string {
					wire := appendH2ResponseHeadersFrame(nil, 1, response, true, H2DefaultMaxFrameSize)
					fields, err := newHpackDecoder(4096).Decode(wire[9:])
					if err != nil {
						t.Fatal(err)
					}
					return fields
				},
				"h2-stream": func() [][2]string {
					enc := HpackEncoder{}
					encodeH2ResponseHeaders(&enc, status, "", -1, nil, "ALOS")
					fields, err := newHpackDecoder(4096).Decode(enc.Buf)
					if err != nil {
						t.Fatal(err)
					}
					return fields
				},
				"h2-error": func() [][2]string {
					wire := appendH2StatusOnlyResponse(nil, 1, status, "ALOS", H2DefaultMaxFrameSize)
					fields, err := newHpackDecoder(4096).Decode(wire[9:])
					if err != nil {
						t.Fatal(err)
					}
					return fields
				},
				"h3": func() [][2]string {
					bp := qpackEncodeResponseHeaders(status, "", 0, nil, "ALOS")
					var decoder QPACKDecoder
					fields, err := decoder.Decode(*bp)
					putBoxedBufCapped(&qpackEncodeBufPool, bp, qpackEncodeBufPoolMaxCap)
					if err != nil {
						t.Fatal(err)
					}
					return fields
				},
				"proxy-local-buffered": func() [][2]string {
					return dateH1Fields(t, appendProxyResponseHead(nil, status, respHeaders{}, 0, false, ""))
				},
				"proxy-local-stream": func() [][2]string {
					return dateH1Fields(t, appendProxyStreamHead(nil, status, respHeaders{}, 0, false))
				},
			}
			for name, build := range cases {
				t.Run(name, func(t *testing.T) { dateRequireCurrent(t, build()) })
			}
		})
	}
}

func TestResponseDatePresenceAndInformational(t *testing.T) {
	for _, name := range []string{"Date", "date", "dAtE"} {
		for _, value := range []string{"", "opaque", "Tue, 15 Nov 1994 08:12:31 GMT"} {
			headers := [][2]string{{name, value}}
			response := &Response{StatusCode: 200, Headers: headers}
			enc := HpackEncoder{}
			encodeH2ResponseHeaders(&enc, 200, "", 0, headers, "ALOS")
			h2fields, err := newHpackDecoder(4096).Decode(enc.Buf)
			if err != nil {
				t.Fatal(err)
			}
			bp := qpackEncodeResponseHeaders(200, "", 0, headers, "ALOS")
			var dec QPACKDecoder
			h3fields, err := dec.Decode(*bp)
			putBoxedBufCapped(&qpackEncodeBufPool, bp, qpackEncodeBufPoolMaxCap)
			if err != nil {
				t.Fatal(err)
			}
			for _, fields := range [][][2]string{dateH1Fields(t, appendPlainResponse(response, nil)), dateH1Fields(t, appendH1StreamHead(nil, 200, headers, "", false, true, "ALOS", nil)), h2fields, h3fields,
				dateH1Fields(t, appendProxyResponseHead(nil, 200, respHeaders{str: headers}, 0, false, "")),
				dateH1Fields(t, appendProxyStreamHead(nil, 200, respHeaders{str: headers}, 0, false)),
				dateH1Fields(t, appendProxyResponseHead(nil, 200, respHeaders{raw: [][2][]byte{{[]byte(ToLowerASCII(name)), []byte(value)}}}, 0, false, "")),
				dateH1Fields(t, appendProxyStreamHead(nil, 200, respHeaders{raw: [][2][]byte{{[]byte(ToLowerASCII(name)), []byte(value)}}}, 0, false)),
			} {
				if got := dateValues(fields); len(got) != 1 || got[0] != value {
					t.Fatalf("header=%q value=%q Date=%q", name, value, got)
				}
			}
		}
	}
	for _, status := range []int{100, 101} {
		wire := appendPlainResponse(&Response{StatusCode: status}, nil)
		if values := dateValues(dateH1Fields(t, wire)); len(values) != 0 {
			t.Fatalf("origin status=%d Date=%q", status, values)
		}
	}
}

func TestResponseDateRedirectAndACME(t *testing.T) {
	dateRequireCurrent(t, dateH1Fields(t, buildRedirectResponse("https://example.test/")))
	dateRequireCurrent(t, dateH1Fields(t, buildACMEResponse([]byte("public-fixture"))))
	conn := &captureConn{}
	writeHTTPRouteStatus(conn, 400)
	dateRequireCurrent(t, dateH1Fields(t, conn.buf))
}

func TestResponseDateEligibility(t *testing.T) {
	for _, status := range []int{0, 99, 100, 101, 199, 600, 999} {
		if value := responseDateValueAt(status, nil, 1000000000); value != "" {
			t.Fatalf("status=%d generated Date=%q", status, value)
		}
		if got := appendProxyDate([]byte("PREFIX"), status, respHeaders{}); string(got) != "PREFIX" {
			t.Fatalf("proxy status=%d generated metadata %q", status, got)
		}
	}
	for _, status := range []int{200, 299, 300, 399, 400, 499, 500, 599} {
		value := responseDateValueAt(status, nil, 1000000000)
		if value != "Sun, 09 Sep 2001 01:46:40 GMT" {
			t.Fatalf("status=%d Date=%q", status, value)
		}
	}
}

func TestResponseDateDefaultRootClock(t *testing.T) {
	server := rootFastServer(t, Config{})
	if server.dateNow != nil {
		t.Fatal("fixture unexpectedly overrides clock")
	}
	dateRequireCurrent(t, dateH1Fields(t, server.plainRootFast.Load().getKeepAlive))
	dateRequireCurrent(t, dateMemoH2Fields(t, server.h2RootFast.Load()))
}

func TestResponseDateFormatterCacheIndependence(t *testing.T) {
	const mtime int64 = 946684800
	fileDate := httpDate(mtime)
	original := lastHTTPDate.Load()
	for _, unix := range []int64{1767225600, 1767225601, 1767225600} {
		value := responseDateValueAt(200, nil, unix)
		want := time.Unix(unix, 0).UTC().Format(http.TimeFormat)
		if value != want {
			t.Fatalf("response Date=%q want=%q", value, want)
		}
		if lastHTTPDate.Load() != original || httpDate(mtime) != fileDate {
			t.Fatal("response Date evicted file validator cache")
		}
	}
}

func TestResponseDateFormatterConcurrentPublication(t *testing.T) {
	const mtime int64 = 946684800
	const current int64 = 1767225600
	fileText, responseText := httpDate(mtime), responseHTTPDate(current)
	fileEntry, responseEntry := lastHTTPDate.Load(), lastResponseHTTPDate.Load()
	errors := make(chan error, 4)
	var group sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for iteration := 0; iteration < 100; iteration++ {
				unix := current + int64((worker+iteration)%4)
				got := responseHTTPDate(unix)
				want := time.Unix(unix, 0).UTC().Format(http.TimeFormat)
				fileUnix := mtime + int64((worker+iteration)%4)
				fileGot := httpDate(fileUnix)
				fileWant := time.Unix(fileUnix, 0).UTC().Format(http.TimeFormat)
				if got != want || fileGot != fileWant {
					errors <- fmt.Errorf("response=%q want=%q file=%q want=%q", got, want, fileGot, fileWant)
					return
				}
			}
		}(worker)
	}
	group.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	_ = httpDate(mtime + 10)
	_ = responseHTTPDate(current + 10)
	if fileEntry.unix != mtime || fileEntry.text != fileText || responseEntry.unix != current || responseEntry.text != responseText {
		t.Fatal("formatter mutated a published cache entry")
	}
}
