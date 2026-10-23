//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"net/http"
	"strconv"
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
					wire := appendH2ResponseHeadersFrameIndexed(nil, 1, response, true, nil, respServerName(response), H2DefaultMaxFrameSize)
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
					wire := appendH2StatusOnlyResponseIndexed(nil, 1, status, "ALOS", nil, H2DefaultMaxFrameSize)
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
		if value := responseDateValue(status, nil); value != "" {
			t.Fatalf("status=%d generated Date=%q", status, value)
		}
		if got := appendProxyDate([]byte("PREFIX"), status, respHeaders{}); string(got) != "PREFIX" {
			t.Fatalf("proxy status=%d generated metadata %q", status, got)
		}
	}
	installSharedDate(t)
	for _, status := range []int{200, 299, 300, 399, 400, 499, 500, 599} {
		if value := responseDateValue(status, nil); value != sharedDateText {
			t.Fatalf("status=%d Date=%q", status, value)
		}
	}
}

func TestResponseDateDoesNotTouchFileValidatorCache(t *testing.T) {
	const mtime int64 = 946684800
	fileDate := httpDate(mtime)
	original := lastHTTPDate.Load()
	installSharedDate(t)
	for _, status := range []int{200, 404} {
		if responseDateValue(status, nil) != sharedDateText {
			t.Fatal("response Date is not the shared entry")
		}
		if lastHTTPDate.Load() != original || httpDate(mtime) != fileDate {
			t.Fatal("response Date evicted file validator cache")
		}
	}
}
