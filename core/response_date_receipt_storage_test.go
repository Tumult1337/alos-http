//go:build linux && amd64

package core

import (
	"bytes"
	"fmt"
	"testing"
)

func TestResponseDateMaterializedValueOwnership(t *testing.T) {
	const cached = sharedDateText
	for _, consumer := range []string{"parser", "worker"} {
		for _, valueCase := range []struct {
			name, value string
			hit         bool
		}{
			{"date", cached, true},
			{"date", cached, false},
			{"date", "opaque Date", false},
			{"date", "", false},
			{"dAtE", cached, false},
			{"x-other", cached, false},
		} {
			t.Run(fmt.Sprintf("%s/%s/%q/hit=%t", consumer, valueCase.name, valueCase.value, valueCase.hit), func(t *testing.T) {
				if valueCase.hit {
					installDateUnix(t, sharedDateUnix)
				} else {
					installDateUnix(t, sharedDateUnix+1)
				}
				rawName, rawValue := []byte(valueCase.name), []byte(valueCase.value)
				raw := [][2][]byte{{rawName, rawValue}}
				var fields [][2]string
				if consumer == "parser" {
					parser := h1Parser{hdr: raw}
					fields = parser.stringHeaders()
				} else {
					worker := epollWorker{}
					fields = worker.headerStrings(respHeaders{raw: raw})
				}
				if len(fields) != 1 || fields[0][1] != valueCase.value {
					t.Fatalf("materialized fields=%q", fields)
				}
				retained := fields[0][1]
				installDateUnix(t, sharedDateUnix+2)
				for index := range rawValue {
					rawValue[index] = '!'
				}
				if len(rawValue) > 0 && !bytes.Equal(rawValue, bytes.Repeat([]byte{'!'}, len(rawValue))) {
					t.Fatal("raw overwrite did not occur")
				}
				if retained != valueCase.value {
					t.Fatalf("retained header changed after raw reuse: got=%q want=%q", retained, valueCase.value)
				}
			})
		}
	}
}

func TestResponseDateReceiptBufferReuse(t *testing.T) {
	var parser h1Parser
	for _, supplied := range []string{"", "Date: opaque\r\n", "Date:\r\n", ""} {
		parser.reset()
		_, _, err := parser.parseHeaderBlock([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"+supplied), "GET")
		if err != nil {
			t.Fatal(err)
		}
		parser.addReceiptDate()
		fields := parser.stringHeaders()
		if supplied == "" {
			dateRequireCurrent(t, fields)
			if cap(parser.receiptDateBuf) == 0 {
				t.Fatal("generated Date did not populate retained buffer")
			}
		} else {
			want := "opaque"
			if supplied == "Date:\r\n" {
				want = ""
			}
			if got := dateValues(fields); len(got) != 1 || got[0] != want {
				t.Fatalf("supplied Date after parser reuse=%q want=%q", got, want)
			}
		}
	}
}

func TestResponseDateMaterializersReuseCachedString(t *testing.T) {
	const text = sharedDateText
	installSharedDate(t)
	raw := [][2][]byte{{[]byte("date"), []byte(text)}}
	parser, worker := h1Parser{hdr: raw}, epollWorker{}
	for _, consumer := range []string{"parser", "worker"} {
		t.Run(consumer, func(t *testing.T) {
			var retained string
			got := testing.AllocsPerRun(1000, func() {
				if consumer == "parser" {
					retained = parser.stringHeaders()[0][1]
				} else {
					retained = worker.headerStrings(respHeaders{raw: raw})[0][1]
				}
			})
			if retained != text || got != 0 {
				t.Fatalf("cached immutable value=%q allocations=%g, want %q/0", retained, got, text)
			}
		})
	}
}
