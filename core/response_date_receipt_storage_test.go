//go:build linux && amd64

package core

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func TestResponseDateMaterializedValueOwnership(t *testing.T) {
	const cached = "Thu, 01 Jan 2026 00:00:00 GMT"
	for _, consumer := range []string{"parser", "worker"} {
		for _, valueCase := range []struct {
			name, value string
			hit         bool
			nilCache    bool
		}{
			{"date", cached, true, false},
			{"date", cached, false, false},
			{"date", cached, false, true},
			{"date", "opaque Date", false, false},
			{"date", "", false, false},
			{"dAtE", cached, false, false},
			{"x-other", cached, false, false},
		} {
			t.Run(fmt.Sprintf("%s/%s/%q/hit=%t/nil=%t", consumer, valueCase.name, valueCase.value, valueCase.hit, valueCase.nilCache), func(t *testing.T) {
				entry := &httpDateEntry{unix: 1767225600, text: cached}
				if !valueCase.hit {
					entry = &httpDateEntry{unix: 1767225601, text: "Thu, 01 Jan 2026 00:00:01 GMT"}
				}
				if valueCase.nilCache {
					entry = nil
				}
				lastResponseHTTPDate.Store(entry)
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
				lastResponseHTTPDate.Store(&httpDateEntry{unix: 1767225602, text: "Thu, 01 Jan 2026 00:00:02 GMT"})
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

func TestResponseDateMaterializersConcurrentCacheReplacement(t *testing.T) {
	const rawText = "Thu, 01 Jan 2026 00:00:00 GMT"
	matching := &httpDateEntry{unix: 1767225600, text: rawText}
	other := &httpDateEntry{unix: 1767225601, text: "Thu, 01 Jan 2026 00:00:01 GMT"}
	lastResponseHTTPDate.Store(matching)
	stop, started := make(chan struct{}), make(chan struct{})
	var publisher sync.WaitGroup
	publisher.Add(1)
	go func() {
		defer publisher.Done()
		close(started)
		for {
			select {
			case <-stop:
				return
			default:
				lastResponseHTTPDate.Store(other)
				lastResponseHTTPDate.Store(matching)
			}
		}
	}()
	<-started
	defer func() { close(stop); publisher.Wait() }()
	raw := [][2][]byte{{[]byte("date"), []byte(rawText)}}
	parser, worker := h1Parser{hdr: raw}, epollWorker{}
	for index := 0; index < 200000; index++ {
		if got := parser.stringHeaders()[0][1]; got != rawText {
			t.Fatalf("parser selected a different cache epoch: %q", got)
		}
		if got := worker.headerStrings(respHeaders{raw: raw})[0][1]; got != rawText {
			t.Fatalf("worker selected a different cache epoch: %q", got)
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
	const text = "Thu, 01 Jan 2026 00:00:00 GMT"
	lastResponseHTTPDate.Store(&httpDateEntry{unix: 1767225600, text: text})
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
