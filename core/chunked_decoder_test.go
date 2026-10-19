//go:build linux && amd64

package core

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func decodeChunkedInSteps(t *testing.T, wire []byte, step int) ([]byte, error) {
	t.Helper()
	var d chunkedDecoder
	var out []byte
	var pending []byte
	for off := 0; off < len(wire) || len(pending) > 0; {
		if off < len(wire) {
			end := min(off+step, len(wire))
			pending = append(pending, wire[off:end]...)
			off = end
		}
		for !d.done() && len(pending) > 0 {
			n, data, err := d.next(pending)
			if err != nil {
				return out, err
			}
			if n == 0 {
				break
			}
			out = append(out, data...)
			pending = pending[n:]
		}
		if d.done() {
			if len(pending) > 0 {
				t.Fatalf("decoder left %d trailing bytes unconsumed: %q", len(pending), pending)
			}
			return out, nil
		}
		if off >= len(wire) {
			return out, errors.New("incomplete")
		}
	}
	return out, errors.New("incomplete")
}

func TestChunkedDecoderReassemblesAcrossEverySplit(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdefghij"), 700)
	wire := append([]byte(nil), "1b58;name=value\r\n"...)
	wire = append(wire, payload...)
	wire = append(wire, "\r\n5\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n"...)
	want := append(append([]byte(nil), payload...), "hello"...)
	for _, step := range []int{1, 2, 3, 7, 64, 4096, len(wire)} {
		got, err := decodeChunkedInSteps(t, wire, step)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("step=%d: err=%v got %d bytes want %d", step, err, len(got), len(want))
		}
	}
}

var chunkedMalformedCases = map[string]string{
	"non-hex size":                  "zz\r\nab\r\n0\r\n\r\n",
	"empty size":                    "\r\nab\r\n0\r\n\r\n",
	"data not followed by CR":       "2\r\nabXY0\r\n\r\n",
	"data followed by other bytes":  "5\r\nhelloXX\r\n0\r\n\r\n",
	"data followed by digit and LF": "5;000000000000\n000000\n00\n\n",
	"size line too long":            strings.Repeat("0", chunkedFramingLineMax+1),
	"trailer too large":             "0\r\n" + strings.Repeat("X-A: b\r\n", chunkedFramingLineMax/8+1) + "\r\n",
	"size overflow":                 "fffffffffffffffff\r\n",
}

func TestChunkedDecoderRejectsMalformedFraming(t *testing.T) {
	for name, wire := range chunkedMalformedCases {
		if _, err := decodeChunkedInSteps(t, []byte(wire), 3); !errors.Is(err, errChunkedMalformed) {
			t.Errorf("%s: err=%v, want errChunkedMalformed", name, err)
		}
	}
}

func TestChunkedDecoderStopsAtTheEndOfTheBody(t *testing.T) {
	var d chunkedDecoder
	src := []byte("3\r\nabc\r\n0\r\n\r\nGET / HTTP/1.1\r\n")
	var got []byte
	consumed := 0
	for !d.done() {
		n, data, err := d.next(src[consumed:])
		if err != nil || n == 0 {
			t.Fatalf("n=%d err=%v", n, err)
		}
		got = append(got, data...)
		consumed += n
	}
	if string(got) != "abc" || string(src[consumed:]) != "GET / HTTP/1.1\r\n" {
		t.Fatalf("body=%q rest=%q", got, src[consumed:])
	}
}
