//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

func TestResponseDateH2PeerFrameBoundaryProbe(t *testing.T) {
	empty := HpackEncoder{}
	encodeH2ResponseHeadersAt(&empty, 200, "", 0, [][2]string{{"x-padding", ""}}, "ALOS", "")
	padding := int(H2DefaultMaxFrameSize) - len(empty.Buf) - 2
	var headers [][2]string
	var base HpackEncoder
	for adjustment := -4; adjustment <= 4; adjustment++ {
		headers = [][2]string{{"x-padding", strings.Repeat("\xff", padding+adjustment)}}
		base.Buf = nil
		encodeH2ResponseHeadersAt(&base, 200, "", 0, headers, "ALOS", "")
		if len(base.Buf) == int(H2DefaultMaxFrameSize) {
			break
		}
	}
	if len(base.Buf) != int(H2DefaultMaxFrameSize) {
		t.Fatalf("fixture header block=%d, want existing exact frame limit=%d", len(base.Buf), H2DefaultMaxFrameSize)
	}
	frame := appendH2ResponseHeadersFrame(nil, 1, &Response{StatusCode: 200, Headers: headers}, true, H2DefaultMaxFrameSize)
	block, body, frames := responseHeaderFlight(t, frame, 1, H2DefaultMaxFrameSize, true)
	if frames != 2 || len(body) != 0 {
		t.Fatalf("Date crossing frames=%d body=%d", frames, len(body))
	}
	fields, err := newHpackDecoder(4096).Decode(block)
	if err != nil {
		t.Fatal(err)
	}
	dateRequireCurrent(t, fields)
	paddingValue := ""
	for _, field := range fields {
		if field[0] == "x-padding" {
			paddingValue = field[1]
		}
	}
	if paddingValue != headers[0][1] {
		t.Fatal("Date crossing lost original header bytes")
	}
}
