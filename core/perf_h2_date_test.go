//go:build linux && amd64

package core

import (
	"net/http"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const perfH2DateSkew = 2 * time.Second

func perfH2DecodeFields(t *testing.T, block []byte) [][2]string {
	t.Helper()
	d := &HpackDecoder{maxTableSize: 4096, protocolMaxSize: 4096, maxHeaderListSize: 1 << 20}
	fields, err := d.DecodeInto(nil, block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return fields
}

func perfH2DateValues(fields [][2]string) []string {
	var out []string
	for _, f := range fields {
		if f[0] == "date" {
			out = append(out, f[1])
		}
	}
	return out
}

func perfH2AssertFreshDate(t *testing.T, fields [][2]string) {
	t.Helper()
	dates := perfH2DateValues(fields)
	if len(dates) != 1 {
		t.Fatalf("want exactly one date field, got %q", dates)
	}
	got, err := http.ParseTime(dates[0])
	if err != nil {
		t.Fatalf("date %q is not an HTTP-date: %v", dates[0], err)
	}
	if skew := time.Duration(turbo.Unix()-got.Unix()) * time.Second; skew > perfH2DateSkew || skew < -perfH2DateSkew {
		t.Fatalf("date %q is %v away from now", dates[0], skew)
	}
}

func TestH2ResponseHeadersCarryDate(t *testing.T) {
	enc := HpackEncoder{}
	encodeH2ResponseHeaders(&enc, 200, "text/plain", 5, nil, "ALOS")
	fields := perfH2DecodeFields(t, enc.Buf)
	if fields[0][0] != ":status" {
		t.Fatalf("first field %q, want :status", fields[0][0])
	}
	perfH2AssertFreshDate(t, fields)
}

func TestH2ResponseHeadersKeepHandlerDate(t *testing.T) {
	const handlerDate = "Mon, 02 Jan 2006 15:04:05 GMT"
	enc := HpackEncoder{}
	encodeH2ResponseHeaders(&enc, 404, "", -1, [][2]string{{"Date", handlerDate}}, "ALOS")
	dates := perfH2DateValues(perfH2DecodeFields(t, enc.Buf))
	if len(dates) != 1 || dates[0] != handlerDate {
		t.Fatalf("dates %q, want only the handler's %q", dates, handlerDate)
	}
}

func TestH2MemoizedRootResponseRefreshesDate(t *testing.T) {
	stale := newH2DateField(turbo.Unix() - 3600)
	enc := HpackEncoder{}
	enc.EncodeStatus(200)
	enc.Buf = append(enc.Buf, stale.enc...)
	enc.encodeStaticFieldCached(hpackStaticContentType, "text/plain")
	for _, body := range [][]byte{[]byte("ok"), make([]byte, 2*H2DefaultMaxFrameSize)} {
		fast := newH2RootFastResponse(append([]byte(nil), enc.Buf...), body)
		out := appendFastH2RootResponse(nil, fast, 5, H2DefaultMaxFrameSize)
		n := int(out[0])<<16 | int(out[1])<<8 | int(out[2])
		perfH2AssertFreshDate(t, perfH2DecodeFields(t, out[9:9+n]))
		if string(fast.headerPayload) != string(enc.Buf) {
			t.Fatal("refreshing the date modified the shared memoised header block")
		}
	}
}
