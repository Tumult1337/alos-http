//go:build linux && amd64

package core

import (
	"strconv"
	"strings"
	"testing"
)

const h2DeclaredLength = 10

func h2PostWithLength(path string, lengths ...int) []byte {
	var enc HpackEncoder
	enc.EncodeHeader(":method", "POST")
	enc.EncodeHeader(":scheme", "http")
	enc.EncodeHeader(":path", path)
	enc.EncodeHeader(":authority", cancelH2Authority)
	for _, n := range lengths {
		enc.EncodeHeader("content-length", strconv.Itoa(n))
	}
	return enc.Buf
}

func TestH2ContentLength(t *testing.T) {
	cases := []struct {
		name     string
		sent     int
		trailer  bool
		wantBody bool
	}{
		{"exact", h2DeclaredLength, false, true},
		{"exact with trailers", h2DeclaredLength, true, true},
		{"over", h2DeclaredLength + 1, false, false},
		{"short", h2DeclaredLength - 1, false, false},
		{"short with trailers", h2DeclaredLength - 1, true, false},
	}
	for _, mode := range trailerModes() {
		for _, tc := range cases {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				ts := startTrailerServer(t, true, mode.streamed)
				rc := dialCancelH2(t, ts)
				rc.write(H2FrameHeaders, H2FlagEndHeaders, 1, h2PostWithLength("/t", h2DeclaredLength))
				body := strings.Repeat("b", tc.sent)
				if tc.trailer {
					rc.write(H2FrameData, 0, 1, []byte(body))
					rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2LiteralField("x-t", "1"))
				} else {
					rc.write(H2FrameData, 0, 1, []byte(body[:len(body)/2]))
					rc.write(H2FrameData, H2FlagEndStream, 1, []byte(body[len(body)/2:]))
				}
				if !tc.wantBody {
					h2ExpectReset(t, rc, 1)
				} else {
					want := body
					if tc.trailer {
						want += "|x-t=1"
					}
					if status, got := h2ReadBody(t, rc, 1); status != 200 || got != want {
						t.Fatalf("status %d body %q, want %q", status, got, want)
					}
				}
				rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, cancelH2Headers("/ok"))
				if status, got := h2ReadBody(t, rc, 3); status != 200 || got != "ok" {
					t.Fatalf("connection unusable afterwards: %d %q", status, got)
				}
			})
		}
	}
}

func TestH2ContentLengthWithoutBody(t *testing.T) {
	ts := startTrailerServer(t, true, false)
	rc := dialCancelH2(t, ts)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, h2PostWithLength("/t", 5))
	h2ExpectReset(t, rc, 1)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, h2PostWithLength("/t", 0))
	if status, got := h2ReadBody(t, rc, 3); status != 200 || got != "" {
		t.Fatalf("content-length 0 without body: %d %q", status, got)
	}
}

func TestH2ContentLengthConflictingDuplicates(t *testing.T) {
	ts := startTrailerServer(t, true, false)
	rc := dialCancelH2(t, ts)
	rc.write(H2FrameHeaders, H2FlagEndHeaders, 1, h2PostWithLength("/t", 3, 4))
	rc.write(H2FrameData, H2FlagEndStream, 1, []byte("abc"))
	f, err := rc.awaitStreamOutcome(1)
	if err != nil {
		t.Fatal(err)
	}
	if f.typ != H2FrameRSTStream && f.typ != H2FrameGoAway {
		t.Fatalf("conflicting content-length got frame type %d", f.typ)
	}
}
