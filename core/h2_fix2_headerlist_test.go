//go:build linux && amd64

package core

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"testing"
)

const (
	h2Fix2CookieCrumbs       = 40
	h2Fix2CookieCrumbLen     = 170
	h2Fix2RaisedHeaderSize   = 32 << 10
	h2Fix2RaisedListBytes    = 20000
	h2Fix2PadName            = "x-pad"
	h2Fix2StatusTooLarge     = "431"
	h2Fix2StatusOK           = "200"
	h2Fix2DefaultFrameBudget = H2DefaultMaxFrameSize
)

func h2Fix2CrumbFields() [][2]string {
	fields := make([][2]string, 0, h2Fix2CookieCrumbs)
	for i := range h2Fix2CookieCrumbs {
		fields = append(fields, [2]string{"cookie", fmt.Sprintf("c%02d=%s", i, strings.Repeat("v", h2Fix2CookieCrumbLen))})
	}
	return fields
}

func h2Fix2BaseListSize() int {
	return h2FieldListSize([][2]string{
		{":method", "GET"}, {":scheme", "http"}, {":path", "/ok"}, {":authority", h2FixAuthority},
	})
}

func h2Fix2PaddedBlock(listSize int) []byte {
	padLen := listSize - h2Fix2BaseListSize() - len(h2Fix2PadName) - hpackEntryOverhead
	return append(h2FixRequestBlock("GET", "/ok"), h2FixLiteral(h2Fix2PadName, strings.Repeat("p", padLen))...)
}

func (rc *h2RawConn) h2Fix2WriteHeaderBlock(streamID uint32, block []byte) {
	rc.t.Helper()
	first := min(len(block), h2Fix2DefaultFrameBudget)
	flags := byte(H2FlagEndStream)
	if first == len(block) {
		flags |= H2FlagEndHeaders
	}
	frames := appendH2Frame(nil, H2FrameHeaders, flags, streamID, block[:first])
	for rest := block[first:]; len(rest) > 0; {
		n := min(len(rest), h2Fix2DefaultFrameBudget)
		cflags := byte(0)
		if n == len(rest) {
			cflags = H2FlagEndHeaders
		}
		frames = appendH2Frame(frames, H2FrameContinuation, cflags, streamID, rest[:n])
		rest = rest[n:]
	}
	rc.writeRaw(frames)
}

func (rc *h2RawConn) h2Fix2Status(streamID uint32) string {
	rc.t.Helper()
	f, err := rc.awaitStreamOutcome(streamID)
	if err != nil {
		rc.t.Fatalf("stream %d: %v", streamID, err)
	}
	switch f.typ {
	case H2FrameGoAway:
		return fmt.Sprintf("GOAWAY(%d)", binary.BigEndian.Uint32(f.payload[4:8]))
	case H2FrameRSTStream:
		return fmt.Sprintf("RST_STREAM(%d)", binary.BigEndian.Uint32(f.payload))
	}
	fields, err := f.fields, f.fieldErr
	if err != nil {
		rc.t.Fatalf("stream %d response HEADERS: %v", streamID, err)
	}
	for _, kv := range fields {
		if kv[0] == ":status" {
			return kv[1]
		}
	}
	rc.t.Fatalf("stream %d response HEADERS without :status", streamID)
	return ""
}

func h2Fix2H1Status(t *testing.T, addr string, headers [][2]string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr, h2FixCeiling)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(wallDeadline(h2FixCeiling))
	var b strings.Builder
	b.WriteString("GET /ok HTTP/1.1\r\nHost: " + h2FixAuthority + "\r\nConnection: close\r\n")
	for _, kv := range headers {
		b.WriteString(kv[0] + ": " + kv[1] + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("H1 status line: %v", err)
	}
	return strings.Fields(line)[1]
}

func TestH2Fix2CookieCrumbsAcceptedOnH1AreAcceptedOnH2(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, nil)
	crumbs := h2Fix2CrumbFields()
	if got := h2Fix2H1Status(t, addr, crumbs); got != h2Fix2StatusOK {
		t.Fatalf("H1 answered %s for the crumb request; the parity premise does not hold", got)
	}
	rc := h2RawDial(t, addr, nil)
	block := h2FixRequestBlock("GET", "/ok")
	for _, kv := range crumbs {
		block = append(block, h2FixLiteral(kv[0], kv[1])...)
	}
	rc.h2Fix2WriteHeaderBlock(1, block)
	if got := rc.h2Fix2Status(1); got != h2Fix2StatusOK {
		t.Fatalf("H2 answered %s for %d cookie crumbs that H1 serves under the same MaxHeaderSize", got, h2Fix2CookieCrumbs)
	}
}

func TestH2Fix2HeaderListLimitIsAdvertisedEnforcedAndAnswered431(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, nil)
	conn, err := net.DialTimeout("tcp", addr, h2FixCeiling)
	if err != nil {
		t.Fatal(err)
	}
	rc, settings := h2HandshakeCaptureSettings(t, conn)
	advertised := 0
	for p := settings; len(p) >= 6; p = p[6:] {
		if binary.BigEndian.Uint16(p) == H2SettingMaxHeaderListSize {
			advertised = int(binary.BigEndian.Uint32(p[2:]))
		}
	}
	if advertised < limitDefaultMaxHeaderSize {
		t.Fatalf("advertised SETTINGS_MAX_HEADER_LIST_SIZE %d is below the default MaxHeaderSize %d", advertised, limitDefaultMaxHeaderSize)
	}
	rc.h2Fix2WriteHeaderBlock(1, h2Fix2PaddedBlock(advertised))
	if got := rc.h2Fix2Status(1); got != h2Fix2StatusOK {
		t.Fatalf("a header list of exactly the advertised %d bytes got %s", advertised, got)
	}
	rc.h2Fix2WriteHeaderBlock(3, h2Fix2PaddedBlock(advertised+1))
	if got := rc.h2Fix2Status(3); got != h2Fix2StatusTooLarge {
		t.Fatalf("a header list one byte over the advertised %d got %s, want :status 431", advertised, got)
	}
	rc.h2Fix2WriteHeaderBlock(5, h2FixRequestBlock("GET", "/ok"))
	if got := rc.h2Fix2Status(5); got != h2Fix2StatusOK {
		t.Fatalf("request after the 431 got %s", got)
	}
}

func TestH2Fix2RaisedMaxHeaderSizeAppliesToH2(t *testing.T) {
	addr, _ := startH2FixFlowServer(t, func(c *Config) { c.MaxHeaderSize = h2Fix2RaisedHeaderSize })
	rc := h2RawDial(t, addr, nil)
	rc.h2Fix2WriteHeaderBlock(1, h2Fix2PaddedBlock(h2Fix2RaisedListBytes))
	if got := rc.h2Fix2Status(1); got != h2Fix2StatusOK {
		t.Fatalf("a %d-byte header list with MaxHeaderSize %d got %s", h2Fix2RaisedListBytes, h2Fix2RaisedHeaderSize, got)
	}
}

func TestH2Fix2HeaderListLimitStaysWithinTheSettingRange(t *testing.T) {
	if got := h2HeaderListLimitFor(math.MaxInt); got != math.MaxUint32 {
		t.Fatalf("limit for MaxHeaderSize=MaxInt is %d, want it clamped to %d", got, uint32(math.MaxUint32))
	}
	if got := h2HeaderListLimitFor(limitDefaultMaxHeaderSize); got <= limitDefaultMaxHeaderSize {
		t.Fatalf("limit for the default MaxHeaderSize is %d, want room for per-field overhead above %d", got, limitDefaultMaxHeaderSize)
	}
}
