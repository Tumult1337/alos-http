//go:build linux && amd64

package core

import (
	"slices"
	"strings"
	"testing"
)

type fpG2Field struct{ name, value string }

func fpG2Block(fields ...fpG2Field) []byte {
	var e hpackEncoder
	e.reset(nil)
	for _, f := range fields {
		e.buf = append(e.buf, 0x00)
		e.appendString(f.name)
		e.appendString(f.value)
	}
	return e.buf
}

func fpG2Status(code string) fpG2Field { return fpG2Field{":status", code} }

type fpG2Frame struct {
	typ   byte
	flags byte
	body  []byte
}

func fpG2Headers(flags byte, fields ...fpG2Field) fpG2Frame {
	return fpG2Frame{h2FrameHeaders, h2FlagEndHeaders | flags, fpG2Block(fields...)}
}

func fpG2Run(t *testing.T, frames ...fpG2Frame) (*Exchange, *fpFix2RecordingTransport) {
	t.Helper()
	c, ex, rec := fpFix2RecordedH2Conn(t)
	c.h2.nextID = fpFixStreamID + 2
	h := c.proto.(*h2Proto)
	for i, f := range frames {
		if err := h.handleFrame(c, f.typ, f.flags, fpFixStreamID, f.body); err != nil {
			t.Fatalf("frame %d tore down the connection: %v", i, err)
		}
	}
	return ex, rec
}

func fpG2WantMalformed(t *testing.T, name string, frames ...fpG2Frame) {
	t.Helper()
	ex, rec := fpG2Run(t, frames...)
	if !fpFixExchangeFailed(ex) {
		t.Errorf("%s: response accepted, status=%d headers=%d", name, ex.resp.Status, len(ex.resp.Headers))
		return
	}
	if got := rec.rstCodes(); !slices.Equal(got, []uint32{H2ErrProtocol}) {
		t.Errorf("%s: RST_STREAM codes %v, want [PROTOCOL_ERROR]", name, got)
	}
}

func TestFPH2UpstreamRejectsRepeatedHeaderBlocks(t *testing.T) {
	big := strings.Repeat("v", 1024)
	frames := []fpG2Frame{fpG2Headers(0, fpG2Status("200"), fpG2Field{"x-a", big})}
	for range 64 {
		frames = append(frames, fpG2Headers(0, fpG2Field{"x-a", big}))
	}
	c, ex, rec := fpFix2RecordedH2Conn(t)
	c.h2.nextID = fpFixStreamID + 2
	h := c.proto.(*h2Proto)
	st := ex.h2st
	for i, f := range frames {
		if err := h.handleFrame(c, f.typ, f.flags, fpFixStreamID, f.body); err != nil {
			t.Fatalf("frame %d tore down the connection: %v", i, err)
		}
	}
	if len(st.headers) > 1 {
		t.Fatalf("stream kept %d header fields from %d blocks", len(st.headers), len(frames))
	}
	if !fpFixExchangeFailed(ex) {
		t.Fatalf("a second header block without END_STREAM was accepted")
	}
	if got := rec.rstCodes(); !slices.Equal(got, []uint32{H2ErrProtocol}) {
		t.Fatalf("RST_STREAM codes %v, want [PROTOCOL_ERROR]", got)
	}
}

func TestFPH2UpstreamRejectsMalformedResponseSequences(t *testing.T) {
	data := func(flags byte) fpG2Frame { return fpG2Frame{h2FrameData, flags, []byte("x")} }
	fpG2WantMalformed(t, "headers after final status", fpG2Headers(0, fpG2Status("200")), fpG2Headers(h2FlagEndStream, fpG2Status("200")))
	fpG2WantMalformed(t, "trailers without END_STREAM", fpG2Headers(0, fpG2Status("200")), data(0), fpG2Headers(0, fpG2Field{"x-t", "1"}))
	fpG2WantMalformed(t, "pseudo-header in trailers", fpG2Headers(0, fpG2Status("200")), fpG2Headers(h2FlagEndStream, fpG2Status("500")))
	fpG2WantMalformed(t, "informational with END_STREAM", fpG2Headers(h2FlagEndStream, fpG2Status("103")))
	fpG2WantMalformed(t, "missing status", fpG2Headers(h2FlagEndStream, fpG2Field{"x-a", "200"}))
	fpG2WantMalformed(t, "status below 100", fpG2Headers(0, fpG2Status("099")))
	fpG2WantMalformed(t, "duplicate status", fpG2Headers(h2FlagEndStream, fpG2Status("200"), fpG2Status("204")))
	fpG2WantMalformed(t, "non-numeric status", fpG2Headers(h2FlagEndStream, fpG2Status("2x0")))
	fpG2WantMalformed(t, "status out of range", fpG2Headers(h2FlagEndStream, fpG2Status("1000")))
	fpG2WantMalformed(t, "switching protocols", fpG2Headers(0, fpG2Status("101")))
	fpG2WantMalformed(t, "status after regular field", fpG2Headers(h2FlagEndStream, fpG2Field{"x-a", "1"}, fpG2Status("200")))
	fpG2WantMalformed(t, "data before headers", data(h2FlagEndStream))
	fpG2WantMalformed(t, "data after interim only", fpG2Headers(0, fpG2Status("100")), data(h2FlagEndStream))
}

func TestFPH2UpstreamAcceptsInterimFinalAndTrailers(t *testing.T) {
	ex, rec := fpG2Run(t,
		fpG2Headers(0, fpG2Status("100")),
		fpG2Headers(0, fpG2Status("103"), fpG2Field{"link", "</a>"}),
		fpG2Headers(0, fpG2Status("201"), fpG2Field{"x-final", "yes"}),
		fpG2Frame{h2FrameData, 0, []byte("body")},
		fpG2Headers(h2FlagEndStream, fpG2Field{"x-trailer", "t"}),
	)
	select {
	case <-ex.done:
	default:
		t.Fatalf("the exchange did not complete")
	}
	if ex.err != nil {
		t.Fatalf("a legal response failed: %v", ex.err)
	}
	if ex.resp.Status != 201 || string(ex.resp.Body) != "body" {
		t.Fatalf("status=%d body=%q", ex.resp.Status, ex.resp.Body)
	}
	if !slices.Equal(ex.resp.Headers, [][2]string{{"x-final", "yes"}}) {
		t.Fatalf("headers = %q, want only the final header section", ex.resp.Headers)
	}
	if got := rec.rstCodes(); len(got) != 0 {
		t.Fatalf("RST_STREAM codes %v on a legal response", got)
	}
}

func TestFPH1UpstreamRejectsStatusBelow100(t *testing.T) {
	for _, line := range []string{"HTTP/1.1 000 Zero", "HTTP/1.1 099 Low"} {
		var p h1Parser
		if _, _, err := p.parseHeaderBlock([]byte(line+"\r\nContent-Length: 0"), "GET"); err == nil {
			t.Errorf("%q accepted with status %d", line, p.status)
		}
	}
	var p h1Parser
	if _, _, err := p.parseHeaderBlock([]byte("HTTP/1.1 100 Continue"), "GET"); err != nil || p.status != 100 {
		t.Fatalf("100 Continue: status=%d err=%v", p.status, err)
	}
}
