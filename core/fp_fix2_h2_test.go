//go:build linux && amd64

package core

import (
	"slices"
	"testing"
)

type fpFix2RecordingTransport struct {
	plainTransport
	sent []byte
}

func (t *fpFix2RecordingTransport) wrapOut(c *backendConn, plain []byte) error {
	t.sent = append(t.sent, plain...)
	return t.plainTransport.wrapOut(c, plain)
}

func (t *fpFix2RecordingTransport) rstCodes() []uint32 {
	var codes []uint32
	for b := t.sent; len(b) >= h2FrameHeaderSize; {
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if len(b) < h2FrameHeaderSize+n {
			break
		}
		if p := b[h2FrameHeaderSize : h2FrameHeaderSize+n]; b[3] == h2FrameRSTStream && n == 4 {
			codes = append(codes, uint32(p[0])<<24|uint32(p[1])<<16|uint32(p[2])<<8|uint32(p[3]))
		}
		b = b[h2FrameHeaderSize+n:]
	}
	return codes
}

func fpFix2RecordedH2Conn(t *testing.T) (*backendConn, *Exchange, *fpFix2RecordingTransport) {
	t.Helper()
	c, ex := fpFixH2Conn(t)
	rec := &fpFix2RecordingTransport{plainTransport: plainTransport{h2: true}}
	c.transport = rec
	return c, ex, rec
}

func TestFPFix2H2StreamWindowOverflowSendsFlowControlError(t *testing.T) {
	c, ex, rec := fpFix2RecordedH2Conn(t)
	if err := c.proto.(*h2Proto).handleFrame(c, h2FrameWindowUpdate, 0, fpFixStreamID, fpFixWindowUpdate(0x7fffffff)); err != nil || !fpFixExchangeFailed(ex) {
		t.Fatalf("stream window overflow: err=%v failed=%v", err, fpFixExchangeFailed(ex))
	}
	if got := rec.rstCodes(); !slices.Equal(got, []uint32{H2ErrFlowControl}) {
		t.Fatalf("RST_STREAM codes %v, want [FLOW_CONTROL_ERROR %d]", got, H2ErrFlowControl)
	}
}

func TestFPFix2H2MalformedResponseSendsProtocolError(t *testing.T) {
	c, ex, rec := fpFix2RecordedH2Conn(t)
	block := fpFixHeadersBlock(func(e *hpackEncoder) {
		e.buf = append(e.buf, 0x00)
		e.appendString("x-a")
		e.appendString("bad\x00value")
	})
	if err := c.proto.(*h2Proto).handleFrame(c, h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, fpFixStreamID, block); err != nil || !fpFixExchangeFailed(ex) {
		t.Fatalf("malformed response: err=%v failed=%v", err, fpFixExchangeFailed(ex))
	}
	if got := rec.rstCodes(); !slices.Equal(got, []uint32{H2ErrProtocol}) {
		t.Fatalf("RST_STREAM codes %v, want [PROTOCOL_ERROR %d]", got, H2ErrProtocol)
	}
}
