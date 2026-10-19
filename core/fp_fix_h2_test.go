//go:build linux && amd64

package core

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const fpFixStreamID = 1

func fpFixH2Conn(t *testing.T) (*backendConn, *Exchange) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	l := newLoopForTest()
	l.cfg.fill(1)
	c := &backendConn{fd: fds[0], be: &l.beLoop, state: connReady, key: poolKey{h2: true}, transport: &plainTransport{h2: true}}
	c.proto = &l.h2proto
	c.h2init()
	l.ensureFD(fds[0])
	l.conns[fds[0]] = c
	l.liveConns = 1
	l.h2conns[c.key] = c
	ex := &Exchange{req: &fpRequest{Method: "GET"}, done: make(chan struct{}), bc: c}
	st := &h2Stream{id: fpFixStreamID, ex: ex, sendWindow: c.h2.peerInitWindow}
	ex.h2st = st
	c.h2.streams[fpFixStreamID] = st
	return c, ex
}

func fpFixWindowUpdate(inc uint32) []byte {
	return []byte{byte(inc >> 24), byte(inc >> 16), byte(inc >> 8), byte(inc)}
}

func fpFixSetting(id uint16, val uint32) []byte {
	return []byte{byte(id >> 8), byte(id), byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)}
}

func fpFixExchangeFailed(ex *Exchange) bool {
	select {
	case <-ex.done:
		return ex.err != nil
	default:
		return false
	}
}

func TestFPFixH2ConnectionWindowOverflowIsAnError(t *testing.T) {
	c, _ := fpFixH2Conn(t)
	if err := c.proto.(*h2Proto).handleFrame(c, h2FrameWindowUpdate, 0, 0, fpFixWindowUpdate(0x7fffffff)); err == nil {
		t.Fatalf("connection window overflowed to %d without an error", c.h2.connSendWindow)
	}
}

func TestFPFixH2StreamWindowOverflowResetsStream(t *testing.T) {
	c, ex := fpFixH2Conn(t)
	if err := c.proto.(*h2Proto).handleFrame(c, h2FrameWindowUpdate, 0, fpFixStreamID, fpFixWindowUpdate(0x7fffffff)); err != nil {
		t.Fatalf("a stream flow-control error tore down the connection: %v", err)
	}
	if !fpFixExchangeFailed(ex) {
		t.Fatalf("stream window overflowed to %d and the stream lived on", ex.h2st.sendWindow)
	}
}

func TestFPFixH2WindowUpdateToExactMaximumIsAccepted(t *testing.T) {
	c, ex := fpFixH2Conn(t)
	h := c.proto.(*h2Proto)
	room := uint32(1<<31-1) - uint32(h2DefaultWindow)
	if err := h.handleFrame(c, h2FrameWindowUpdate, 0, 0, fpFixWindowUpdate(room)); err != nil {
		t.Fatalf("connection window to exactly 2^31-1 rejected: %v", err)
	}
	if err := h.handleFrame(c, h2FrameWindowUpdate, 0, fpFixStreamID, fpFixWindowUpdate(room)); err != nil || fpFixExchangeFailed(ex) {
		t.Fatalf("stream window to exactly 2^31-1 rejected: %v", err)
	}
}

func TestFPFixH2InitialWindowSettingIsBounded(t *testing.T) {
	c, _ := fpFixH2Conn(t)
	if err := c.proto.(*h2Proto).applySettings(c, fpFixSetting(h2SettingsInitialWindowSize, 0x80000000)); err == nil {
		t.Fatalf("SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1 accepted, window now %d", c.h2.peerInitWindow)
	}
	c, _ = fpFixH2Conn(t)
	h := c.proto.(*h2Proto)
	if err := h.handleFrame(c, h2FrameWindowUpdate, 0, fpFixStreamID, fpFixWindowUpdate(uint32(1<<31-1)-uint32(h2DefaultWindow))); err != nil {
		t.Fatalf("window update: %v", err)
	}
	if err := h.applySettings(c, fpFixSetting(h2SettingsInitialWindowSize, h2DefaultWindow+1)); err == nil {
		t.Fatalf("a SETTINGS delta pushed a stream window to %d without an error", c.h2.streams[fpFixStreamID].sendWindow)
	}
}

func fpFixHeadersBlock(fields func(e *hpackEncoder)) []byte {
	var e hpackEncoder
	e.reset(nil)
	e.buf = append(e.buf, 0x88)
	fields(&e)
	return e.buf
}

func TestFPFixH2DecodedHeaderListIsBounded(t *testing.T) {
	c, ex := fpFixH2Conn(t)
	block := fpFixHeadersBlock(func(e *hpackEncoder) {
		e.buf = append(e.buf, 0x40)
		e.appendString("x-a")
		e.appendString(strings.Repeat("v", 4000))
		e.buf = append(e.buf, bytes.Repeat([]byte{0xbe}, 1000)...)
	})
	err := c.proto.(*h2Proto).handleFrame(c, h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, fpFixStreamID, block)
	if err == nil && !fpFixExchangeFailed(ex) {
		t.Fatalf("a %d-byte block decoded into %d header fields", len(block), len(ex.resp.Headers))
	}
}

func TestFPFixH2HeaderListWithinLimitIsAccepted(t *testing.T) {
	c, ex := fpFixH2Conn(t)
	block := fpFixHeadersBlock(func(e *hpackEncoder) {
		e.field("content-type", "text/plain")
		e.field("x-tab", "a\tb")
		e.field("set-cookie", "a=b")
	})
	if err := c.proto.(*h2Proto).handleFrame(c, h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, fpFixStreamID, block); err != nil {
		t.Fatalf("legal block rejected: %v", err)
	}
	select {
	case <-ex.done:
	default:
		t.Fatal("stream did not finish")
	}
	if ex.err != nil || ex.resp.Status != 200 || len(ex.resp.Headers) != 3 {
		t.Fatalf("err=%v status=%d headers=%v", ex.err, ex.resp.Status, ex.resp.Headers)
	}
}

func TestFPFixH2MalformedHeaderFieldsAreRejected(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"x-a", "x\r\nset-cookie: s=evil"},
		{"x-a", "nul\x00byte"},
		{"x-a", "bare\rcr"},
		{"X-Upper", "v"},
		{"bad name", "v"},
		{"x-a", " leading-space"},
	} {
		c, ex := fpFixH2Conn(t)
		block := fpFixHeadersBlock(func(e *hpackEncoder) {
			e.buf = append(e.buf, 0x00)
			e.appendString(tc.name)
			e.appendString(tc.value)
		})
		err := c.proto.(*h2Proto).handleFrame(c, h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, fpFixStreamID, block)
		if err == nil && !fpFixExchangeFailed(ex) {
			t.Errorf("%q: %q delivered to the caller", tc.name, tc.value)
		}
	}
}

func TestFPFixHuffmanRejectsUndecodablePadding(t *testing.T) {
	for _, n := range []int{4, 31, 32, 33, 64} {
		if s, err := fpHpackHuffmanDecode(bytes.Repeat([]byte{0xff}, n)); err == nil {
			t.Errorf("%d bytes of 0xff decoded to %q", n, s)
		}
	}
	enc := []byte{0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff}
	if s, err := fpHpackHuffmanDecode(enc); err != nil || s != "www.example.com" {
		t.Fatalf("RFC 7541 C.4.1 vector: %q %v", s, err)
	}
}

func TestFPFixH2MalformedDynamicEntryStaysRejected(t *testing.T) {
	c, ex := fpFixH2Conn(t)
	h := c.proto.(*h2Proto)
	first := fpFixHeadersBlock(func(e *hpackEncoder) {
		e.buf = append(e.buf, 0x40)
		e.appendString("x-a")
		e.appendString("bad\x00value")
	})
	if err := h.handleFrame(c, h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, fpFixStreamID, first); err != nil || !fpFixExchangeFailed(ex) {
		t.Fatalf("malformed literal: err=%v failed=%v", err, fpFixExchangeFailed(ex))
	}
	const second = fpFixStreamID + 2
	ex2 := &Exchange{req: &fpRequest{Method: "GET"}, done: make(chan struct{}), bc: c}
	st := &h2Stream{id: second, ex: ex2, sendWindow: c.h2.peerInitWindow}
	ex2.h2st = st
	c.h2.streams[second] = st
	reuse := fpFixHeadersBlock(func(e *hpackEncoder) { e.buf = append(e.buf, 0xbe) })
	if err := h.handleFrame(c, h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, second, reuse); err != nil || !fpFixExchangeFailed(ex2) {
		t.Fatalf("indexed reference to a malformed entry: err=%v failed=%v headers=%q", err, fpFixExchangeFailed(ex2), ex2.resp.Headers)
	}
}
