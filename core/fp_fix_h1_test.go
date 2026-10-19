//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

const fpFixTestMaxBody = 1 << 10

func fpFixH1Conn(response string) *backendConn {
	l := newLoopForTest()
	l.cfg.fill(1)
	l.cfg.MaxResponseBody = fpFixTestMaxBody
	c := &backendConn{be: &l.beLoop, cur: &Exchange{req: &fpRequest{Method: "GET"}}}
	c.h1.reset()
	c.rbuf.write([]byte(response))
	return c
}

func TestFPFixChunkSizeOverflowIsRejected(t *testing.T) {
	for _, size := range []string{"7fffffffffffffff", "ffffffffffffffff", "+10", "4000000000000"} {
		c := fpFixH1Conn("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n" + size + "\r\n")
		done, err := c.h1.advance(c)
		if err == nil || done {
			t.Errorf("chunk size %s: done=%v err=%v, want a rejection", size, done, err)
			continue
		}
	}
	c := fpFixH1Conn("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n7fffffffffffffff\r\n")
	if _, err := c.h1.advance(c); err == nil {
		c.rbuf.write([]byte(strings.Repeat("x", 4*fpFixTestMaxBody)))
		_, _ = c.h1.advance(c)
		t.Fatalf("buffered body grew to %d bytes past a %d-byte cap", len(c.h1.body), fpFixTestMaxBody)
	}
}

func TestFPFixChunkSizeStillAcceptsLegalSizes(t *testing.T) {
	c := fpFixH1Conn("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n 0002 \r\nde\r\n0\r\n\r\n")
	done, err := c.h1.advance(c)
	if err != nil || !done || string(c.h1.body) != "abcde" {
		t.Fatalf("done=%v err=%v body=%q", done, err, c.h1.body)
	}
	over := fpFixH1Conn("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n401\r\n")
	if _, err := over.h1.advance(over); err != errFPBodyTooLarge {
		t.Fatalf("chunk above the body cap: err=%v, want errFPBodyTooLarge", err)
	}
}

func TestFPFixResponseHeaderInjectionIsRejected(t *testing.T) {
	for _, line := range []string{
		"Location: /x\rSet-Cookie: sid=attacker",
		"X-A: a\x00b",
		"X\rA: b",
		"X A: b",
		"X\x00A: b",
		" folded: b",
		"X-\x7fA: b",
	} {
		var p h1Parser
		block := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n" + line)
		if _, _, err := p.parseHeaderBlock(block, "GET"); err == nil {
			t.Errorf("%q: accepted", line)
		}
	}
}

func TestFPFixResponseHeadersStillAcceptLegalFields(t *testing.T) {
	var p h1Parser
	block := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Tab: a\tb\r\nX-Obs: caf\xc3\xa9\r\nBare-LF: ok\nX-Empty:\r\n")
	if _, _, err := p.parseHeaderBlock(block, "GET"); err != nil {
		t.Fatalf("legal header block rejected: %v", err)
	}
	if len(p.hdr) != 5 {
		t.Fatalf("parsed %d headers, want 5", len(p.hdr))
	}
}

func TestFPFixByteBufferCompactsDeadPrefix(t *testing.T) {
	const frame = 100
	const keep = 10
	var bb byteBuffer
	chunk := make([]byte, frame)
	maxCap := 0
	for i := 0; i < 10000; i++ {
		bb.write(chunk)
		bb.consume(bb.length() - keep)
		maxCap = max(maxCap, cap(bb.b))
	}
	if maxCap > 8*frame {
		t.Fatalf("buffer capacity reached %d bytes while never holding more than %d live bytes", maxCap, frame+keep)
	}
	if bb.length() != keep {
		t.Fatalf("live bytes = %d, want %d", bb.length(), keep)
	}
}

func TestFPFixStatusTextIsCorrect(t *testing.T) {
	for code, want := range map[int]string{
		101: "Switching Protocols",
		200: "OK",
		202: "Accepted",
		400: "Bad Request",
		418: "I'm a teapot",
		504: "Gateway Timeout",
		599: "Unknown",
	} {
		if got := statusText(code); got != want {
			t.Errorf("statusText(%d) = %q, want %q", code, got, want)
		}
	}
}
