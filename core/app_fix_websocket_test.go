//go:build linux && amd64

package core

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"
)

var errAppFixScriptExhausted = errors.New("scripted conn: no more bytes")

type appFixScriptedConn struct {
	net.Conn
	script *bytes.Reader
}

func (c *appFixScriptedConn) Read(p []byte) (int, error) {
	if c.script.Len() == 0 {
		return 0, errAppFixScriptExhausted
	}
	return c.script.Read(p)
}

func (c *appFixScriptedConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *appFixScriptedConn) Close() error                     { return nil }
func (c *appFixScriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *appFixScriptedConn) SetWriteDeadline(time.Time) error { return nil }
func (c *appFixScriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *appFixScriptedConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *appFixScriptedConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }

func appFixMaskedFrameHeader(first byte, declaredLen int) []byte {
	hdr := wsAppendFrameHeader(nil, first, declaredLen)
	hdr[1] |= 0x80
	return append(hdr, wsTestMaskKey[:]...)
}

func appFixScriptedWS(maxMessage int, script ...[]byte) *WSConn {
	ws := newNegotiatedWSConn(newTestReq(), WSUpgradeOptions{})
	ws.MaxMessageSize = maxMessage
	ws.conn = &appFixScriptedConn{script: bytes.NewReader(bytes.Join(script, nil))}
	return ws
}

func appFixBytesAllocated(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestAppFixWSDeclaredFrameLengthIsNotPreallocated(t *testing.T) {
	const declared = wsDefaultMaxMessageSize - 1
	const allocBudget = 4 * wsFrameReadChunk
	ws := appFixScriptedWS(wsDefaultMaxMessageSize, appFixMaskedFrameHeader(0x80|wsOpBinary, declared), []byte("abc"))
	var err error
	allocated := appFixBytesAllocated(func() { _, _, err = ws.ReadMessage() })
	if !errors.Is(err, errAppFixScriptExhausted) {
		t.Fatalf("ReadMessage err %v, want the scripted EOF", err)
	}
	if allocated > allocBudget {
		t.Fatalf("a %d-byte declared frame with 3 payload bytes allocated %d bytes, budget %d", declared, allocated, allocBudget)
	}
}

func TestAppFixWSFragmentedMessageRejectedBeforeReadingOversizedFrame(t *testing.T) {
	const limit = 1024
	first := wsClientFrame(wsOpBinary, bytes.Repeat([]byte{'a'}, 800))
	ws := appFixScriptedWS(limit, first, appFixMaskedFrameHeader(0x80|wsOpContinuation, 800))
	if _, _, err := ws.ReadMessage(); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("ReadMessage err %v, want ErrBodyTooLarge before the second frame's payload is read", err)
	}
}

func TestAppFixWSFragmentedMessageAtLimitStillAssembles(t *testing.T) {
	const limit = 3*wsFrameReadChunk + 7
	part1 := bytes.Repeat([]byte{'x'}, 2*wsFrameReadChunk+3)
	part2 := bytes.Repeat([]byte{'y'}, limit-len(part1))
	ws := appFixScriptedWS(limit, wsClientFrame(wsOpBinary, part1), wsClientFrame(0x80|wsOpContinuation, part2))
	op, msg, err := ws.ReadMessage()
	if err != nil || op != wsOpBinary {
		t.Fatalf("ReadMessage op %d err %v", op, err)
	}
	if !bytes.Equal(msg, append(append([]byte(nil), part1...), part2...)) {
		t.Fatalf("reassembled %d bytes do not match the %d sent", len(msg), len(part1)+len(part2))
	}
}

func TestAppFixWSControlFramesStillDecoded(t *testing.T) {
	ws := appFixScriptedWS(wsDefaultMaxMessageSize, wsClientFrame(0x80|wsOpClose, []byte{0x03, 0xE8, 'b', 'y', 'e'}))
	op, payload, err := ws.ReadMessage()
	if op != wsOpClose || err != io.EOF || string(payload[2:]) != "bye" {
		t.Fatalf("close frame op %d payload %q err %v", op, payload, err)
	}
}

func BenchmarkAppFixWSReadMessage(b *testing.B) {
	for _, size := range []int{128, 16 << 10, 256 << 10} {
		frame := wsClientFrame(0x80|wsOpBinary, bytes.Repeat([]byte{'z'}, size))
		ws := appFixScriptedWS(wsDefaultMaxMessageSize)
		conn := ws.conn.(*appFixScriptedConn)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				conn.script.Reset(frame)
				if _, msg, err := ws.ReadMessage(); err != nil || len(msg) != size {
					b.Fatalf("len %d err %v", len(msg), err)
				}
			}
		})
	}
}

func appFixFinalDeflateStream(t testing.TB, msg []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(msg)
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestAppFixWSInflateEmptyFinalBlockFloodIsBounded(t *testing.T) {
	const emptyFinalBlocks = 200000
	payload := appFixFinalDeflateStream(t, bytes.Repeat([]byte("0123456789abcdef"), wsDeflateWindowSize/16))
	payload = append(payload, bytes.Repeat([]byte{0x03, 0x00}, emptyFinalBlocks)...)
	if _, status := wsInflate(payload, wsDefaultMaxMessageSize); status != wsStatusMessageTooBig {
		t.Fatalf("inflate of 32 KiB + %d empty final blocks returned status %d, want %d", emptyFinalBlocks, status, wsStatusMessageTooBig)
	}
}

func TestAppFixWSInflateLegalFinalBlocksStillDecode(t *testing.T) {
	hello := append(appFixFinalDeflateStream(t, []byte("Hello")), 0x00)
	if out, status := wsInflate(hello, 1024); status != 0 || string(out) != "Hello" {
		t.Fatalf("single BFINAL message: out %q status %d", out, status)
	}
	var multi, want []byte
	for i := 0; i < 8; i++ {
		part := bytes.Repeat([]byte{byte('a' + i)}, 40<<10)
		multi = append(multi, appFixFinalDeflateStream(t, part)...)
		want = append(want, part...)
	}
	multi = append(multi, 0x00)
	if out, status := wsInflate(multi, wsDefaultMaxMessageSize); status != 0 || !bytes.Equal(out, want) {
		t.Fatalf("8 concatenated BFINAL streams: %d bytes status %d, want %d bytes", len(out), status, len(want))
	}
}
