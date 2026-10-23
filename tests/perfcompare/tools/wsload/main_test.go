package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func buildServerFrame(payload []byte) []byte {
	n := len(payload)
	frame := []byte{finBit | opText}
	switch {
	case n <= maxControlPayload:
		frame = append(frame, byte(n))
	case n <= 0xFFFF:
		frame = append(frame, 126)
		frame = binary.BigEndian.AppendUint16(frame, uint16(n))
	default:
		frame = append(frame, 127)
		frame = binary.BigEndian.AppendUint64(frame, uint64(n))
	}
	return append(frame, payload...)
}

func startEchoPeer(tb testing.TB, clientFrameLen int, reply []byte) net.Conn {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		in := make([]byte, clientFrameLen)
		for {
			if _, err := io.ReadFull(conn, in); err != nil {
				return
			}
			if _, err := conn.Write(reply); err != nil {
				return
			}
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	return conn
}

func newBenchConn(tb testing.TB, size int) *wsConn {
	payload := bytes.Repeat([]byte{payloadByte}, size)
	const maskKey = 0x5a17c3e9
	frame := buildMaskedFrame(opText, payload, maskKey)
	conn := startEchoPeer(tb, len(frame), buildServerFrame(payload))
	return newWSConn(conn, frame, size, maskKey)
}

func TestMaskedFrameUnmasks(t *testing.T) {
	for _, size := range []int{0, 64, 125, 126, 16384, 70000} {
		payload := bytes.Repeat([]byte{payloadByte}, size)
		frame := buildMaskedFrame(opText, payload, 0x01020304)
		hdr := len(frame) - size
		key := frame[hdr-4 : hdr]
		for i := range size {
			if frame[hdr+i]^key[i&3] != payloadByte {
				t.Fatalf("size %d: byte %d does not unmask", size, i)
			}
		}
	}
}

func TestRoundTripVerifiesLength(t *testing.T) {
	c := newBenchConn(t, 16384)
	var h histogram
	for range 50 {
		if err := c.timedRoundTrip(&h); err != nil {
			t.Fatal(err)
		}
	}
	payload := bytes.Repeat([]byte{payloadByte}, 64)
	frame := buildMaskedFrame(opText, payload, 1)
	short := newWSConn(startEchoPeer(t, len(frame), buildServerFrame(payload[:63])), frame, 64, 1)
	if err := short.roundTrip(); err != errLengthMismatch {
		t.Fatalf("got %v, want errLengthMismatch", err)
	}
}

func TestHistogramQuantiles(t *testing.T) {
	var h histogram
	for v := uint64(1); v <= 1000; v++ {
		h.record(v)
	}
	var total histogramTotal
	total.add(&h)
	p50, p99 := total.quantile(0.50), total.quantile(0.99)
	if p50 < 490 || p50 > 510 || p99 < 975 || p99 > 1005 {
		t.Fatalf("p50=%d p99=%d", p50, p99)
	}
	for v := uint64(0); v < 1<<20; v = v*2 + 1 {
		if histIndex(v) >= histBuckets {
			t.Fatalf("index out of range for %d", v)
		}
	}
}

func benchmarkFrameLoop(b *testing.B, size int) {
	c := newBenchConn(b, size)
	var h histogram
	b.ReportAllocs()
	b.SetBytes(int64(size))
	b.ResetTimer()
	for b.Loop() {
		if err := c.timedRoundTrip(&h); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFrameLoop64(b *testing.B)    { benchmarkFrameLoop(b, 64) }
func BenchmarkFrameLoop16384(b *testing.B) { benchmarkFrameLoop(b, 16384) }
