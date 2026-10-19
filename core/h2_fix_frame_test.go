//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

const (
	h2FixGrowthFrames    = 10000
	h2FixGrowthMaxAllocs = 64
)

func TestH2FixAppendFrameGrowthIsAmortised(t *testing.T) {
	payload := []byte{0, 0, 0, 1}
	allocs := testing.AllocsPerRun(3, func() {
		var dst []byte
		for range h2FixGrowthFrames {
			dst = appendH2Frame(dst, H2FrameWindowUpdate, 0, 1, payload)
		}
		if len(dst) != h2FixGrowthFrames*(9+len(payload)) {
			t.Fatalf("len = %d", len(dst))
		}
	})
	if allocs > h2FixGrowthMaxAllocs {
		t.Fatalf("%d appends of a 13-byte frame allocated %.0f times, want <= %d: growth is not amortised", h2FixGrowthFrames, allocs, h2FixGrowthMaxAllocs)
	}
}

func TestH2FixAppendFramePreservesPrefix(t *testing.T) {
	prefix := []byte("prefix-bytes")
	dst := append([]byte(nil), prefix...)
	dst = appendH2Frame(dst, H2FrameData, H2FlagEndStream, 3, []byte("abc"))
	want := append(append([]byte(nil), prefix...), 0, 0, 3, H2FrameData, H2FlagEndStream, 0, 0, 0, 3, 'a', 'b', 'c')
	if !bytes.Equal(dst, want) {
		t.Fatalf("got %x want %x", dst, want)
	}
}

func BenchmarkH2FixAppendFrameReused(b *testing.B) {
	payload := make([]byte, 16)
	buf := make([]byte, 0, 4096)
	b.ReportAllocs()
	for b.Loop() {
		dst := buf[:0]
		for range 64 {
			dst = appendH2Frame(dst, H2FrameData, 0, 1, payload)
		}
		buf = dst
	}
}

func BenchmarkH2FixAppendFrameFromEmpty(b *testing.B) {
	payload := make([]byte, 16)
	b.ReportAllocs()
	for b.Loop() {
		var dst []byte
		for range 64 {
			dst = appendH2Frame(dst, H2FrameData, 0, 1, payload)
		}
		_ = dst
	}
}

const h2FixFramePrefixSpare = 64

func TestH2FixExportedWritersAppend(t *testing.T) {
	writers := map[string]func([]byte) []byte{
		"Frame": func(dst []byte) []byte { return H2WriteFrame(dst, H2FrameData, H2FlagEndStream, 5, []byte("body")) },
		"Settings": func(dst []byte) []byte {
			return H2WriteSettings(dst, [][2]uint32{{uint32(H2SettingInitialWindowSize), 65535}, {uint32(H2SettingMaxFrameSize), 16384}})
		},
		"SettingsAck":  H2WriteSettingsAck,
		"WindowUpdate": func(dst []byte) []byte { return H2WriteWindowUpdate(dst, 7, 1024) },
		"GoAway":       func(dst []byte) []byte { return H2WriteGoAway(dst, 9, H2ErrProtocol) },
		"Ping":         func(dst []byte) []byte { return H2WritePing(dst, true, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}) },
		"RSTStream":    func(dst []byte) []byte { return H2WriteRSTStream(dst, 11, H2ErrCancel) },
		"Continuation": func(dst []byte) []byte { return H2WriteContinuation(dst, H2FlagEndHeaders, 13, []byte{0x82}) },
	}
	for name, write := range writers {
		frame := write(nil)
		for _, spare := range []int{0, h2FixFramePrefixSpare} {
			prefix := make([]byte, len(H2ClientPreface), len(H2ClientPreface)+spare)
			copy(prefix, H2ClientPreface[:])
			got := write(prefix)
			want := append(append([]byte(nil), H2ClientPreface[:]...), frame...)
			if !bytes.Equal(got, want) {
				t.Errorf("%s (spare cap %d): H2Write%s did not append to dst:\n got %x\nwant %x", name, spare, name, got, want)
			}
		}
	}
}

func TestH2FixExportedWritersChain(t *testing.T) {
	wire := append([]byte(nil), H2ClientPreface[:]...)
	wire = H2WriteSettings(wire, nil)
	wire = H2WriteSettingsAck(wire)
	wire = H2WriteWindowUpdate(wire, 0, 1)
	want := len(H2ClientPreface) + 9 + 9 + 13
	if len(wire) != want || !bytes.Equal(wire[:len(H2ClientPreface)], H2ClientPreface[:]) {
		t.Fatalf("chained preface+SETTINGS+ACK+WINDOW_UPDATE is %d bytes (preface kept=%v), want %d", len(wire), bytes.HasPrefix(wire, H2ClientPreface[:]), want)
	}
}
