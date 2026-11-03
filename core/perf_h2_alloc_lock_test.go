//go:build linux && amd64

package core

import "testing"

const (
	perfH2LockRuns            = 200
	perfH2LockRoundTripRuns   = 50
	perfH2LockFrameSpare      = 1 << 20
	perfH2LockDataFrame       = 16 << 10
	perfH2LockTLSClientBudget = perfH2Streams / 10
)

func perfH2AssertZeroAllocs(t *testing.T, name string, fn func()) {
	t.Helper()
	if got := testing.AllocsPerRun(perfH2LockRuns, fn); got != 0 {
		t.Fatalf("%s: %v allocs per run, want 0", name, got)
	}
}

func TestPerfH2AllocLockHpackDecodeMemoHit(t *testing.T) {
	for _, wl := range perfH2HpackWorkloads {
		d, block := perfH2WarmDecoder(t, wl, "https")
		var headers [][2]string
		perfH2AssertZeroAllocs(t, wl.name, func() {
			var err error
			headers, _, err = d.DecodeRequest(headers[:0], block)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPerfH2AllocLockHpackDecodeSteadyHuffman(t *testing.T) {
	for _, wl := range perfH2HpackWorkloads {
		d, block := perfH2WarmDecoder(t, wl, "https")
		var headers [][2]string
		perfH2AssertZeroAllocs(t, wl.name, func() {
			var err error
			headers, _, err = d.DecodeIntoRequest(headers[:0], block)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPerfH2AllocLockResponseHeaderEncode(t *testing.T) {
	for _, s := range perfH2RespShapes {
		enc := HpackEncoder{Buf: make([]byte, 0, perfH2HpackHeaderSpare)}
		perfH2EncodeShape(&enc, s)
		perfH2AssertZeroAllocs(t, s.name, func() {
			enc.Reset(enc.Buf[:0])
			perfH2EncodeShape(&enc, s)
		})
	}
}

func TestPerfH2AllocLockResponseHeadersFrame(t *testing.T) {
	for _, s := range perfH2RespShapes {
		var resp Response
		resp.Reset()
		resp.Status(s.status)
		resp.ContentType = s.contentType
		resp.body = make([]byte, s.length)
		for _, h := range s.headers {
			resp.SetHeader(h[0], h[1])
		}
		dst := appendH2ResponseHeadersFrameIndexed(make([]byte, 0, perfH2HpackHeaderSpare), perfH2HpackStreamID, &resp, false, nil, respServerName(&resp), 0)
		perfH2AssertZeroAllocs(t, s.name, func() {
			dst = appendH2ResponseHeadersFrameIndexed(dst[:0], perfH2HpackStreamID, &resp, false, nil, respServerName(&resp), 0)
		})
	}
}

func TestPerfH2AllocLockFrameBuilders(t *testing.T) {
	dst := make([]byte, 0, perfH2LockFrameSpare)
	data := make([]byte, perfH2LockDataFrame)
	var ping [8]byte
	srv := New(Config{PlainHTTP: true, HTTPAddr: "-"})
	builders := []struct {
		name string
		fn   func()
	}{
		{"appendH2Frame/data16k", func() { dst = appendH2Frame(dst[:0], H2FrameData, H2FlagEndStream, 1, data) }},
		{"appendH2WindowUpdateFrame", func() { dst = appendH2WindowUpdateFrame(dst[:0], 1, 1<<20) }},
		{"appendH2RSTStreamFrame", func() { dst = appendH2RSTStreamFrame(dst[:0], 1, H2ErrCancel) }},
		{"appendH2GoAwayFrame", func() { dst = appendH2GoAwayFrame(dst[:0], 1, H2ErrEnhanceYourCalm) }},
		{"appendH2PingFrame", func() { dst = appendH2PingFrame(dst[:0], true, ping) }},
		{"appendH2SettingsAckFrame", func() { dst = appendH2SettingsAckFrame(dst[:0]) }},
		{"appendH2ServerSettingsFlight", func() { dst = appendH2ServerSettingsFlight(dst[:0], srv) }},
		{"appendH2StatusOnlyResponse", func() {
			dst = appendH2StatusOnlyResponseIndexed(dst[:0], 1, h2StatusHeaderListTooLarge, "ALOS", nil, 0)
		}},
	}
	for _, b := range builders {
		perfH2AssertZeroAllocs(t, b.name, b.fn)
	}
}

func perfH2RoundTripAllocs(t *testing.T, useTLS bool, wl perfH2Workload) float64 {
	t.Helper()
	addr := perfH2TestServer(t, useTLS)
	cl := perfH2Ready(t, addr, useTLS, wl, perfH2Streams)
	return testing.AllocsPerRun(perfH2LockRoundTripRuns, func() { cl.roundTrip(perfH2Streams) })
}

func TestPerfH2AllocLockH2cRootRoundTrip(t *testing.T) {
	perfTLSSkipUnderRace(t)
	if got := perfH2RoundTripAllocs(t, false, perfH2W1r); got != 0 {
		t.Fatalf("h2c GET / with %d streams: %v allocs per batch, want 0", perfH2Streams, got)
	}
}

func TestPerfH2AllocLockTLSRootRoundTrip(t *testing.T) {
	perfTLSSkipUnderRace(t)
	if got := perfH2RoundTripAllocs(t, true, perfH2W1r); got >= perfH2LockTLSClientBudget {
		t.Fatalf("TLS h2 GET / with %d streams: %v allocs per batch, want < %d (client crypto/tls only)", perfH2Streams, got, perfH2LockTLSClientBudget)
	}
}
