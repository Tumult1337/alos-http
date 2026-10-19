//go:build linux && amd64

package core

import "testing"

func fuzzQUICVisitor() *quicFrameVisitor {
	return &quicFrameVisitor{
		onPadding:       func() {},
		onPing:          func() {},
		onACK:           func(quicAckFrame) {},
		onCrypto:        func(quicCryptoFrame) {},
		onStream:        func(quicStreamFrame) {},
		onMaxData:       func(quicMaxDataFrame) {},
		onMaxStreamData: func(quicMaxStreamDataFrame) {},
		onMaxStreams:    func(quicMaxStreamsFrame) {},
		onResetStream:   func(quicResetStreamFrame) {},
		onStopSending:   func(quicStopSendingFrame) {},
		onConnClose:     func(quicConnCloseFrame) {},
		onHandshakeDone: func() {},
		onNewConnID:     func(quicNewConnIDFrame) {},
		onNewToken:      func([]byte) {},
		allowed:         func(uint64) bool { return true },
	}
}

func FuzzQUICFrames(f *testing.F) {
	for _, s := range [][]byte{
		{0x00, 0x00, 0x01},
		{0x02, 0x05, 0x00, 0x00, 0x05},
		{0x06, 0x00, 0x04, 'a', 'b', 'c', 'd'},
		{0x0f, 0x04, 0x00, 0x03, 'a', 'b', 'c'},
		{0x04, 0x04, 0x00, 0x00},
		{0x05, 0x04, 0x40, 0x0c},
		{0x21},
		{0x1c, 0x0a, 0x00, 0x00},
		{0x18, 0x01, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		{0x02, 0x3f, 0xff, 0x00, 0x3f, 0xff, 0xff, 0xff},
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = quicParseFrames(data, fuzzQUICVisitor())
	})
}

func FuzzQUICLongHeader(f *testing.F) {
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x00, 0x41, 0x00})
	f.Add([]byte{0xe0, 0x00, 0x00, 0x00, 0x01, 0x14})
	f.Fuzz(func(t *testing.T, data []byte) {
		hdr, total, err := quicParseLongHeader(data)
		if err != nil {
			return
		}
		if total > len(data) || hdr.payloadOff+hdr.payloadLen > len(data) || hdr.payloadOff < 0 || hdr.payloadLen < 0 {
			t.Fatalf("header bounds total=%d off=%d len=%d exceed packet %d", total, hdr.payloadOff, hdr.payloadLen, len(data))
		}
	})
}

func FuzzQUICShortDecrypt(f *testing.F) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	keys, _, err := quicDeriveInitialKeys(dcid)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(quicBuildShortPacket(nil, dcid, []byte{0x01, 0x00, 0x00, 0x00}, 7, 6, keys, 0))
	f.Add([]byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Fuzz(func(t *testing.T, data []byte) {
		pkt := append([]byte(nil), data...)
		hdr, perr := quicParseShortHeader(pkt, len(dcid))
		if perr != nil {
			return
		}
		_, _ = quicDecryptPacket(pkt, &hdr, keys, 0)
	})
}

func FuzzQUICTransportParams(f *testing.F) {
	f.Add([]byte{0x01, 0x02, 0x40, 0x64, 0x04, 0x04, 0x80, 0x10, 0x00, 0x00})
	f.Add([]byte{0x0f, 0x08, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Fuzz(func(t *testing.T, data []byte) {
		var ch ParsedClientHello
		parseQUICTransportParams(&ch, data)
	})
}

func FuzzQPACKDecode(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0xd1, 0xd7, 0x50, 0x01, 'a', 0xc1})
	f.Add([]byte{0x00, 0x00, 0x5f, 0x1d, 0x01, 'x'})
	f.Add([]byte{0x00, 0x00, 0x3f, 0xff, 0xff, 0xff, 0x0f})
	f.Fuzz(func(t *testing.T, data []byte) {
		var dec QPACKDecoder
		_, _ = dec.Decode(data)
	})
}
