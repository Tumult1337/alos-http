//go:build linux && amd64

package core

import "testing"

func TestQUICTinyPacketsKeepHeaderProtection(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	scid := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	for _, payload := range [][]byte{{quicFramePing}, {quicFrameMaxStreamsUni, 0x11}, {quicFramePing, quicFramePing, quicFramePing}} {
		for _, pn := range []uint64{0, 1, 300} {
			_, sendKeys, err := quicDeriveInitialKeys(dcid)
			if err != nil {
				t.Fatal(err)
			}
			_, recvKeys, _ := quicDeriveInitialKeys(dcid)

			short := quicBuildShortPacket(nil, dcid, payload, pn, int64(pn)-1, sendKeys, 0)
			hdr, err := quicParseShortHeader(short, len(dcid))
			if err != nil {
				t.Fatal(err)
			}
			plain, err := quicDecryptPacket(short, &hdr, recvKeys, int64(pn)-1)
			if err != nil {
				t.Fatalf("short packet with %d-byte payload, pn %d: %v", len(payload), pn, err)
			}
			if hdr.pn != pn || len(plain) < len(payload) || string(plain[:len(payload)]) != string(payload) {
				t.Fatalf("short packet decoded pn %d payload %x", hdr.pn, plain)
			}
			for _, b := range plain[len(payload):] {
				if b != quicFramePadding {
					t.Fatalf("padding byte %#x is not PADDING", b)
				}
			}
			if err := quicParseFrames(plain, &quicFrameVisitor{}); err != nil {
				t.Fatalf("padded payload does not parse: %v", err)
			}

			for name, pkt := range map[string][]byte{
				"handshake": quicBuildHandshakePacket(nil, dcid, scid, payload, pn, int64(pn)-1, sendKeys),
				"initial":   quicBuildInitialPacket(nil, dcid, scid, nil, payload, pn, int64(pn)-1, sendKeys),
			} {
				lh, _, err := quicParseLongHeader(pkt)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if _, err := quicDecryptPacket(pkt, &lh, recvKeys, int64(pn)-1); err != nil {
					t.Fatalf("%s packet with %d-byte payload, pn %d: %v", name, len(payload), pn, err)
				}
			}
		}
	}
}
