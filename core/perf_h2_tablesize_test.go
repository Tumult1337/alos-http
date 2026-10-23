//go:build linux && amd64

package core

import (
	"testing"
)

const perfH2TableSizeUpdateMask = 0xe0

func perfH2TableSizeRoutes(srv *Server) {
	srv.Router.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("root") })
	srv.Router.GET("/vary", func(req *Request, resp *Response) {
		resp.SetHeader("Vary", "Accept-Encoding").Status(200).String("vary")
	})
	srv.Router.GET("/stream", func(req *Request, resp *Response) {
		sw := resp.EnsureStreamWriter()
		if sw == nil {
			resp.Status(500).String("no stream writer")
			return
		}
		resp.SetStreamer(sw)
		_ = sw.WriteHeader(200, nil, "text/plain")
		_ = sw.WriteChunk([]byte("chunk"))
	})
}

func perfH2ResponseBlock(t *testing.T, rc *h2RawConn, streamID uint32, path string) []byte {
	t.Helper()
	h2FixGet(rc, streamID, path)
	f, err := rc.awaitStreamOutcome(streamID)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if f.typ != H2FrameHeaders {
		t.Fatalf("%s: answered with frame type %d", path, f.typ)
	}
	return f.payload
}

func TestH2PeerTableSizeReductionIsSignalledFirstOnEveryPath(t *testing.T) {
	addr := startH2FixServer(t, nil, perfH2TableSizeRoutes)
	for _, first := range []string{"/", "/vary", "/stream"} {
		rc := h2RawDial(t, addr, h2FixSettings([2]uint32{uint32(H2SettingHeaderTableSize), 0}))
		dec := &HpackDecoder{maxTableSize: 4096, protocolMaxSize: 0, maxHeaderListSize: 1 << 20}
		block := perfH2ResponseBlock(t, rc, 1, first)
		if len(block) == 0 || block[0]&perfH2TableSizeUpdateMask != 0x20 {
			t.Fatalf("first response (%s) after SETTINGS_HEADER_TABLE_SIZE=0 does not start with a table size update: % x", first, block)
		}
		if _, err := dec.DecodeInto(nil, block); err != nil {
			t.Fatalf("first response (%s): %v", first, err)
		}
		for i, path := range []string{"/vary", "/", "/stream", "/vary"} {
			block = perfH2ResponseBlock(t, rc, uint32(2*i+3), path)
			if block[0]&perfH2TableSizeUpdateMask == 0x20 {
				t.Fatalf("response %s repeats the table size update", path)
			}
			fields, err := dec.DecodeInto(nil, block)
			if err != nil {
				t.Fatalf("response %s after %s: %v", path, first, err)
			}
			if fields[0] != [2]string{":status", "200"} {
				t.Fatalf("response %s: first field %q", path, fields[0])
			}
		}
		_ = rc.conn.Close()
	}
}
