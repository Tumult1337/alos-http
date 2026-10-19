//go:build linux && amd64

package core

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func responseHeaderBlockOfSize(t *testing.T, size int) ([][2]string, []byte) {
	t.Helper()
	padding := size - 24
	for adjustment := -32; adjustment <= 32; adjustment++ {
		if padding+adjustment < 0 {
			continue
		}
		headers := [][2]string{{"x-padding", strings.Repeat("\xff", padding+adjustment)}}
		encoder := HpackEncoder{}
		encodeH2ResponseHeaders(&encoder, 200, "", 0, headers, "ALOS")
		if len(encoder.Buf) == size {
			return headers, encoder.Buf
		}
	}
	t.Fatalf("could not produce independently sized %d-byte encoded block", size)
	return nil, nil
}

func responseHeaderFlight(t *testing.T, wire []byte, streamID uint32, maxFrame int, endStream bool) ([]byte, []byte, int) {
	t.Helper()
	var block, body []byte
	headerFrames := 0
	endedHeaders := false
	for len(wire) > 0 {
		if len(wire) < 9 {
			t.Fatal("truncated frame header")
		}
		size := int(wire[0])<<16 | int(wire[1])<<8 | int(wire[2])
		kind, flags := wire[3], wire[4]
		if size > maxFrame || size > len(wire)-9 {
			t.Fatalf("frame size=%d limit=%d remaining=%d", size, maxFrame, len(wire)-9)
		}
		if got := binary.BigEndian.Uint32(wire[5:9]); got != streamID {
			t.Fatalf("frame stream=%d want=%d", got, streamID)
		}
		switch kind {
		case H2FrameHeaders, H2FrameContinuation:
			if endedHeaders {
				t.Fatal("header fragment after END_HEADERS")
			}
			if headerFrames == 0 && kind != H2FrameHeaders || headerFrames > 0 && kind != H2FrameContinuation {
				t.Fatalf("wrong field-block frame type=%d index=%d", kind, headerFrames)
			}
			if headerFrames == 0 {
				if (flags&H2FlagEndStream != 0) != endStream {
					t.Fatalf("initial HEADERS flags=%02x endStream=%v", flags, endStream)
				}
			} else if flags&H2FlagEndStream != 0 {
				t.Fatal("END_STREAM on continuation")
			}
			block = append(block, wire[9:9+size]...)
			endedHeaders = flags&H2FlagEndHeaders != 0
			headerFrames++
		case H2FrameData:
			if !endedHeaders {
				t.Fatal("DATA interleaved into header block")
			}
			body = append(body, wire[9:9+size]...)
		default:
			t.Fatalf("unexpected frame type=%d", kind)
		}
		wire = wire[9+size:]
	}
	if !endedHeaders || headerFrames == 0 {
		t.Fatal("incomplete field block")
	}
	return block, body, headerFrames
}

func TestH2ResponseHeaderFragmentationBuffered(t *testing.T) {
	for _, size := range []int{16384, 16385, 32768, 32769} {
		headers, expected := responseHeaderBlockOfSize(t, size)
		for _, spare := range []bool{false, true} {
			prefix := []byte("PENDING")
			output := bytes.Clone(prefix)
			if spare {
				output = make([]byte, len(prefix), len(prefix)+size+9*8)
				copy(output, prefix)
			}
			originalAddress := &output[0]
			wire := appendH2ResponseHeadersFrame(output, 7, &Response{StatusCode: 200, Headers: headers}, true, H2DefaultMaxFrameSize)
			if !bytes.Equal(wire[:len(prefix)], prefix) {
				t.Fatal("existing output prefix changed")
			}
			if spare && &wire[0] != originalAddress {
				t.Fatal("alias fixture unexpectedly reallocated")
			}
			got, body, frames := responseHeaderFlight(t, wire[len(prefix):], 7, H2DefaultMaxFrameSize, true)
			if !bytes.Equal(got, expected) || len(body) != 0 {
				t.Fatal("header block changed")
			}
			fields, err := newHpackDecoder(4096).Decode(got)
			if err != nil {
				t.Fatal(err)
			}
			status, padding := "", ""
			for _, field := range fields {
				if field[0] == ":status" {
					status = field[1]
				}
				if field[0] == "x-padding" {
					padding = field[1]
				}
			}
			if status != "200" || padding != headers[0][1] {
				t.Fatal("decoded response fields changed")
			}
			if frames != (size+16383)/16384 {
				t.Fatalf("frames=%d size=%d", frames, size)
			}
		}
	}
}

func TestH2ResponseHeaderFragmentationStatusOnly(t *testing.T) {
	serverName := strings.Repeat("\xff", 16385)
	encoder := HpackEncoder{}
	encodeH2ResponseHeaders(&encoder, 431, "", 0, nil, serverName)
	wire := appendH2StatusOnlyResponse(nil, 9, 431, serverName, H2DefaultMaxFrameSize)
	got, body, _ := responseHeaderFlight(t, wire, 9, H2DefaultMaxFrameSize, true)
	if !bytes.Equal(got, encoder.Buf) || len(body) != 0 {
		t.Fatal("status-only encoded fields changed")
	}
}

func TestH2ResponseHeaderFragmentationRootTemplates(t *testing.T) {
	for _, size := range []int{64, 16384, 16385, 32769} {
		_, block := responseHeaderBlockOfSize(t, size)
		for _, body := range [][]byte{nil, []byte("body"), bytes.Repeat([]byte("b"), 32769)} {
			cached := newH2RootFastResponse(bytes.Clone(block), bytes.Clone(body))
			originalHeader, originalBody := bytes.Clone(cached.headerPayload), bytes.Clone(cached.body)
			for _, streamID := range []uint32{1, 3} {
				wire := appendFastH2RootResponse(nil, cached, streamID, H2DefaultMaxFrameSize)
				got, actual, _ := responseHeaderFlight(t, wire, streamID, H2DefaultMaxFrameSize, len(body) == 0)
				if !bytes.Equal(got, block) || !bytes.Equal(actual, body) {
					t.Fatal("root template header/body changed")
				}
			}
			if !bytes.Equal(originalHeader, cached.headerPayload) || !bytes.Equal(originalBody, cached.body) {
				t.Fatal("cached template changed")
			}
			shouldFrame := size <= 16384 && len(body) <= 16384
			if (len(cached.framed) > 0) != shouldFrame {
				t.Fatalf("header=%d body=%d preframed=%v", size, len(body), len(cached.framed) > 0)
			}
		}
	}
}

func TestH2ResponseHeaderFragmentationStreamAndBodyFlow(t *testing.T) {
	headers, _ := responseHeaderBlockOfSize(t, 32769)
	for _, onlyHeaders := range []bool{false, true} {
		connection := &epollConn{}
		connection.h2.maxFrameSize = H2DefaultMaxFrameSize
		stream := &H2Stream{}
		writer := newEpollH2StreamWriter().(*epollH2StreamWriter)
		writer.stream, writer.streamID, writer.serverName, writer.method = stream, 11, "ALOS", "GET"
		writer.pumpQueued = true
		if err := writer.WriteHeader(200, headers, ""); err != nil {
			t.Fatal(err)
		}
		expected := bytes.Clone(writer.header)
		writer.ended = true
		if !onlyHeaders {
			writer.pending = []byte("ok")
		}
		first := connection.h2PumpFrames(nil, writer, 0)
		got, body, _ := responseHeaderFlight(t, first, 11, H2DefaultMaxFrameSize, onlyHeaders)
		if !bytes.Equal(got, expected) || len(body) != 0 {
			t.Fatal("stream header changed or zero-window DATA sent")
		}
		if onlyHeaders {
			if !writer.finished {
				t.Fatal("header-only stream not finished")
			}
			continue
		}
		if writer.finished || writer.pendingOff != 0 || connection.h2.connWindow != 0 || stream.Window.Load() != 0 {
			t.Fatal("header output consumed DATA flow state")
		}
		connection.h2.connWindow = 2
		stream.Window.Store(2)
		rest := connection.h2PumpFrames(nil, writer, 0)
		if len(rest) != 11 || rest[3] != H2FrameData || rest[4]&H2FlagEndStream == 0 || string(rest[9:]) != "ok" {
			t.Fatalf("DATA after complete headers=%x", rest)
		}
	}
}

func TestH2ResponseHeaderFragmentationBufferedBodyFlow(t *testing.T) {
	headers, _ := responseHeaderBlockOfSize(t, 32769)
	connection := &epollConn{}
	connection.h2.maxFrameSize = H2DefaultMaxFrameSize
	stream := &H2Stream{}
	stream.resp.StatusCode = 200
	stream.resp.Headers = headers
	stream.resp.SetBody([]byte("ok"))
	first, done := connection.h2AppendWindowed(nil, stream, 15, 1<<20)
	encoder := HpackEncoder{}
	encodeH2ResponseHeaders(&encoder, 200, "", 2, headers, "ALOS")
	expected := encoder.Buf
	got, body, _ := responseHeaderFlight(t, first, 15, H2DefaultMaxFrameSize, false)
	if done || !bytes.Equal(got, expected) || len(body) != 0 || stream.respOff != 0 || connection.h2.connWindow != 0 || stream.Window.Load() != 0 {
		t.Fatal("buffered headers/data flow changed")
	}
	connection.h2.connWindow = 2
	stream.Window.Store(2)
	rest, done := connection.h2AppendWindowed(nil, stream, 15, 1<<20)
	if !done || len(rest) != 11 || rest[3] != H2FrameData || rest[4]&H2FlagEndStream == 0 || string(rest[9:]) != "ok" {
		t.Fatalf("buffered DATA done=%v wire=%x", done, rest)
	}
}

func TestH2ResponseHeaderFragmentationNegotiatedDirection(t *testing.T) {
	headers, expected := responseHeaderBlockOfSize(t, 20000)
	for _, peerLimit := range []uint32{16384, 32768} {
		server := New(Config{H2MaxFrameSize: 16384})
		connection := &epollConn{worker: &epollWorker{server: server}}
		connection.h2.maxFrameSize = H2DefaultMaxFrameSize
		if !connection.epollH2Settings(h2FixSettings([2]uint32{uint32(H2SettingMaxFrameSize), peerLimit})) {
			t.Fatal("valid peer frame limit rejected")
		}
		if server.h2MaxFrameSize() != 16384 || connection.h2.maxFrameSize != peerLimit {
			t.Fatal("inbound and outbound limits conflated")
		}
		stream := &H2Stream{}
		stream.resp.StatusCode = 200
		stream.resp.Headers = headers
		wire, done := connection.h2AppendWindowed(nil, stream, 21, 1<<20)
		got, _, frames := responseHeaderFlight(t, wire, 21, int(peerLimit), true)
		if !done || !bytes.Equal(got, expected) {
			t.Fatal("negotiated buffered block changed")
		}
		wantFrames := 2
		if peerLimit == 32768 {
			wantFrames = 1
		}
		if frames != wantFrames {
			t.Fatalf("peer=%d frames=%d want=%d", peerLimit, frames, wantFrames)
		}
		writer := newEpollH2StreamWriter().(*epollH2StreamWriter)
		writer.stream, writer.streamID, writer.header, writer.headerReady, writer.ended = &H2Stream{}, 23, expected, true, true
		wire = connection.h2PumpFrames(nil, writer, 0)
		_, _, frames = responseHeaderFlight(t, wire, 23, int(peerLimit), true)
		if frames != wantFrames {
			t.Fatalf("peer=%d streamframes=%d want=%d", peerLimit, frames, wantFrames)
		}
		server.config.ServerName = strings.Repeat("\xff", 20000)
		connection.writeBuf = nil
		if connection.answerH2HeaderListTooLarge(server, 25, true) {
			t.Fatal("first status reply unexpectedly closed connection")
		}
		_, _, frames = responseHeaderFlight(t, connection.writeBuf, 25, int(peerLimit), true)
		if frames != wantFrames {
			t.Fatalf("peer=%d statusframes=%d want=%d", peerLimit, frames, wantFrames)
		}
	}
}

func TestH2ResponseHeaderFragmentationAppenderEdges(t *testing.T) {
	for _, size := range []int{0, 1, 7, 8, 9, 16, 17, 16384, 16385} {
		block := make([]byte, size)
		for index := range block {
			block[index] = byte(index*17 + 3)
		}
		for _, limit := range []int{0, -1, 8, 16384, 32768} {
			effective := limit
			if effective <= 0 {
				effective = 16384
			}
			for _, endStream := range []bool{false, true} {
				flags := byte(0)
				if endStream {
					flags = H2FlagEndStream
				}
				output := appendH2ResponseHeaderBlock([]byte("PREFIX"), 31, flags, block, limit)
				if string(output[:6]) != "PREFIX" {
					t.Fatal("appender changed prefix")
				}
				got, body, frames := responseHeaderFlight(t, output[6:], 31, effective, endStream)
				if !bytes.Equal(got, block) || len(body) != 0 {
					t.Fatal("appender dropped/duplicated bytes")
				}
				want := max(1, (size+effective-1)/effective)
				if frames != want {
					t.Fatalf("size=%d limit=%d frames=%d want=%d", size, limit, frames, want)
				}
			}
		}
	}
	block := make([]byte, H2MaxFrameSize+1)
	block[0], block[len(block)-1] = 11, 29
	wire := appendH2ResponseHeaderBlock(nil, 33, H2FlagEndStream, block, H2MaxFrameSize+1)
	got, _, frames := responseHeaderFlight(t, wire, 33, H2MaxFrameSize, true)
	if frames != 2 || !bytes.Equal(got, block) {
		t.Fatal("24-bit frame limit lost bytes")
	}
}

func TestH2ResponseHeaderFragmentationAltSvcAndTLS(t *testing.T) {
	_, block := responseHeaderBlockOfSize(t, 16384)
	base := newH2RootFastResponse(bytes.Clone(block), []byte("body"))
	if len(base.framed) == 0 {
		t.Fatal("exact-limit base stopped using preframed path")
	}
	server := New(Config{})
	server.altSvc.Store(newAltSvcHeader(443))
	attached := server.attachAltSvc(base)
	if attached.withAltSvc == nil || len(attached.withAltSvc.headerPayload) <= 16384 || len(attached.withAltSvc.framed) != 0 {
		t.Fatal("Alt-Svc crossing did not use fragmenting fallback")
	}
	wire := appendFastH2RootResponse(nil, attached.forConn(true), 35, 16384)
	got, body, _ := responseHeaderFlight(t, wire, 35, 16384, false)
	decoder := newHpackDecoder(4096)
	fields, err := decoder.Decode(got)
	if err != nil {
		t.Fatal(err)
	}
	altCount := 0
	for _, field := range fields {
		if field[0] == "alt-svc" {
			altCount++
		}
	}
	if altCount != 1 || string(body) != "body" || !bytes.Equal(base.headerPayload, block) {
		t.Fatal("Alt-Svc header/body/base template changed")
	}
	suite := &SupportedSuites[0]
	fixture := bytes.Repeat([]byte{7}, suite.HashLen)
	writer, err := NewTrafficAEAD(suite.HashFn, fixture, suite)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewTrafficAEAD(suite.HashFn, fixture, suite)
	if err != nil {
		t.Fatal(err)
	}
	connection := &epollConn{appWriter: writer}
	records := connection.sealTLSAppData(nil, wire)
	var plain []byte
	for len(records) > 0 {
		if len(records) < 5 {
			t.Fatal("short TLS header")
		}
		size := int(records[3])<<8 | int(records[4])
		if size > len(records)-5 {
			t.Fatal("short TLS record")
		}
		payload, err := reader.Decrypt(bytes.Clone(records[5 : 5+size]))
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) == 0 || payload[len(payload)-1] != 0x17 {
			t.Fatal("wrong inner type")
		}
		plain = append(plain, payload[:len(payload)-1]...)
		records = records[5+size:]
	}
	if !bytes.Equal(plain, wire) {
		t.Fatal("TLS flight altered fragmented response")
	}
	small := newH2RootFastResponse(block[:64], []byte("body"))
	if len(small.tlsInner) != len(small.framed)+1 || small.tlsInner[len(small.tlsInner)-1] != 0x17 || !bytes.Equal(small.tlsInner[:len(small.tlsInner)-1], small.framed) {
		t.Fatal("existing small TLS-inner template changed")
	}
}
