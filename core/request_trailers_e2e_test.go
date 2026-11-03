//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

const trailerStreamThreshold = 1

func trailerEcho(req *Request, resp *Response) {
	body := req.Body
	if bs := req.BodyStream(); bs != nil {
		var err error
		body, err = io.ReadAll(bs)
		if err != nil {
			resp.Status(500).String(err.Error())
			return
		}
	}
	var b strings.Builder
	b.Write(body)
	for _, tr := range req.Trailers() {
		b.WriteString("|" + strings.ToLower(tr[0]) + "=" + tr[1])
	}
	resp.Status(200).String(b.String())
}

func startTrailerServer(t *testing.T, plainH2 bool, streamed bool) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		Config: func(cfg *Config) {
			cfg.PlainHTTP = plainH2
			if streamed {
				cfg.StreamBodyAbove = trailerStreamThreshold
			}
		},
		Routes: func(r *Router) {
			r.POST("/t", trailerEcho)
			r.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
		},
	})
}

func trailerModes() []struct {
	name     string
	streamed bool
} {
	return []struct {
		name     string
		streamed bool
	}{{"buffered", false}, {"streamed", true}}
}

func TestTrailersH1Chunked(t *testing.T) {
	for _, mode := range trailerModes() {
		t.Run(mode.name, func(t *testing.T) {
			ts := startTrailerServer(t, false, mode.streamed)
			c := ts.dial(t)
			br := bufio.NewReader(c)
			writeAll(t, c, "POST /t HTTP/1.1\r\nHost: "+ts.domain+"\r\nTransfer-Encoding: chunked\r\n\r\n"+
				"5\r\nhello\r\n0\r\nX-Checksum: 1\r\nContent-Length: 99\r\nHost: evil\r\nX-Two:  b \r\n\r\n")
			readFinal(t, br, 200, "hello|x-checksum=1|x-two=b")
			writeAll(t, c, "POST /t HTTP/1.1\r\nHost: "+ts.domain+"\r\nContent-Length: 2\r\n\r\nhi")
			readFinal(t, br, 200, "hi")
		})
	}
}

func TestTrailersH1MalformedIs400(t *testing.T) {
	for _, mode := range trailerModes() {
		t.Run(mode.name, func(t *testing.T) {
			ts := startTrailerServer(t, false, mode.streamed)
			c := ts.dial(t)
			br := bufio.NewReader(c)
			writeAll(t, c, "POST /t HTTP/1.1\r\nHost: "+ts.domain+"\r\nTransfer-Encoding: chunked\r\n\r\n"+
				"5\r\nhello\r\n0\r\nbad trailer\r\n\r\n")
			resp, _ := readH1Response(t, br, "POST")
			if mode.streamed {
				if resp.StatusCode != 500 {
					t.Fatalf("streamed status %d, want 500 from the aborted body read", resp.StatusCode)
				}
				return
			}
			if resp.StatusCode != 400 {
				t.Fatalf("status %d, want 400", resp.StatusCode)
			}
		})
	}
}

func h2PostHeaders(path string) []byte {
	block := []byte{0x83, 0x86, 0x04, byte(len(path))}
	block = append(block, path...)
	block = append(block, 0x01, byte(len(cancelH2Authority)))
	return append(block, cancelH2Authority...)
}

func h2LiteralField(name, value string) []byte {
	block := []byte{0x00, byte(len(name))}
	block = append(block, name...)
	block = append(block, byte(len(value)))
	return append(block, value...)
}

func h2ReadBody(t *testing.T, rc *h2RawConn, streamID uint32) (int, string) {
	t.Helper()
	status := 0
	var body []byte
	for {
		f := rc.read()
		if f.typ == H2FrameGoAway {
			t.Fatalf("GOAWAY while waiting for stream %d", streamID)
		}
		if f.streamID != streamID {
			continue
		}
		switch f.typ {
		case H2FrameRSTStream:
			t.Fatalf("stream %d reset", streamID)
		case H2FrameHeaders:
			status = f.status(t)
		case H2FrameData:
			body = append(body, f.payload...)
		}
		if f.flags&H2FlagEndStream != 0 {
			return status, string(body)
		}
	}
}

func h2ExpectReset(t *testing.T, rc *h2RawConn, streamID uint32) {
	t.Helper()
	f, err := rc.awaitStreamOutcome(streamID)
	if err != nil {
		t.Fatalf("stream %d: %v", streamID, err)
	}
	if f.typ != H2FrameRSTStream {
		t.Fatalf("stream %d got frame type %d, want RST_STREAM", streamID, f.typ)
	}
}

func TestTrailersH2(t *testing.T) {
	for _, mode := range trailerModes() {
		t.Run(mode.name, func(t *testing.T) {
			ts := startTrailerServer(t, true, mode.streamed)
			rc := dialCancelH2(t, ts)
			rc.write(H2FrameHeaders, H2FlagEndHeaders, 1, h2PostHeaders("/t"))
			rc.write(H2FrameData, 0, 1, []byte("abc"))
			trailer := append(h2LiteralField("x-checksum", "1"), h2LiteralField("content-length", "7")...)
			rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, trailer)
			status, body := h2ReadBody(t, rc, 1)
			if status != 200 || body != "abc|x-checksum=1" {
				t.Fatalf("status %d body %q", status, body)
			}
			rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, cancelH2Headers("/ok"))
			if status, body := h2ReadBody(t, rc, 3); status != 200 || body != "ok" {
				t.Fatalf("second request on the connection: %d %q", status, body)
			}
		})
	}
}

func TestTrailersH2Malformed(t *testing.T) {
	cases := []struct {
		name  string
		flags byte
		block []byte
	}{
		{"pseudo header", H2FlagEndHeaders | H2FlagEndStream, append(h2LiteralField("x-a", "1"), 0x04, 0x02, '/', 'x')},
		{"no end stream", H2FlagEndHeaders, h2LiteralField("x-a", "1")},
	}
	for _, mode := range trailerModes() {
		for _, tc := range cases {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				ts := startTrailerServer(t, true, mode.streamed)
				rc := dialCancelH2(t, ts)
				rc.write(H2FrameHeaders, H2FlagEndHeaders, 1, h2PostHeaders("/t"))
				rc.write(H2FrameData, 0, 1, []byte("abc"))
				rc.write(H2FrameHeaders, tc.flags, 1, tc.block)
				h2ExpectReset(t, rc, 1)
				rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, cancelH2Headers("/ok"))
				if status, body := h2ReadBody(t, rc, 3); status != 200 || body != "ok" {
					t.Fatalf("connection unusable after the reset: %d %q", status, body)
				}
			})
		}
	}
}
