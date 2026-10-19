//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	proxyFixPoll       = 15 * time.Millisecond
	proxyFixCeiling    = 3 * time.Second
	proxyFixIOTimeout  = 2 * time.Second
	proxyFixStep       = 150 * time.Millisecond
	proxyFixShutdownTO = 2 * time.Second
)

const proxyFixH2FrameHeaderLen = 9

const proxyFixDomain = "origin.test"

func proxyFixFreeAddr(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func proxyFixStart(t testing.TB, cfg Config, domains []DomainConfig, tune func(*Server)) (*Server, string) {
	t.Helper()
	addr := proxyFixFreeAddr(t)
	cfg.Addr = addr
	cfg.PlainHTTP = true
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = "-"
	}
	if cfg.MaxConnsPerIP == 0 {
		cfg.MaxConnsPerIP = -1
	}
	if cfg.Listeners == 0 {
		cfg.Listeners = 1
	}
	srv := New(cfg)
	for _, d := range domains {
		srv.AddProxyDomain(d)
	}
	if tune != nil {
		tune(srv)
	}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), proxyFixShutdownTO)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	proxyFixEventually(t, "server accepts connections", func() bool {
		c, err := net.DialTimeout("tcp", addr, proxyFixStep)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
	proxyFixEventually(t, "probe connection released", func() bool { return srv.activeConns.Load() == 0 })
	return srv, addr
}

func proxyFixWaitFor(cond func() bool) bool {
	deadline := turbo.Deadline(proxyFixCeiling)
	for turbo.Until(deadline) > 0 {
		if cond() {
			return true
		}
		time.Sleep(proxyFixPoll)
	}
	return cond()
}

func proxyFixEventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	if !proxyFixWaitFor(cond) {
		t.Fatalf("timed out waiting for: %s", what)
	}
}

func proxyFixDial(t testing.TB, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, proxyFixIOTimeout)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	_ = c.SetDeadline(wallDeadline(proxyFixIOTimeout))
	return c
}

func proxyFixRoundTrip(t *testing.T, addr, raw string) (*http.Response, string) {
	t.Helper()
	c := proxyFixDial(t, addr)
	defer c.Close()
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return proxyFixReadResponse(t, bufio.NewReader(c))
}

func proxyFixReadResponse(t *testing.T, br *bufio.Reader) (*http.Response, string) {
	t.Helper()
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

func proxyFixGet(host, target string, extra ...string) string {
	var b strings.Builder
	b.WriteString("GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\n")
	for _, h := range extra {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("Connection: close\r\n\r\n")
	return b.String()
}

func proxyFixAppendH2Frame(dst []byte, typ, flags byte, streamID uint32, payload []byte) []byte {
	var hdr [proxyFixH2FrameHeaderLen]byte
	hdr[0] = byte(len(payload) >> 16)
	hdr[1] = byte(len(payload) >> 8)
	hdr[2] = byte(len(payload))
	hdr[3] = typ
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:], streamID&0x7fffffff)
	dst = append(dst, hdr[:]...)
	return append(dst, payload...)
}

func proxyFixAppendHPACKLiteral(dst []byte, staticIndex byte, value string) []byte {
	dst = append(dst, staticIndex)
	dst = append(dst, byte(len(value)))
	return append(dst, value...)
}

const (
	proxyFixHpackStaticAuthority  = 1
	proxyFixHpackStaticMethod     = 2
	proxyFixHpackStaticPath       = 4
	proxyFixHpackStaticSchemeHTTP = 0x86
)

func proxyFixH2Request(streamID uint32, method, authority, path string) []byte {
	block := proxyFixAppendHPACKLiteral(nil, proxyFixHpackStaticMethod, method)
	block = append(block, proxyFixHpackStaticSchemeHTTP)
	block = proxyFixAppendHPACKLiteral(block, proxyFixHpackStaticPath, path)
	block = proxyFixAppendHPACKLiteral(block, proxyFixHpackStaticAuthority, authority)
	return proxyFixAppendH2Frame(nil, h2FrameHeaders, h2FlagEndStream|h2FlagEndHeaders, streamID, block)
}

type proxyFixH2Conn struct {
	net.Conn
	br  *bufio.Reader
	dec *HpackDecoder
}

type proxyFixH2Frame struct {
	typ      byte
	flags    byte
	streamID uint32
	payload  []byte
}

func proxyFixH2cDial(t *testing.T, addr string) *proxyFixH2Conn {
	t.Helper()
	c := proxyFixDial(t, addr)
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	var settings [6]byte
	binary.BigEndian.PutUint16(settings[:2], h2SettingsInitialWindowSize)
	binary.BigEndian.PutUint32(settings[2:], proxyFixH2Window)
	preface = proxyFixAppendH2Frame(preface, h2FrameSettings, 0, 0, settings[:])
	var bump [4]byte
	binary.BigEndian.PutUint32(bump[:], proxyFixH2Window-h2DefaultWindow)
	preface = proxyFixAppendH2Frame(preface, h2FrameWindowUpdate, 0, 0, bump[:])
	if _, err := c.Write(preface); err != nil {
		t.Fatalf("write h2 preface: %v", err)
	}
	return &proxyFixH2Conn{Conn: c, br: bufio.NewReader(c), dec: NewHpackDecoder()}
}

const proxyFixH2Window = 64 << 20

type proxyFixH2Response struct {
	status string
	body   []byte
	reset  bool
}

func (c *proxyFixH2Conn) collect(t *testing.T, streams int) map[uint32]*proxyFixH2Response {
	t.Helper()
	out := map[uint32]*proxyFixH2Response{}
	ended := 0
	for ended < streams {
		f := c.readFrame(t)
		if f.streamID == 0 {
			if f.typ == h2FrameGoAway {
				t.Fatalf("GOAWAY after %d of %d streams ended", ended, streams)
			}
			continue
		}
		r := out[f.streamID]
		if r == nil {
			r = &proxyFixH2Response{}
			out[f.streamID] = r
		}
		switch f.typ {
		case h2FrameHeaders:
			fields, err := c.dec.Decode(f.payload)
			if err != nil {
				t.Fatalf("decode response headers on stream %d: %v", f.streamID, err)
			}
			for _, kv := range fields {
				if kv[0] == ":status" {
					r.status = kv[1]
				}
			}
		case h2FrameData:
			r.body = append(r.body, f.payload...)
		case h2FrameRSTStream:
			r.reset = true
			ended++
			continue
		default:
			continue
		}
		if f.flags&h2FlagEndStream != 0 {
			ended++
		}
	}
	return out
}

func (c *proxyFixH2Conn) readFrame(t *testing.T) proxyFixH2Frame {
	t.Helper()
	var hdr [proxyFixH2FrameHeaderLen]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		t.Fatalf("read h2 frame header: %v", err)
	}
	n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		t.Fatalf("read h2 frame payload: %v", err)
	}
	f := proxyFixH2Frame{typ: hdr[3], flags: hdr[4], streamID: binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff, payload: payload}
	if f.typ == h2FrameSettings && f.flags&h2FlagAck == 0 {
		if _, err := c.Write(proxyFixAppendH2Frame(nil, h2FrameSettings, h2FlagAck, 0, nil)); err != nil {
			t.Fatalf("ack settings: %v", err)
		}
	}
	return f
}

const proxyFixPingPayload = "fixping!"

func (c *proxyFixH2Conn) framesUntilPingAck(t *testing.T) []proxyFixH2Frame {
	t.Helper()
	if _, err := c.Write(proxyFixAppendH2Frame(nil, h2FramePing, 0, 0, []byte(proxyFixPingPayload))); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	var frames []proxyFixH2Frame
	for {
		f := c.readFrame(t)
		if f.typ == h2FramePing && f.flags&h2FlagAck != 0 && string(f.payload) == proxyFixPingPayload {
			return frames
		}
		frames = append(frames, f)
	}
}

func (c *proxyFixH2Conn) readBody(t *testing.T, streamID uint32) string {
	t.Helper()
	var body []byte
	for {
		f := c.readFrame(t)
		switch {
		case f.typ == h2FrameGoAway:
			t.Fatalf("server sent GOAWAY while waiting for stream %d", streamID)
		case f.streamID != streamID:
		case f.typ == h2FrameData:
			body = append(body, f.payload...)
			if f.flags&h2FlagEndStream != 0 {
				return string(body)
			}
		case f.typ == h2FrameHeaders && f.flags&h2FlagEndStream != 0:
			return string(body)
		}
	}
}

const proxyFixChunkSize = 16 << 10

func proxyFixBodyByte(i int) byte { return byte('a' + i%26) }

func proxyFixPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = proxyFixBodyByte(i)
	}
	return b
}

func proxyFixShapedOrigin(t *testing.T, release chan struct{}) *inloopOrigin {
	t.Helper()
	return newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		kind, sizeText, _ := strings.Cut(strings.TrimPrefix(req.URL.Path, "/"), "/")
		size, _ := strconv.Atoi(sizeText)
		switch kind {
		case "hold":
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
			<-release
			_ = conn.Close()
		case "cl":
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
			_, _ = conn.Write(proxyFixPattern(size))
		case "chunked":
			fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
			body := proxyFixPattern(size)
			for len(body) > 0 {
				n := min(len(body), proxyFixChunkSize)
				fmt.Fprintf(conn, "%x\r\n", n)
				_, _ = conn.Write(body[:n])
				_, _ = conn.Write([]byte("\r\n"))
				body = body[n:]
			}
			fmt.Fprint(conn, "0\r\n\r\n")
		}
	})
}
