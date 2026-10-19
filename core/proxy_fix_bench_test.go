//go:build linux && amd64

package core

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

const (
	proxyFixBenchBodySize = 1024
	proxyFixBenchWarmup   = 300
	proxyFixBenchReadTO   = 10 * time.Second
)

func proxyFixKeepAliveDriver(tb testing.TB, addr, path string) func(n int) {
	tb.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	return proxyFixKeepAliveConnDriver(tb, conn, proxyFixDomain, path)
}

func proxyFixKeepAliveConnDriver(tb testing.TB, conn net.Conn, host, path string) func(n int) {
	tb.Helper()
	tb.Cleanup(func() { _ = conn.Close() })
	req := []byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	buf := make([]byte, 2<<20)
	if _, err := conn.Write(req); err != nil {
		tb.Fatalf("probe write: %v", err)
	}
	total, replyLen := 0, 0
	for replyLen == 0 {
		_ = conn.SetReadDeadline(wallDeadline(proxyFixBenchReadTO))
		nr, rerr := conn.Read(buf[total:])
		total += nr
		if rerr != nil {
			tb.Fatalf("probe read: %v", rerr)
		}
		if idx := bytes.Index(buf[:total], dpCRLFCRLF); idx >= 0 {
			if want := idx + 4 + dpDeclaredBodyLen(buf[:idx]); total >= want {
				replyLen = want
			}
		}
	}
	return func(n int) {
		for i := 0; i < n; i++ {
			if _, werr := conn.Write(req); werr != nil {
				tb.Fatalf("write %d: %v", i, werr)
			}
			for got := 0; got < replyLen; {
				_ = conn.SetReadDeadline(wallDeadline(proxyFixBenchReadTO))
				nr, rerr := conn.Read(buf[got:replyLen])
				got += nr
				if rerr != nil {
					tb.Fatalf("read %d: %v", i, rerr)
				}
			}
		}
	}
}

func proxyFixBenchRoundTrip(b *testing.B, path string, tune func(*Server)) {
	if raceEnabled {
		b.Skip("the race detector distorts per-request cost")
	}
	domains := []DomainConfig{{Domain: proxyFixDomain, Backends: []BackendConfig{{Addr: zeroAllocOrigin(b, proxyFixBenchBodySize)}}}}
	_, addr := proxyFixStart(b, Config{}, domains, tune)
	drive := proxyFixKeepAliveDriver(b, addr, path)
	drive(proxyFixBenchWarmup)
	b.ReportAllocs()
	b.ResetTimer()
	drive(b.N)
}

func BenchmarkProxyFixInLoopRoundTrip(b *testing.B) {
	proxyFixBenchRoundTrip(b, "/bench?q=1", nil)
}

func BenchmarkProxyFixInLoopHooked(b *testing.B) {
	proxyFixBenchRoundTrip(b, "/bench?q=1", func(s *Server) {
		pe := s.proxy.Load()
		pe.OnRequest = func(pr *ProxyRequest) bool { return true }
		pe.OnResponse = func(pr *ProxyResponse) {}
	})
}

func BenchmarkProxyFixInLoopCacheHit(b *testing.B) {
	proxyFixBenchRoundTrip(b, "/bench?q=1", func(s *Server) {
		s.SetProxyCache(ProxyCacheConfig{
			Rules:         []CacheRule{{PathPrefix: "/", MaxAge: time.Minute}},
			MaxEntrySize:  1 << 20,
			DefaultMaxAge: time.Minute,
		})
	})
}

const proxyFixBenchH2ConnWindow = 1 << 30

type proxyFixBenchH2Client struct {
	conn    net.Conn
	request []byte
	hdr     [proxyFixH2FrameHeaderLen]byte
	payload []byte
	ack     []byte
	next    uint32
}

func newProxyFixBenchH2Client(tb testing.TB, addr, path string) *proxyFixBenchH2Client {
	tb.Helper()
	conn := proxyFixDial(tb, addr)
	_ = conn.SetDeadline(time.Time{})
	tb.Cleanup(func() { _ = conn.Close() })
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	preface = proxyFixAppendH2Frame(preface, h2FrameSettings, 0, 0, nil)
	var bump [4]byte
	binary.BigEndian.PutUint32(bump[:], proxyFixBenchH2ConnWindow)
	preface = proxyFixAppendH2Frame(preface, h2FrameWindowUpdate, 0, 0, bump[:])
	if _, err := conn.Write(preface); err != nil {
		tb.Fatalf("write preface: %v", err)
	}
	return &proxyFixBenchH2Client{
		conn:    conn,
		request: proxyFixH2Request(1, "GET", proxyFixDomain, path),
		payload: make([]byte, 1<<20),
		ack:     proxyFixAppendH2Frame(nil, h2FrameSettings, h2FlagAck, 0, nil),
		next:    1,
	}
}

func (c *proxyFixBenchH2Client) roundTrip(tb testing.TB) {
	sid := c.next
	c.next += 2
	binary.BigEndian.PutUint32(c.request[5:9], sid)
	if _, err := c.conn.Write(c.request); err != nil {
		tb.Fatalf("write stream %d: %v", sid, err)
	}
	for {
		if _, err := io.ReadFull(c.conn, c.hdr[:]); err != nil {
			tb.Fatalf("read frame header: %v", err)
		}
		n := int(c.hdr[0])<<16 | int(c.hdr[1])<<8 | int(c.hdr[2])
		if _, err := io.ReadFull(c.conn, c.payload[:n]); err != nil {
			tb.Fatalf("read frame payload: %v", err)
		}
		typ, flags := c.hdr[3], c.hdr[4]
		got := binary.BigEndian.Uint32(c.hdr[5:]) & 0x7fffffff
		if typ == h2FrameSettings && flags&h2FlagAck == 0 {
			if _, err := c.conn.Write(c.ack); err != nil {
				tb.Fatalf("ack settings: %v", err)
			}
			continue
		}
		if got == sid && (typ == h2FrameData || typ == h2FrameHeaders) && flags&h2FlagEndStream != 0 {
			return
		}
	}
}

func BenchmarkProxyFixInLoopH2RoundTrip(b *testing.B) {
	if raceEnabled {
		b.Skip("the race detector distorts per-request cost")
	}
	domains := []DomainConfig{{Domain: proxyFixDomain, Backends: []BackendConfig{{Addr: zeroAllocOrigin(b, proxyFixBenchBodySize)}}}}
	_, addr := proxyFixStart(b, Config{}, domains, nil)
	c := newProxyFixBenchH2Client(b, addr, "/bench?q=1")
	for i := 0; i < proxyFixBenchWarmup; i++ {
		c.roundTrip(b)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.roundTrip(b)
	}
}
