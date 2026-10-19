//go:build linux && amd64

package core

import (
	"net"
	"net/http"
	"strconv"
	"testing"
)

const (
	appFix3BenchPath     = "/streamed"
	appFix3BenchBodySize = 1024
)

func appFix3BenchStreamRoute(s *Server) {
	body := make([]byte, appFix3BenchBodySize)
	headers := [][2]string{{"Content-Length", strconv.Itoa(appFix3BenchBodySize)}}
	s.Router.GET(appFix3BenchPath, func(req *Request, resp *Response) {
		sw := resp.EnsureStreamWriter()
		if sw == nil {
			resp.Status(http.StatusInternalServerError).String("no stream")
			return
		}
		resp.SetStreamer(sw)
		if sw.WriteHeader(http.StatusOK, headers, "application/octet-stream") != nil {
			return
		}
		_ = sw.WriteChunk(body)
		_ = sw.Close()
	})
}

func appFix3BenchStart(b *testing.B, withCORS bool) string {
	if raceEnabled {
		b.Skip("the race detector distorts per-request cost")
	}
	_, addr := proxyFixStart(b, Config{}, nil, func(s *Server) {
		appFix3BenchStreamRoute(s)
		if withCORS {
			s.SetCORS(appFix3ExactPolicy)
		}
	})
	return addr
}

func appFix3BenchH1(b *testing.B, withCORS bool) {
	drive := proxyFixKeepAliveDriver(b, appFix3BenchStart(b, withCORS), appFix3BenchPath)
	drive(proxyFixBenchWarmup)
	b.ReportAllocs()
	b.ResetTimer()
	drive(b.N)
}

func BenchmarkAppFix3StreamedH1NoCORS(b *testing.B) { appFix3BenchH1(b, false) }

func BenchmarkAppFix3StreamedH1CORS(b *testing.B) { appFix3BenchH1(b, true) }

func BenchmarkAppFix3StreamedH2NoCORS(b *testing.B) {
	c := newProxyFixBenchH2Client(b, appFix3BenchStart(b, false), appFix3BenchPath)
	for i := 0; i < proxyFixBenchWarmup; i++ {
		c.roundTrip(b)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.roundTrip(b)
	}
}

type appFix3DiscardConn struct{ net.Conn }

func (appFix3DiscardConn) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkAppFix3PlainStreamWriterNoCORS(b *testing.B) {
	s := New(Config{})
	conn := appFix3DiscardConn{}
	body := make([]byte, appFix3BenchBodySize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := s.NewPlainH1StreamWriter(conn)
		_ = w.WriteHeader(http.StatusOK, nil, "application/octet-stream")
		_ = w.WriteChunk(body)
		_ = w.Close()
		releaseStreamWriter(w)
	}
}
