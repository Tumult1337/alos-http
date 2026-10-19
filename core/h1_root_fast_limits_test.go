//go:build linux && amd64

package core

import (
	"bytes"
	"strings"
	"testing"
)

func TestPlainRootFastHeaderLimits(t *testing.T) {
	for _, shape := range []struct {
		name string
		raw  string
	}{
		{"scalar", "GET / HTTP/1.1\r\nHost: a\r\nX: v\r\n\r\n"},
		{"indexed", "GET / HTTP/1.1\r\nHost: a\r\nX: " + strings.Repeat("v", 80) + "\r\n\r\n"},
		{"line", "GET / HTTP/1.1\r\nHost: a\r\nX: " + strings.Repeat("v", 1100) + "\r\n\r\n"},
	} {
		for _, limit := range []struct {
			name     string
			maxBytes int
			maxCount int
			wantOK   bool
		}{
			{"exact_bytes", len(shape.raw) - 2, 2, true},
			{"over_bytes", len(shape.raw) - 3, 2, false},
			{"exact_count", 8192, 2, true},
			{"over_count", 8192, 1, false},
		} {
			t.Run(shape.name+"/"+limit.name, func(t *testing.T) {
				server := &Server{config: Config{MaxHeaderCount: limit.maxCount}}
				server.limits.Store(&Limits{MaxHeaderSize: limit.maxBytes})
				response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				server.plainRootFast.Store(&plainRootFastResponse{getKeepAlive: response})
				raw := []byte(shape.raw)
				if server.plainRootFast.Load() == nil {
					t.Fatal("root fast response is not cached")
				}
				switch shape.name {
				case "scalar":
					if len(raw) > rootScalarScanMaxBytes {
						t.Fatal("fixture exceeds scalar scan size")
					}
				case "indexed":
					block := raw[len(rootPrefixBytes) : len(raw)-2]
					var index h1BlockIndexOut
					if len(raw) <= rootScalarScanMaxBytes || len(block) < h1BlockMinBytes || len(block) > h1BlockMaxBytes || hasAVX2 && !h1BlockIndex(block, &index) {
						t.Fatal("fixture cannot take the indexed scan")
					}
					t.Logf("AVX2 indexed scan enabled=%v", hasAVX2)
				case "line":
					if len(raw)-len(rootPrefixBytes)-2 <= h1BlockMaxBytes {
						t.Fatal("fixture does not exceed indexed scan size")
					}
				}
				_, _, _, _, reject, _, tooLarge, parsed := parseH1RequestHead(raw, &Request{}, limit.maxBytes, limit.maxCount)
				if reject != h1RejectNone || parsed != limit.wantOK || tooLarge == limit.wantOK {
					t.Fatalf("general parser: parsed=%v tooLarge=%v reject=%v; want accepted=%v", parsed, tooLarge, reject, limit.wantOK)
				}
				got, consumed, closeConn, ok := server.matchPlainRootFastRequest(raw, false)
				if ok != limit.wantOK {
					t.Fatalf("fast path accepted=%v; want %v (bytes=%d count=%d)", ok, limit.wantOK, limit.maxBytes, limit.maxCount)
				}
				if limit.wantOK {
					if !bytes.Equal(got, response) || consumed != len(raw) || closeConn {
						t.Fatalf("accepted request: response=%q consumed=%d close=%v", got, consumed, closeConn)
					}
				} else if got != nil || consumed != 0 || closeConn {
					t.Fatalf("limit rejection must fall through: response=%q consumed=%d close=%v", got, consumed, closeConn)
				}
			})
		}
	}
}

func TestPlainRootFastDefaultHeaderCount(t *testing.T) {
	for _, configured := range []int{0, -1} {
		server := &Server{config: Config{MaxHeaderCount: configured}}
		server.limits.Store(&Limits{MaxHeaderSize: 8192})
		response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		server.plainRootFast.Store(&plainRootFastResponse{getKeepAlive: response})
		for _, fields := range []int{128, 129} {
			raw := []byte("GET / HTTP/1.1\r\nHost: a\r\n" + strings.Repeat("X: v\r\n", fields-1) + "\r\n")
			got, consumed, closeConn, ok := server.matchPlainRootFastRequest(raw, false)
			if fields == 128 {
				if !ok || consumed != len(raw) || closeConn || !bytes.Equal(got, response) {
					t.Errorf("configured=%d fields=%d: response=%q consumed=%d close=%v ok=%v", configured, fields, got, consumed, closeConn, ok)
				}
			} else if ok || got != nil || consumed != 0 || closeConn {
				t.Errorf("configured=%d fields=%d: exceeded default count accepted: response=%q consumed=%d close=%v ok=%v", configured, fields, got, consumed, closeConn, ok)
			}
		}
	}
}

func TestPlainRootFastLimitAppliesToFirstPipelinedRequest(t *testing.T) {
	first := "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
	second := "GET / HTTP/1.1\r\nHost: b\r\nX: " + strings.Repeat("v", 1100) + "\r\n\r\n"
	server := &Server{config: Config{MaxHeaderCount: 1}}
	server.limits.Store(&Limits{MaxHeaderSize: len(first) - 2})
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	server.plainRootFast.Store(&plainRootFastResponse{getKeepAlive: response})
	raw := []byte(first + second)
	got, consumed, closeConn, ok := server.matchPlainRootFastRequest(raw, false)
	if !ok || consumed != len(first) || closeConn || !bytes.Equal(got, response) {
		t.Fatalf("first pipelined request: response=%q consumed=%d close=%v ok=%v", got, consumed, closeConn, ok)
	}
	got, consumed, closeConn, ok = server.matchPlainRootFastRequest(raw[consumed:], false)
	if ok || got != nil || consumed != 0 || closeConn {
		t.Fatalf("oversized second request must fall through: response=%q consumed=%d close=%v ok=%v", got, consumed, closeConn, ok)
	}
}
