//go:build linux && amd64

package core

import (
	"io"
	"net"
	"testing"
	"time"
)

const (
	fuzzWSMaxMessage = 1 << 16
	fuzzWSMaxReads   = 64
	fuzzWSTimeout    = 150 * time.Millisecond
)

func FuzzWebSocketFrame(f *testing.F) {
	f.Add([]byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58})
	f.Add([]byte{0x01, 0x83, 0, 0, 0, 0, 'a', 'b', 'c', 0x80, 0x82, 0, 0, 0, 0, 'd', 'e'})
	f.Add([]byte{0x89, 0x80, 0, 0, 0, 0})
	f.Add([]byte{0x88, 0x82, 0, 0, 0, 0, 0x03, 0xe8})
	f.Add([]byte{0x82, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4})
	f.Add([]byte{0x81, 0x84, 0, 0, 0, 0, 0xff, 0xfe, 0xfd, 0xfc})
	f.Fuzz(func(t *testing.T, data []byte) {
		serverSide, clientSide := net.Pipe()
		defer serverSide.Close()
		defer clientSide.Close()
		go func() {
			_, _ = clientSide.Write(data)
			_ = clientSide.Close()
		}()
		go func() { _, _ = io.Copy(io.Discard, clientSide) }()
		ws := &WSConn{conn: serverSide, readTimeout: fuzzWSTimeout, writeTimeout: fuzzWSTimeout, MaxMessageSize: fuzzWSMaxMessage}
		_ = serverSide.SetReadDeadline(wallDeadline(fuzzWSTimeout))
		for range fuzzWSMaxReads {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if len(msg) > fuzzWSMaxMessage {
				t.Fatalf("message of %d bytes exceeds MaxMessageSize %d", len(msg), fuzzWSMaxMessage)
			}
		}
	})
}
