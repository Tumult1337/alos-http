//go:build linux && amd64

package core

import (
	"encoding/hex"
	"fmt"
	"sync/atomic"
)

var debugFlag atomic.Bool

// SetDebugFlag enables or disables package-level debug logging used by Dbg
// and DbgHex.
//
// Example: SetDebugFlag(true)
// Example: SetDebugFlag(false)
func SetDebugFlag(on bool) { debugFlag.Store(on) }

// Dbg logs a formatted message at slog.LevelDebug when debug logging
// is enabled via SetDebugFlag; it is a no-op otherwise.
//
// Example: Dbg("accepted %d bytes from %s", n, addr)
func Dbg(format string, v ...interface{}) {
	if debugFlag.Load() {
		logger().Debug(fmt.Sprintf(format, v...))
	}
}

// DbgHex logs a labeled hex dump of data when debug logging is enabled via
// SetDebugFlag. Payloads of 48 bytes or fewer are dumped in full; larger
// payloads log only their length.
//
// Example: DbgHex("client hello", buf)
func DbgHex(label string, data []byte) {
	if !debugFlag.Load() {
		return
	}
	if len(data) <= 48 {
		logger().Debug(label, "bytes", len(data), "hex", hex.EncodeToString(data))
	} else {
		logger().Debug(label, "bytes", len(data))
	}
}
