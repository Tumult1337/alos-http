//go:build linux && amd64

package core

import (
	"bytes"
	"compress/flate"
	"io"
	"slices"
	"strings"
	"sync"
)

const (
	wsExtensionPermessageDeflate      = "permessage-deflate"
	wsDeflateAcceptance               = wsExtensionPermessageDeflate + "; server_no_context_takeover; client_no_context_takeover"
	wsDeflateWindowBits               = "15"
	wsDeflateWindowSize               = 1 << 15
	wsDefaultCompressionLevel         = flate.BestSpeed
	wsCompressMinSize                 = 64
	wsInflateMinGrowth                = 4096
	wsInflateResetOverheadBytes       = 8 << 10
	wsInflateResetBudgetFloor         = 1 << 20
	wsRSV1                       byte = 0x40
	wsRSVMask                    byte = 0x70
)

const (
	wsDeflateServerNoContextTakeover = 1 << iota
	wsDeflateClientNoContextTakeover
	wsDeflateServerMaxWindowBits
	wsDeflateClientMaxWindowBits
)

var (
	wsSyncFlushMarker = []byte{0x00, 0x00, 0xff, 0xff}
	wsInflateTail     = []byte{0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff}
)

var wsInflaterPool = sync.Pool{New: func() any { return flate.NewReader(bytes.NewReader(nil)) }}

func wsClientOffersDeflate(headers [][2]string) bool {
	for i := range headers {
		if !EqualFoldASCII(headers[i][0], "sec-websocket-extensions") {
			continue
		}
		for offers := headers[i][1]; offers != ""; {
			var offer string
			offer, offers, _ = strings.Cut(offers, ",")
			if wsDeflateOfferAcceptable(offer) {
				return true
			}
		}
	}
	return false
}

func wsDeflateOfferAcceptable(offer string) bool {
	name, params, hasParams := strings.Cut(offer, ";")
	if !EqualFoldASCII(trimASCIISpace(name), wsExtensionPermessageDeflate) {
		return false
	}
	seen := 0
	for hasParams {
		var param string
		param, params, hasParams = strings.Cut(params, ";")
		key, value, hasValue := strings.Cut(param, "=")
		key, value = trimASCIISpace(key), wsUnquoteParam(trimASCIISpace(value))
		var bit int
		switch key {
		case "server_no_context_takeover":
			bit = wsDeflateServerNoContextTakeover
			if hasValue {
				return false
			}
		case "client_no_context_takeover":
			bit = wsDeflateClientNoContextTakeover
			if hasValue {
				return false
			}
		case "server_max_window_bits":
			bit = wsDeflateServerMaxWindowBits
			if value != wsDeflateWindowBits {
				return false
			}
		case "client_max_window_bits":
			bit = wsDeflateClientMaxWindowBits
			if hasValue && !wsValidWindowBits(value) {
				return false
			}
		default:
			return false
		}
		if seen&bit != 0 {
			return false
		}
		seen |= bit
	}
	return true
}

func wsUnquoteParam(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

func wsValidWindowBits(v string) bool {
	switch len(v) {
	case 1:
		return v[0] == '8' || v[0] == '9'
	case 2:
		return v[0] == '1' && v[1] >= '0' && v[1] <= '5'
	}
	return false
}

func wsSelectSubprotocol(headers [][2]string, supported []string) string {
	for _, want := range supported {
		for i := range headers {
			if !EqualFoldASCII(headers[i][0], "sec-websocket-protocol") {
				continue
			}
			for offered := headers[i][1]; offered != ""; {
				var p string
				p, offered, _ = strings.Cut(offered, ",")
				if trimASCIISpace(p) == want {
					return want
				}
			}
		}
	}
	return ""
}

func wsNormalizeCompressionLevel(level int) int {
	if level < flate.BestSpeed || level > flate.BestCompression {
		return wsDefaultCompressionLevel
	}
	return level
}

type wsDeflater struct {
	fw  *flate.Writer
	out []byte
}

func (d *wsDeflater) Write(p []byte) (int, error) {
	d.out = append(d.out, p...)
	return len(p), nil
}

var wsDeflaterPool [flate.BestCompression + 1]sync.Pool

func init() {
	for level := flate.BestSpeed; level <= flate.BestCompression; level++ {
		wsDeflaterPool[level].New = func() any {
			d := &wsDeflater{}
			d.fw, _ = flate.NewWriter(d, level)
			return d
		}
	}
}

func wsDeflate(dst, payload []byte, level int) []byte {
	d := wsDeflaterPool[level].Get().(*wsDeflater)
	d.out = dst
	d.fw.Reset(d)
	_, _ = d.fw.Write(payload)
	_ = d.fw.Flush()
	dst = d.out
	d.out = nil
	wsDeflaterPool[level].Put(d)
	return bytes.TrimSuffix(dst, wsSyncFlushMarker)
}

func wsInflate(compressed []byte, limit int64) ([]byte, uint16) {
	src := bytes.NewReader(append(compressed, wsInflateTail...))
	fr := wsInflaterPool.Get().(io.ReadCloser)
	defer wsInflaterPool.Put(fr)
	resetter := fr.(flate.Resetter)
	if err := resetter.Reset(src, nil); err != nil {
		return nil, wsStatusInvalidPayload
	}
	var out []byte
	resetWork, resetBudget := int64(0), max(limit, wsInflateResetBudgetFloor)
	for {
		if len(out) == cap(out) {
			out = slices.Grow(out, int(min(int64(max(cap(out), wsInflateMinGrowth)), limit+1-int64(len(out)))))
		}
		room := out[len(out):cap(out)]
		if headroom := limit + 1 - int64(len(out)); int64(len(room)) > headroom {
			room = room[:headroom]
		}
		n, err := fr.Read(room)
		out = out[:len(out)+n]
		if int64(len(out)) > limit {
			return nil, wsStatusMessageTooBig
		}
		switch {
		case err == nil:
		case err == io.EOF && src.Len() == 0:
			return out, 0
		case err == io.EOF:
			dict := out[max(0, len(out)-wsDeflateWindowSize):]
			resetWork += int64(len(dict)) + wsInflateResetOverheadBytes
			if resetWork > resetBudget {
				return nil, wsStatusMessageTooBig
			}
			if err := resetter.Reset(src, dict); err != nil {
				return nil, wsStatusInvalidPayload
			}
		default:
			return nil, wsStatusInvalidPayload
		}
	}
}
