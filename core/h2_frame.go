//go:build linux && amd64

package core

import "slices"

// H2ClientPreface is the 24-byte connection preface an HTTP/2 client sends
// before the first frame.
var H2ClientPreface = [24]byte{'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0', '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n'}

// H2Frame represents a parsed HTTP/2 frame header and payload.
type H2Frame struct {
	Length   uint32
	Type     byte
	Flags    byte
	StreamID uint32
	Payload  []byte
}

func releaseH2Frame(f *H2Frame) {
	f.Payload = f.Payload[:0]
	H2FramePool.Put(f)
}

// H2ReadFrame parses an HTTP/2 frame from the bytes returned by reader,
// returning a pooled *H2Frame, or an error if the data is too short or the
// declared frame length exceeds it.
func H2ReadFrame(reader func() ([]byte, error)) (*H2Frame, error) {
	data, err := reader()
	if err != nil {
		return nil, err
	}
	if len(data) < 9 {
		return nil, ErrH2FrameTooLarge
	}
	f := H2FramePool.Get().(*H2Frame)
	f.Length = uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	f.Type = data[3]
	f.Flags = data[4]
	f.StreamID = (uint32(data[5])<<24 | uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])) & 0x7fffffff
	if 9+int(f.Length) > len(data) {
		releaseH2Frame(f)
		return nil, ErrH2FrameTooLarge
	}
	f.Payload = data[9 : 9+f.Length]
	return f, nil
}

const h2SettingEntryLen = 6

// H2WriteFrame appends an HTTP/2 frame with the given type, flags, stream ID,
// and payload to dst, reusing dst's capacity when it is large enough, and
// returns the resulting slice.
func H2WriteFrame(dst []byte, typ, flags byte, streamID uint32, payload []byte) []byte {
	return appendH2Frame(dst, typ, flags, streamID, payload)
}

// H2WriteSettings appends an HTTP/2 SETTINGS frame carrying the given
// identifier/value pairs to dst and returns the resulting slice.
func H2WriteSettings(dst []byte, settings [][2]uint32) []byte {
	payloadLen := len(settings) * h2SettingEntryLen
	off := len(dst)
	dst = appendH2Frame(slices.Grow(dst, 9+payloadLen), H2FrameSettings, 0, 0, nil)
	for _, s := range settings {
		v16 := uint16(s[0])
		v32 := s[1]
		dst = append(dst, byte(v16>>8), byte(v16), byte(v32>>24), byte(v32>>16), byte(v32>>8), byte(v32))
	}
	putH2FrameLength(dst[off:], payloadLen)
	return dst
}

// H2WriteSettingsAck appends an HTTP/2 SETTINGS frame with the ACK flag set
// to dst and returns the resulting slice.
func H2WriteSettingsAck(dst []byte) []byte {
	return appendH2SettingsAckFrame(dst)
}

// H2WriteWindowUpdate appends an HTTP/2 WINDOW_UPDATE frame for streamID
// with the given increment to dst and returns the resulting slice.
func H2WriteWindowUpdate(dst []byte, streamID, increment uint32) []byte {
	return appendH2WindowUpdateFrame(dst, streamID, increment)
}

// H2WriteGoAway appends an HTTP/2 GOAWAY frame reporting lastStream and
// errCode to dst and returns the resulting slice.
func H2WriteGoAway(dst []byte, lastStream, errCode uint32) []byte {
	return appendH2GoAwayFrame(dst, lastStream, errCode)
}

// H2WritePing appends an HTTP/2 PING frame carrying data to dst, setting the
// ACK flag when ack is true, and returns the resulting slice.
func H2WritePing(dst []byte, ack bool, data [8]byte) []byte {
	return appendH2PingFrame(dst, ack, data)
}

// H2WriteRSTStream appends an HTTP/2 RST_STREAM frame for streamID with
// errCode to dst and returns the resulting slice.
func H2WriteRSTStream(dst []byte, streamID, errCode uint32) []byte {
	return appendH2RSTStreamFrame(dst, streamID, errCode)
}

// H2WriteContinuation appends an HTTP/2 CONTINUATION frame carrying
// headerBlock to dst and returns the resulting slice.
func H2WriteContinuation(dst []byte, flags byte, streamID uint32, headerBlock []byte) []byte {
	return H2WriteFrame(dst, H2FrameContinuation, flags, streamID, headerBlock)
}
