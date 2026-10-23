//go:build linux && amd64

package core

import (
	"golang.org/x/sys/unix"
)

const (
	h2DirectMaxFrames    = 64
	h2DirectSendHighMark = 1 << 20
)

type h2DirectScratch struct {
	hdrs []byte
	segs [][]byte
	iov  []unix.Iovec
}

func (c *epollConn) h2SendsDirect(stream *H2Stream, budget int) bool {
	if c.tls || c.outArmed || c.lingering || c.fd < 0 || budget < h2DirectSealMinBody {
		return false
	}
	return len(stream.resp.transmittedBodyBytes())-stream.respOff >= h2DirectSealMinBody
}

func (c *epollConn) h2SendWindowed(w *epollWorker, stream *H2Stream, streamID uint32, budget int) bool {
	body := stream.resp.transmittedBodyBytes()
	c.writeBuf = c.h2AppendResponseHead(c.writeBuf, stream, streamID, len(body))
	frameLimit := c.h2.dataFrameLimit()
	start := stream.respOff
	hdrs := w.h2Direct.hdrs[:0]
	for sent := 0; stream.respOff < len(body) && sent < budget && len(hdrs) < h2DirectMaxFrames*h2FrameHeaderLen; {
		n, flags := c.h2DataChunk(stream, len(body), frameLimit)
		if n <= 0 {
			break
		}
		hdrs = appendH2FrameHeader(hdrs, H2FrameData, flags, streamID, n)
		sent += h2FrameHeaderLen + n
		c.h2ConsumeData(stream, n)
	}
	w.h2Direct.hdrs = hdrs
	if len(hdrs) > 0 {
		c.h2SendFrames(w, stream, hdrs, body[start:stream.respOff])
	}
	return stream.respOff >= len(body)
}

func (c *epollConn) h2SendFrames(w *epollWorker, stream *H2Stream, hdrs, data []byte) {
	d := &w.h2Direct
	segs := append(d.segs[:0], c.writeBuf[c.writeSent:])
	for h := 0; h < len(hdrs); h += h2FrameHeaderLen {
		n := h2FramePayloadLen(hdrs[h:])
		segs = append(segs, hdrs[h:h+h2FrameHeaderLen], data[:n])
		data = data[n:]
	}
	sent := d.send(c.fd, segs)
	if sent > 0 {
		w.bytesOut += uint64(sent)
		c.h2.directSent += uint64(sent)
	}
	unsentFrom := 1
	if pending := len(segs[0]); sent < pending {
		c.writeSent += sent
	} else {
		c.writeBuf = c.writeBuf[:0]
		c.writeSent = 0
		unsentFrom = c.h2KeepPartialFrame(segs, sent-pending)
	}
	c.h2UnconsumeFrames(stream, segs[unsentFrom:])
	clear(segs)
	d.segs = segs[:0]
}

func (c *epollConn) h2KeepPartialFrame(segs [][]byte, sent int) int {
	for i := 1; i < len(segs); i += 2 {
		frameLen := len(segs[i]) + len(segs[i+1])
		if sent >= frameLen {
			sent -= frameLen
			continue
		}
		hdrRest := max(len(segs[i])-sent, 0)
		dataSent := max(sent-len(segs[i]), 0)
		c.writeBuf = append(c.writeBuf, segs[i][len(segs[i])-hdrRest:]...)
		c.writeBuf = append(c.writeBuf, segs[i+1][dataSent:]...)
		return i + 2
	}
	return len(segs)
}

func (c *epollConn) h2UnconsumeFrames(stream *H2Stream, frames [][]byte) {
	unsent := 0
	for i := 1; i < len(frames); i += 2 {
		unsent += len(frames[i])
	}
	if unsent == 0 {
		return
	}
	stream.respOff -= unsent
	c.h2.connWindow += int64(unsent)
	stream.Window.Add(int64(unsent))
}

func (d *h2DirectScratch) send(fd int, segs [][]byte) int {
	iov := d.iov[:0]
	for _, seg := range segs {
		iov = appendIovec(iov, seg)
	}
	n, err := socketSendIovecs(fd, iov)
	d.iov = iov[:0]
	if err != nil {
		return 0
	}
	return n
}

func h2FramePayloadLen(hdr []byte) int {
	return int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
}
