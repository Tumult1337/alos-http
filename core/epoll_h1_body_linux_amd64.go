//go:build linux && amd64

package core

const (
	h1BodyStreamCap  = 256 << 10
	h1BodyReadAhead  = 256 << 10
	h1ContinueHeader = "HTTP/1.1 100 Continue\r\n\r\n"
)

type h1BodyIn struct {
	reader *BodyReader
	left   int64
	chunk  chunkedDecoder
	done   bool
	broken bool
}

func (w *epollWorker) streamsH1Body(chunked, hasContentLength bool, contentLength int) bool {
	if w.streamBodyAbove <= 0 || w.server.config.InlineHandlers || w.server.builtInProxyActive() {
		return false
	}
	return chunked || (hasContentLength && int64(contentLength) > w.streamBodyAbove)
}

func (c *epollConn) startH1BodyStream(w *epollWorker, out []byte, chunked bool, contentLength int) []byte {
	in := &h1BodyIn{left: h1NoContentLength, chunk: chunkedDecoder{captureTrailers: true}}
	if !chunked {
		in.left = int64(contentLength)
	}
	gen := c.generation
	in.reader = newBodyReader(func() {
		w.postTask(func(w *epollWorker) { c.h1BodyAcked(w, in, gen) })
	})
	in.reader.uploadConn, in.reader.uploadGlobal = c.connLimiter, w.server.globalLimiter
	c.h1In = in
	c.req.Body = c.req.Body[:0]
	c.req.bodyStream = in.reader
	if c.req.expect == h1ExpectContinue {
		out = append(out, h1ContinueHeader...)
	}
	c.h1FeedBody(w)
	return out
}

func (c *epollConn) h1Continue(out []byte) []byte {
	if c.req.expect != h1ExpectContinue || c.h1ContinueSent {
		return out
	}
	c.h1ContinueSent = true
	return append(out, h1ContinueHeader...)
}

func (c *epollConn) h1BodyStreaming() bool {
	return c.h1In != nil && !c.h1In.done
}

func (c *epollConn) h1BodyDrainsToEOF() bool {
	return c.peerHup && c.h1BodyStreaming()
}

func (c *epollConn) h1BodyStarved() bool {
	return c.inputEOF && c.h1BodyStreaming() && len(c.h1Unread()) == 0 && (!c.tls || c.readN == 0)
}

func (w *epollWorker) abortStarvedBody(c *epollConn) bool {
	if c.fd < 0 || !c.h1BodyStarved() {
		return false
	}
	w.closeConn(c)
	return true
}

func (c *epollConn) h1BodyWantsInput() bool {
	in := c.h1In
	return in != nil && !in.done && in.reader.buffered() < h1BodyStreamCap
}

func (c *epollConn) h1FeedBody(w *epollWorker) {
	in := c.h1In
	if in == nil || in.done {
		return
	}
	for !in.done {
		data := c.h1Unread()
		room := h1BodyStreamCap - in.reader.buffered()
		if len(data) == 0 || room <= 0 {
			break
		}
		if in.left != h1NoContentLength {
			n := int(min(int64(len(data)), int64(room), in.left))
			in.reader.push(data[:n])
			c.h1Advance(n)
			in.left -= int64(n)
			if in.left == 0 {
				in.end(nil)
			}
			continue
		}
		src := data
		if in.chunk.state == chunkedInData {
			src = data[:min(len(data), room)]
		}
		consumed, chunk, err := in.chunk.next(src)
		if err != nil {
			in.end(err)
			break
		}
		if consumed == 0 {
			break
		}
		if len(chunk) > 0 {
			if w.bodyTooLarge(in.reader.receivedBytes() + int64(len(chunk))) {
				in.end(ErrBodyTooLarge)
				break
			}
			in.reader.push(chunk)
		}
		c.h1Advance(consumed)
		if in.chunk.done() {
			in.end(nil)
		}
	}
	c.h1CompactUnread()
}

func (in *h1BodyIn) end(err error) {
	in.done = true
	in.broken = err != nil
	if err != nil {
		in.reader.finish(err)
		return
	}
	in.reader.finishWithTrailers(in.chunk.trailers)
}

func (c *epollConn) h1CompactUnread() {
	if c.tls {
		c.compactAppConsumed()
		return
	}
	c.compactH1ReadBuffer()
}

func (c *epollConn) h1BodyAcked(w *epollWorker, in *h1BodyIn, gen uint32) {
	in.reader.takeAck()
	if c.generation != gen || c.fd < 0 || c.h1In != in {
		return
	}
	c.h1FeedBody(w)
	if w.abortStarvedBody(c) || !c.h1BodyWantsInput() {
		return
	}
	if c.readPending || c.peerHup && !c.inputEOF {
		w.readable(c, false)
		return
	}
	w.serviceBuffered(c, false, false)
}

func (c *epollConn) h1EndBodyStream() (mustClose bool) {
	in := c.h1In
	if in == nil {
		return false
	}
	c.h1In = nil
	if !in.done {
		in.reader.finish(ErrBodyStreamAborted)
		return true
	}
	return in.broken
}

func (c *epollConn) h1AbortIn() {
	if in := c.h1In; in != nil {
		c.h1In = nil
		if !in.done {
			in.reader.finish(ErrBodyStreamAborted)
		}
	}
}
