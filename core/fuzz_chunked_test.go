//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

type chunkedStreamResult struct {
	body     []byte
	consumed int
	done     bool
	err      error
}

func streamDecodeChunked(src []byte, step int) chunkedStreamResult {
	var (
		d   chunkedDecoder
		res chunkedStreamResult
	)
	pos, window := 0, step
	for !d.done() {
		end := min(len(src), pos+window)
		n, data, err := d.next(src[pos:end])
		if err != nil {
			res.err, res.consumed = err, pos
			return res
		}
		res.body = append(res.body, data...)
		if n == 0 {
			if end == len(src) {
				res.consumed = pos
				return res
			}
			window += step
			continue
		}
		pos += n
		window = step
	}
	res.consumed, res.done = pos, true
	return res
}

func epollChunkedPipeline(src []byte) (body []byte, bodyEnd int, complete bool, malformed bool) {
	end, status, _ := asyncChunkedComplete(src, 0)
	switch status {
	case -1:
		return nil, 0, false, true
	case 0:
		return nil, 0, false, false
	}
	decoded, _, ok := decodeChunkedInto(nil, src[:end])
	if !ok {
		return nil, end, false, true
	}
	return decoded, end, true, false
}

func FuzzChunkedDecoder(f *testing.F) {
	for _, s := range []string{
		"5\r\nhello\r\n0\r\n\r\n",
		"5\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\n",
		"5;ext=1\r\nhello\r\n0\r\n\r\n",
		"5\r\nhelloXX\r\n0\r\n\r\n",
		"5\nhello\n0\n\n",
		"ffffffffffffffff\r\n",
		"0\r\n\r\n",
		"3\r\nabc\r\n0\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		ref := streamDecodeChunked(src, len(src)+1)
		for _, step := range []int{1, 3, 7} {
			got := streamDecodeChunked(src, step)
			if got.done != ref.done || (got.err == nil) != (ref.err == nil) || !bytes.Equal(got.body, ref.body) || got.consumed != ref.consumed {
				t.Fatalf("step %d disagrees: done=%v/%v err=%v/%v consumed=%d/%d", step, got.done, ref.done, got.err, ref.err, got.consumed, ref.consumed)
			}
		}
		body, bodyEnd, complete, malformed := epollChunkedPipeline(src)
		switch {
		case ref.err != nil && complete:
			t.Fatalf("epoll pipeline accepted %q that the streaming decoder rejects (%v)", src, ref.err)
		case ref.done && malformed:
			t.Fatalf("epoll pipeline rejects %q that the streaming decoder accepts", src)
		case ref.done && complete && (bodyEnd != ref.consumed || !bytes.Equal(body, ref.body)):
			t.Fatalf("pipelines disagree on %q: end %d vs %d, body %q vs %q", src, bodyEnd, ref.consumed, body, ref.body)
		}
	})
}
