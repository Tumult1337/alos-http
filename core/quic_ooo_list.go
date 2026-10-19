//go:build linux && amd64

package core

import (
	"slices"
	"sort"
)

const quicOOOChunkLen = 64

type quicOOOPos struct {
	chunk int
	idx   int
}

type quicOOOList struct {
	chunks [][]quicOOOSegment
	inline [1][]quicOOOSegment
	spare  []quicOOOSegment
	count  int
}

func (l *quicOOOList) len() int {
	return l.count
}

func (l *quicOOOList) last() *quicOOOSegment {
	ch := l.chunks[len(l.chunks)-1]
	return &ch[len(ch)-1]
}

func (l *quicOOOList) endPos() quicOOOPos {
	return quicOOOPos{chunk: len(l.chunks)}
}

func (l *quicOOOList) firstEndingAfter(off uint64) quicOOOPos {
	if l.count == 0 || l.last().end() <= off {
		return l.endPos()
	}
	c := sort.Search(len(l.chunks), func(c int) bool {
		ch := l.chunks[c]
		return ch[len(ch)-1].end() > off
	})
	ch := l.chunks[c]
	return quicOOOPos{chunk: c, idx: sort.Search(len(ch), func(i int) bool { return ch[i].end() > off })}
}

func (l *quicOOOList) at(p quicOOOPos) *quicOOOSegment {
	if p.chunk >= len(l.chunks) {
		return nil
	}
	return &l.chunks[p.chunk][p.idx]
}

func (l *quicOOOList) before(p quicOOOPos) *quicOOOSegment {
	if p.idx > 0 {
		return &l.chunks[p.chunk][p.idx-1]
	}
	if p.chunk == 0 {
		return nil
	}
	ch := l.chunks[p.chunk-1]
	return &ch[len(ch)-1]
}

func (l *quicOOOList) next(p quicOOOPos) quicOOOPos {
	if p.idx+1 < len(l.chunks[p.chunk]) {
		return quicOOOPos{chunk: p.chunk, idx: p.idx + 1}
	}
	return quicOOOPos{chunk: p.chunk + 1}
}

func (l *quicOOOList) insert(p quicOOOPos, seg quicOOOSegment) quicOOOPos {
	l.count++
	if len(l.chunks) == 0 {
		l.chunks = append(l.inline[:0], append(l.spare[:0], seg))
		l.spare = nil
		return quicOOOPos{}
	}
	if p.chunk == len(l.chunks) {
		p = quicOOOPos{chunk: p.chunk - 1, idx: len(l.chunks[p.chunk-1])}
		if p.idx == quicOOOChunkLen {
			l.chunks = append(l.chunks, append(make([]quicOOOSegment, 0, quicOOOChunkLen), seg))
			l.inline[0] = nil
			return quicOOOPos{chunk: p.chunk + 1}
		}
	}
	if len(l.chunks[p.chunk]) == quicOOOChunkLen {
		p = l.split(p)
	}
	l.chunks[p.chunk] = slices.Insert(l.chunks[p.chunk], p.idx, seg)
	return p
}

func (l *quicOOOList) split(p quicOOOPos) quicOOOPos {
	const half = quicOOOChunkLen / 2
	ch := l.chunks[p.chunk]
	right := append(make([]quicOOOSegment, 0, quicOOOChunkLen), ch[half:]...)
	clear(ch[half:])
	l.chunks[p.chunk] = ch[:half]
	l.chunks = slices.Insert(l.chunks, p.chunk+1, right)
	l.inline[0] = nil
	if p.idx > half {
		return quicOOOPos{chunk: p.chunk + 1, idx: p.idx - half}
	}
	return p
}

func (l *quicOOOList) dropFront(k int) {
	l.count -= k
	for k > 0 {
		ch := l.chunks[0]
		if k < len(ch) {
			n := copy(ch, ch[k:])
			clear(ch[n:])
			l.chunks[0] = ch[:n]
			return
		}
		k -= len(ch)
		clear(ch)
		if len(l.chunks) == 1 {
			l.spare = ch[:0]
			l.chunks = nil
			return
		}
		l.chunks[0] = nil
		l.chunks = l.chunks[1:]
	}
}
