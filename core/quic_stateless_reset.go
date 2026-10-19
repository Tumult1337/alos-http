//go:build linux && amd64

package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync/atomic"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicStatelessResetTokenLen = 16
	quicMinShortPacketLen      = 21
	quicStatelessResetMaxLen   = 64
	quicStatelessResetsPerSec  = 100
	quicShortHeaderRandomBits  = 0x3f
)

const quicStatelessResetKeyLen = 32

type quicStatelessResetter struct {
	key    []byte
	window atomic.Int64
	sent   atomic.Int64
}

func newQUICStatelessResetter(configured []byte) *quicStatelessResetter {
	r := &quicStatelessResetter{}
	if len(configured) > 0 {
		r.key = append([]byte(nil), configured...)
		return r
	}
	r.key = make([]byte, quicStatelessResetKeyLen)
	rand.Read(r.key)
	return r
}

func (r *quicStatelessResetter) token(cid []byte) [quicStatelessResetTokenLen]byte {
	mac := hmac.New(sha256.New, r.key)
	mac.Write(cid)
	var sum [sha256.Size]byte
	var tok [quicStatelessResetTokenLen]byte
	copy(tok[:], mac.Sum(sum[:0]))
	return tok
}

func (r *quicStatelessResetter) allow() bool {
	second := turbo.UnixNano() / int64(time.Second)
	if w := r.window.Load(); w != second && r.window.CompareAndSwap(w, second) {
		r.sent.Store(0)
	}
	return r.sent.Add(1) <= quicStatelessResetsPerSec
}

func (r *quicStatelessResetter) packet(cid []byte, triggerLen int) []byte {
	if triggerLen <= quicMinShortPacketLen || !r.allow() {
		return nil
	}
	size := min(triggerLen-1, quicStatelessResetMaxLen)
	pkt := make([]byte, size)
	for i := 0; i < size-quicStatelessResetTokenLen; i += 8 {
		v := turbo.Uint64()
		for j := 0; j < 8 && i+j < size-quicStatelessResetTokenLen; j++ {
			pkt[i+j] = byte(v >> (8 * j))
		}
	}
	pkt[0] = quicFixedBit | pkt[0]&quicShortHeaderRandomBits
	tok := r.token(cid)
	copy(pkt[size-quicStatelessResetTokenLen:], tok[:])
	return pkt
}

func (s *Server) statelessResetFor(data []byte) []byte {
	if s.quicResets == nil || len(data) < 1+quicConnIDLen {
		return nil
	}
	return s.quicResets.packet(data[1:1+quicConnIDLen], len(data))
}
