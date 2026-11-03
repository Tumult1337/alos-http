//go:build linux && amd64

package core

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"reflect"
	"sync"
)

const tlsHMACStageLen = 256

type tlsHMAC struct {
	inner  hash.Hash
	outer  hash.Hash
	pool   *sync.Pool
	block  int
	staged int
	ipad   [sha512.BlockSize]byte
	opad   [sha512.BlockSize]byte
	stage  [tlsHMACStageLen]byte
	sum    [sha512.Size]byte
}

var (
	tlsHMACSHA256Code = reflect.ValueOf(sha256.New).Pointer()
	tlsHMACSHA384Code = reflect.ValueOf(sha512.New384).Pointer()
	tlsHMACSHA256Pool sync.Pool
	tlsHMACSHA384Pool sync.Pool
)

func init() {
	tlsHMACSHA256Pool.New = func() any { return newTLSHMAC(sha256.New, &tlsHMACSHA256Pool) }
	tlsHMACSHA384Pool.New = func() any { return newTLSHMAC(sha512.New384, &tlsHMACSHA384Pool) }
}

func newTLSHMAC(h func() hash.Hash, pool *sync.Pool) *tlsHMAC {
	inner := h()
	return &tlsHMAC{inner: inner, outer: h(), pool: pool, block: inner.BlockSize()}
}

func tlsHMACPoolFor(h func() hash.Hash) *sync.Pool {
	switch reflect.ValueOf(h).Pointer() {
	case tlsHMACSHA256Code:
		return &tlsHMACSHA256Pool
	case tlsHMACSHA384Code:
		return &tlsHMACSHA384Pool
	}
	return nil
}

func acquireTLSHMAC(h func() hash.Hash, key []byte) *tlsHMAC {
	pool := tlsHMACPoolFor(h)
	if pool == nil {
		return nil
	}
	m := pool.Get().(*tlsHMAC)
	m.setKey(key)
	return m
}

func (m *tlsHMAC) setKey(key []byte) {
	if len(key) > m.block {
		m.inner.Reset()
		m.write(key)
		m.flushStage()
		m.inner.Sum(m.ipad[:0])
	} else {
		copy(m.ipad[:], key)
	}
	for i := range m.block {
		m.opad[i] = m.ipad[i] ^ 0x5c
		m.ipad[i] ^= 0x36
	}
	m.restart()
}

func (m *tlsHMAC) restart() {
	m.inner.Reset()
	m.inner.Write(m.ipad[:m.block])
}

func (m *tlsHMAC) write(p []byte) {
	for len(p) > 0 {
		if m.staged == len(m.stage) {
			m.flushStage()
		}
		n := copy(m.stage[m.staged:], p)
		m.staged += n
		p = p[n:]
	}
}

func (m *tlsHMAC) flushStage() {
	if m.staged > 0 {
		m.inner.Write(m.stage[:m.staged])
		m.staged = 0
	}
}

func (m *tlsHMAC) sumTo(dst []byte) []byte {
	m.flushStage()
	inner := m.inner.Sum(m.sum[:0])
	m.outer.Reset()
	m.outer.Write(m.opad[:m.block])
	m.outer.Write(inner)
	return append(dst, m.outer.Sum(m.sum[:0])...)
}

func (m *tlsHMAC) release() {
	m.inner.Reset()
	m.outer.Reset()
	clear(m.ipad[:])
	clear(m.opad[:])
	clear(m.stage[:])
	clear(m.sum[:])
	m.staged = 0
	m.pool.Put(m)
}

type tls13HelloScratch struct {
	early     [64]byte
	salt      [64]byte
	hsHash    [64]byte
	cvHash    [64]byte
	finHash   [64]byte
	appHash   [64]byte
	resHash   [64]byte
	clientFin [tlsHandshakeHeaderLen + 64]byte
}

var tls13HelloScratchPool = sync.Pool{New: func() any { return new(tls13HelloScratch) }}

func acquireTLS13HelloScratch() *tls13HelloScratch {
	return tls13HelloScratchPool.Get().(*tls13HelloScratch)
}

func releaseTLS13HelloScratch(sc *tls13HelloScratch) {
	*sc = tls13HelloScratch{}
	tls13HelloScratchPool.Put(sc)
}
