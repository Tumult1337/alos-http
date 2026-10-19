//go:build linux && amd64

package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/turbo"
)

type aeadKeys struct {
	cur, prev     cipher.AEAD
	curID, prevID byte
	rotatedAt     int64
}

type aeadKeyRing struct {
	mu       sync.Mutex
	keys     atomic.Pointer[aeadKeys]
	now      func() int64
	keyLen   int
	rotation time.Duration
}

func newAEADKeyRing(keyLen int, rotation time.Duration, now func() int64) *aeadKeyRing {
	if now == nil {
		now = turbo.UnixNano
	}
	r := &aeadKeyRing{now: now, keyLen: keyLen, rotation: rotation}
	r.keys.Store(&aeadKeys{cur: r.freshAEAD(), curID: 1, rotatedAt: now()})
	return r
}

func newGCMFromKey(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

func (r *aeadKeyRing) freshAEAD() cipher.AEAD {
	key := make([]byte, r.keyLen)
	rand.Read(key)
	aead := newGCMFromKey(key)
	clear(key)
	return aead
}

func (r *aeadKeyRing) expired(k *aeadKeys) bool {
	return time.Duration(r.now()-k.rotatedAt) >= r.rotation
}

func (r *aeadKeyRing) current() *aeadKeys {
	k := r.keys.Load()
	if !r.expired(k) {
		return k
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k = r.keys.Load()
	if !r.expired(k) {
		return k
	}
	now := r.now()
	next := &aeadKeys{cur: r.freshAEAD(), curID: k.curID + 1, rotatedAt: now}
	if time.Duration(now-k.rotatedAt) < 2*r.rotation {
		next.prev, next.prevID = k.cur, k.curID
	}
	r.keys.Store(next)
	return next
}

func (r *aeadKeyRing) forID(id byte) cipher.AEAD {
	k := r.current()
	switch {
	case id == k.curID:
		return k.cur
	case k.prev != nil && id == k.prevID:
		return k.prev
	}
	return nil
}
