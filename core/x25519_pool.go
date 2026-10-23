//go:build linux && amd64

package core

import (
	"crypto/rand"
	"crypto/subtle"
	"runtime"
	"sync"
	"time"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

const (
	x25519KeyLen       = 32
	x25519LadderA24    = 121665
	x25519ScalarTopBit = 254
)

var x25519AllZero [x25519KeyLen]byte

type x25519Keypair struct {
	priv [x25519KeyLen]byte
	pub  [x25519KeyLen]byte
}

func generateX25519Keypair() (x25519Keypair, error) {
	var kp x25519Keypair
	if _, err := rand.Read(kp.priv[:]); err != nil {
		return x25519Keypair{}, err
	}
	var s edwards25519.Scalar
	if _, err := s.SetBytesWithClamping(kp.priv[:]); err != nil {
		return x25519Keypair{}, err
	}
	var p edwards25519.Point
	copy(kp.pub[:], p.ScalarBaseMult(&s).BytesMontgomery())
	s = edwards25519.Scalar{}
	return kp, nil
}

func (kp *x25519Keypair) sharedSecret(peer []byte) ([32]byte, bool) {
	var shared [x25519KeyLen]byte
	if len(peer) != x25519KeyLen {
		return shared, false
	}
	x25519Ladder(&shared, &kp.priv, peer)
	return shared, subtle.ConstantTimeCompare(shared[:], x25519AllZero[:]) == 0
}

func x25519Ladder(dst, priv *[x25519KeyLen]byte, u []byte) {
	k := *priv
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	var x1, x2, z2, x3, z3, a, aa, b, bb, e, c, d, da, cb field.Element
	x1.SetBytes(u)
	x2.One()
	x3.Set(&x1)
	z3.One()
	swap := 0
	for t := x25519ScalarTopBit; t >= 0; t-- {
		bit := int(k[t>>3]>>(t&7)) & 1
		swap ^= bit
		x2.Swap(&x3, swap)
		z2.Swap(&z3, swap)
		swap = bit
		a.Add(&x2, &z2)
		aa.Square(&a)
		b.Subtract(&x2, &z2)
		bb.Square(&b)
		e.Subtract(&aa, &bb)
		c.Add(&x3, &z3)
		d.Subtract(&x3, &z3)
		da.Multiply(&d, &a)
		cb.Multiply(&c, &b)
		x3.Add(&da, &cb)
		x3.Square(&x3)
		z3.Subtract(&da, &cb)
		z3.Square(&z3)
		z3.Multiply(&x1, &z3)
		x2.Multiply(&aa, &bb)
		z2.Mult32(&e, x25519LadderA24)
		z2.Add(&aa, &z2)
		z2.Multiply(&e, &z2)
	}
	x2.Swap(&x3, swap)
	z2.Swap(&z3, swap)
	z2.Invert(&z2)
	x2.Multiply(&x2, &z2)
	copy(dst[:], x2.Bytes())
	clear(k[:])
}

func (kp *x25519Keypair) zero() {
	clear(kp.priv[:])
	clear(kp.pub[:])
}

type x25519KeyPool struct {
	ch        chan x25519Keypair
	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func newX25519KeyPool(size int) *x25519KeyPool {
	if size < 1 {
		size = 1
	}
	p := &x25519KeyPool{
		ch:   make(chan x25519Keypair, size),
		stop: make(chan struct{}),
	}
	for len(p.ch) < cap(p.ch) {
		kp, err := generateX25519Keypair()
		if err != nil {
			break
		}
		p.ch <- kp
	}
	workers := runtime.GOMAXPROCS(0) * 2
	if workers < 1 {
		workers = 1
	}
	if workers > 32 {
		workers = 32
	}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.fillLoop()
	}
	return p
}

func (p *x25519KeyPool) fillLoop() {
	defer p.wg.Done()
	for {
		kp, err := generateX25519Keypair()
		if err != nil {
			select {
			case <-p.stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		select {
		case p.ch <- kp:
		case <-p.stop:
			kp.zero()
			return
		}
	}
}

func (p *x25519KeyPool) Get() (x25519Keypair, error) {
	if p != nil {
		select {
		case kp, ok := <-p.ch:
			if ok {
				return kp, nil
			}
		default:
		}
	}
	return generateX25519Keypair()
}

func (p *x25519KeyPool) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		close(p.stop)
		p.wg.Wait()
		close(p.ch)
		for kp := range p.ch {
			kp.zero()
		}
	})
}

func x25519KeyPoolSize(cfg Config) int {
	size := cfg.WorkerCount * 128
	if size < 4096 {
		size = cfg.Listeners * 512
	}
	if size < 4096 {
		size = runtime.GOMAXPROCS(0) * 256
	}
	if size < 4096 {
		size = 4096
	}
	if size > 32768 {
		size = 32768
	}
	return size
}
