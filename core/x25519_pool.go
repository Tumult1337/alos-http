//go:build linux && amd64

package core

import (
	"crypto/ecdh"
	"crypto/rand"
	"runtime"
	"sync"
	"time"
)

type x25519Keypair struct {
	priv *ecdh.PrivateKey
	pub  [32]byte
}

func generateX25519Keypair() (x25519Keypair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return x25519Keypair{}, err
	}
	kp := x25519Keypair{priv: priv}
	copy(kp.pub[:], priv.PublicKey().Bytes())
	return kp, nil
}

func (kp *x25519Keypair) sharedSecret(peer []byte) ([32]byte, bool) {
	var shared [32]byte
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return shared, false
	}
	secret, err := kp.priv.ECDH(pub)
	if err != nil {
		return shared, false
	}
	copy(shared[:], secret)
	clear(secret)
	return shared, true
}

func (kp *x25519Keypair) zero() {
	kp.priv = nil
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
