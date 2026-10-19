//go:build linux && amd64

package core

import (
	"net"
	"testing"
	"time"

	"github.com/guno1928/alosmap"
	"github.com/guno1928/turbo"
)

type quicFixNullSender struct{}

func (quicFixNullSender) sendTo(buf []byte, _ *net.UDPAddr) (int, error) { return len(buf), nil }
func (quicFixNullSender) sendToPooled(buf []byte, _ *net.UDPAddr, pbuf *[]byte) (int, error) {
	if pbuf != nil {
		quicPktBufPool.Put(pbuf)
	}
	return len(buf), nil
}

type quicFixConnFactory struct {
	t       *testing.T
	srv     *Server
	connMap *quicConnMap
	next    byte
}

func newQUICFixConnFactory(t *testing.T, cfg Config) *quicFixConnFactory {
	t.Helper()
	srv := New(cfg)
	f := &quicFixConnFactory{t: t, srv: srv, connMap: alosmap.NewTyped[[20]byte, *QUICConn]().Prealloc(16)}
	t.Cleanup(func() { srv.quicTimers.closeAll(ErrClientGone) })
	return f
}

func (f *quicFixConnFactory) dial(ip net.IP, port int) *QUICConn {
	f.next++
	dcid := []byte{0xd0, f.next, 3, 4, 5, 6, 7, 8}
	scid := []byte{0x5c, f.next, 3, 4, 5, 6, 7, 8}
	return f.srv.createQUICConnIOUring(quicFixNullSender{}, &net.UDPAddr{IP: ip, Port: port}, dcid, scid, f.connMap)
}

func quicFixAwait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := turbo.Deadline(quicPeerWait)
	for !cond() {
		if turbo.Until(deadline) <= 0 {
			t.Fatalf("timed out waiting for %s", what)
		}
		turbo.Sleep(quicPeerPoll)
	}
}

func TestQUICFixConnsArePerIPLimited(t *testing.T) {
	f := newQUICFixConnFactory(t, Config{MaxConnsPerIP: 2})
	attacker := net.IPv4(127, 0, 0, 1)
	var held []*QUICConn
	for port := 40000; port < 40002; port++ {
		qc := f.dial(attacker, port)
		if qc == nil {
			t.Fatalf("conn from port %d refused below the per-IP limit", port)
		}
		held = append(held, qc)
	}
	if qc := f.dial(attacker, 40002); qc != nil {
		t.Fatal("a third QUIC conn from one IP was admitted with MaxConnsPerIP=2")
	}
	if qc := f.dial(net.IPv4(127, 0, 0, 2), 40000); qc == nil {
		t.Fatal("another IP was refused while only the first IP is at its limit")
	}
	held[0].close()
	quicFixAwait(t, "the per-IP slot to be released", func() bool { return f.dial(attacker, 40003) != nil })
}

func TestQUICFixHalfOpenConnsCannotStarveTCP(t *testing.T) {
	const maxConns = 8
	f := newQUICFixConnFactory(t, Config{MaxConns: maxConns, MaxConnsPerIP: -1})
	admitted := 0
	for i := 0; i < maxConns; i++ {
		if f.dial(net.IPv4(10, 0, 0, byte(i+1)), 443) != nil {
			admitted++
		}
	}
	if admitted >= maxConns {
		t.Fatalf("%d handshaking QUIC conns took every one of the %d MaxConns slots", admitted, maxConns)
	}
	if !f.srv.tryTrackConn() {
		t.Fatal("a TCP accept was refused while only half-open QUIC conns exist")
	}
	f.srv.releaseTrackedConn()
}

func TestQUICFixHandshakeTimeoutClosesHalfOpenConn(t *testing.T) {
	const timeout = 150 * time.Millisecond
	f := newQUICFixConnFactory(t, Config{HandshakeTimeout: timeout, MaxConnsPerIP: -1})
	qc := f.dial(net.IPv4(127, 0, 0, 1), 40000)
	if qc == nil {
		t.Fatal("conn refused")
	}
	qc.tick(turbo.UnixNano()+int64(2*timeout), true)
	if !qc.closed.Load() {
		t.Fatal("a conn that never completed its handshake survived past HandshakeTimeout")
	}
	done := f.dial(net.IPv4(127, 0, 0, 1), 40001)
	if done == nil {
		t.Fatal("conn refused")
	}
	done.handshakeDone.Store(true)
	done.tick(turbo.UnixNano()+int64(2*timeout), true)
	if done.closed.Load() {
		t.Fatal("an established conn was closed by the handshake timeout")
	}
}
