//go:build linux && amd64

package core

import (
	"net"
	"sync"
	"testing"

	"github.com/guno1928/alosmap"
)

type captureUDPSender struct {
	mu    sync.Mutex
	pkts  [][]byte
	addrs []*net.UDPAddr
}

func (c *captureUDPSender) sendTo(buf []byte, addr *net.UDPAddr) (int, error) {
	c.mu.Lock()
	c.pkts = append(c.pkts, append([]byte(nil), buf...))
	c.addrs = append(c.addrs, addr)
	c.mu.Unlock()
	return len(buf), nil
}

func (c *captureUDPSender) sendToPooled(buf []byte, addr *net.UDPAddr, pbuf *[]byte) (int, error) {
	n, err := c.sendTo(buf, addr)
	if pbuf != nil {
		quicPktBufPool.Put(pbuf)
	}
	return n, err
}

func TestQUICUnknownShortPacketGetsStatelessResetEpoll(t *testing.T) {
	srv := New(Config{})
	uc := &captureUDPSender{}
	connMap := alosmap.NewTyped[[20]byte, *QUICConn]()
	from := udpAddrToSockaddr4(&net.UDPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 4433})
	for _, size := range []int{1200, 21} {
		data := shortTrigger(statelessResetCID, size)
		srv.handleQUICPacketIOUring(uc, &from, data, nil, connMap)
	}
	if len(uc.pkts) != 1 {
		t.Fatalf("sent %d datagrams, want one reset for the 1200-byte trigger only", len(uc.pkts))
	}
	tok := srv.quicResets.token(statelessResetCID)
	pkt := uc.pkts[0]
	if len(pkt) > 1199 || string(pkt[len(pkt)-16:]) != string(tok[:]) {
		t.Fatalf("reset %d bytes ending %x, want <=1199 ending %x", len(pkt), pkt[len(pkt)-16:], tok)
	}
	if a := uc.addrs[0]; !a.IP.Equal(net.IPv4(10, 1, 2, 3)) || a.Port != 4433 {
		t.Fatalf("reset sent to %v, want the trigger's source 10.1.2.3:4433", a)
	}
}
