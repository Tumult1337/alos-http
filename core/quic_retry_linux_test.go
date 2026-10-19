//go:build linux && amd64

package core

import (
	"net"
	"testing"

	"github.com/guno1928/alosmap"
)

func TestQUICTokenlessInitialGetsRetryEpoll(t *testing.T) {
	srv := New(Config{})
	uc := &captureUDPSender{}
	connMap := alosmap.NewTyped[[20]byte, *QUICConn]()
	from := udpAddrToSockaddr4(net.UDPAddrFromAddrPort(retryClient))
	sent := func() [][]byte {
		uc.mu.Lock()
		defer uc.mu.Unlock()
		return append([][]byte(nil), uc.pkts...)
	}
	checkRetryAdmission(t, srv, func(data []byte) { srv.handleQUICPacketIOUring(uc, &from, data, nil, connMap) }, sent, connMap)
	if a := uc.addrs[0]; !a.IP.Equal(retryClient.Addr().AsSlice()) || a.Port != int(retryClient.Port()) {
		t.Fatalf("Retry sent to %v, want %v", a, retryClient)
	}
}
