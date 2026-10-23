//go:build linux && amd64

package core

import (
	"net"
	"slices"
	"testing"

	"github.com/guno1928/alosmap"
)

func (f *quicFixFlightConn) clientInitialOfSize(t *testing.T, pn uint64, frames []byte, size int) []byte {
	t.Helper()
	pad := 0
	for range 4 {
		payload := append(append([]byte(nil), frames...), make([]byte, pad)...)
		pkt := quicBuildInitialPacket(nil, f.qc.srcCID(), quicFixClientSCID, nil, payload, pn, -1, f.qc.keys[quicSpaceInitial])
		if len(pkt) == size {
			return pkt
		}
		pad += size - len(pkt)
		if pad < 0 {
			break
		}
	}
	t.Fatalf("cannot build a %d-byte Initial datagram", size)
	return nil
}

type quicFixInitialState struct {
	largest int64
	ranges  []pnRange
	closed  bool
	sent    int
}

func (f *quicFixFlightConn) initialState() quicFixInitialState {
	return quicFixInitialState{
		largest: f.qc.recvLargest[quicSpaceInitial],
		ranges:  slices.Clone(f.qc.ackRanges[quicSpaceInitial]),
		closed:  f.qc.closed.Load(),
		sent:    f.datagrams(),
	}
}

func TestQUICFixInitialInADatagramBelow1200BytesIsDiscarded(t *testing.T) {
	f := newQUICFixFlightConn(t)
	before := f.initialState()
	const pn = 5
	f.feedDatagram(f.clientInitialOfSize(t, pn, []byte{quicFramePing}, quicMinInitialDatagram-1))
	after := f.initialState()
	if after.largest != before.largest || !slices.Equal(after.ranges, before.ranges) || after.closed || after.sent != before.sent {
		t.Fatalf("a %d-byte Initial datagram changed state: before %+v, after %+v", quicMinInitialDatagram-1, before, after)
	}
	f.feedDatagram(f.clientInitialOfSize(t, pn, []byte{quicFramePing}, quicMinInitialDatagram))
	sent := f.serverDatagrams(t, before.sent)
	if f.qc.recvLargest[quicSpaceInitial] != pn || len(sent) != 1 || len(sent[0].initialAcks) != 1 || !quicFixAckCovers(sent[0].initialAcks[0], pn) {
		t.Fatalf("a %d-byte Initial datagram was not processed: largest %d, replies %+v", quicMinInitialDatagram, f.qc.recvLargest[quicSpaceInitial], sent)
	}
}

func TestQUICFixSmallInitialDatagramIsNotForwardedToAValidatedConnection(t *testing.T) {
	f := newQUICFixFlightConn(t)
	f.qc.addressValidated.Store(true)
	connMap := alosmap.NewTyped[[20]byte, *QUICConn]()
	connMap.Store(quicCIDKey(f.qc.srcCID()), f.qc)
	uc := &captureUDPSender{}
	from := udpAddrToSockaddr4(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: quicFixLoopback.Port})
	f.qc.server.handleQUICPacketIOUring(uc, &from, f.clientInitialOfSize(t, 9, []byte{quicFramePing}, quicMinInitialDatagram-1), nil, connMap)
	if queued := len(f.qc.inbound); queued != 0 {
		t.Fatalf("a %d-byte Initial datagram reached a validated connection (%d queued)", quicMinInitialDatagram-1, queued)
	}
	f.qc.server.handleQUICPacketIOUring(uc, &from, f.clientInitialOfSize(t, 10, []byte{quicFramePing}, quicMinInitialDatagram), nil, connMap)
	if queued := len(f.qc.inbound); queued != 1 {
		t.Fatalf("a %d-byte Initial datagram was not forwarded (%d queued)", quicMinInitialDatagram, queued)
	}
	uc.mu.Lock()
	replies := len(uc.pkts)
	uc.mu.Unlock()
	if replies != 0 {
		t.Fatalf("the dispatcher answered %d times", replies)
	}
}
