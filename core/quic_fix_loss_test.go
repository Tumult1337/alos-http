//go:build linux && amd64

package core

import (
	"testing"
)

const (
	quicFixOutstanding    = 10
	quicFixForgedAckCount = 20
	quicFixMaxVarint      = uint64(1)<<62 - 1
	quicFixPingFrame      = 0x01
	quicFixPacketThresh   = 3
)

func (p *quicTestPeer) sendPings(n int) {
	for i := 0; i < n; i++ {
		p.qc.sendFrames(quicSpaceAppData, []byte{quicFixPingFrame}, true)
	}
}

func quicFixPredictedAckChain(outstanding, rounds int) []uint64 {
	tracked := make([]uint64, outstanding)
	for i := range tracked {
		tracked[i] = uint64(i)
	}
	next := uint64(outstanding)
	acks := make([]uint64, 0, rounds)
	for r := 0; r < rounds; r++ {
		largest := next - 1
		acks = append(acks, largest)
		var keep []uint64
		lost := 0
		for _, pn := range tracked {
			switch {
			case pn == largest:
			case pn+quicFixPacketThresh <= largest:
				lost++
			default:
				keep = append(keep, pn)
			}
		}
		for i := 0; i < lost; i++ {
			keep = append(keep, next)
			next++
		}
		tracked = keep
	}
	return acks
}

func TestQUICFixAckOfUnsentPacketClosesConnection(t *testing.T) {
	p := newQUICFixPeer(t, nil)
	p.sendPings(quicFixOutstanding)
	p.send(quicAppendACKFrame(nil, quicFixMaxVarint, 0, 0))
	p.awaitClose(quicFixProtocolViolation)
	if la := p.qc.loss.largestAckedPN(quicSpaceAppData); la >= quicFixOutstanding {
		t.Fatalf("largestAcked poisoned to %d by an ACK for a packet never sent", la)
	}
}

func TestQUICFixChainedAcksInOnePacketCannotAmplify(t *testing.T) {
	p := newQUICFixPeer(t, nil)
	p.sendPings(quicFixOutstanding)
	before := len(p.pc.snapshot())
	var frames []byte
	for _, largest := range quicFixPredictedAckChain(quicFixOutstanding, quicFixForgedAckCount) {
		frames = quicAppendACKFrame(frames, largest, 0, 0)
	}
	p.send(frames)
	if sent := len(p.pc.snapshot()) - before; sent > quicFixOutstanding+1 {
		t.Fatalf("one %d-byte packet of %d ACK frames made the server send %d packets", len(frames), quicFixForgedAckCount, sent)
	}
}

func TestQUICFixLossRecoveryStillRetransmits(t *testing.T) {
	p := newQUICFixPeer(t, nil)
	p.sendPings(quicFixOutstanding)
	before := len(p.pc.snapshot())
	p.send(quicAppendACKFrame(nil, quicFixOutstanding-1, 0, 0))
	if p.qc.closed.Load() {
		t.Fatal("a valid ACK closed the connection")
	}
	if sent := len(p.pc.snapshot()) - before; sent == 0 {
		t.Fatal("packets declared lost by a valid ACK were never retransmitted")
	}
	p.qc.loss.mu.Lock()
	defer p.qc.loss.mu.Unlock()
	for _, sp := range p.qc.loss.sent[quicSpaceAppData] {
		if sp.pn+quicFixPacketThresh <= quicFixOutstanding-1 {
			t.Fatalf("packet %d is below the loss threshold but still tracked as in flight", sp.pn)
		}
	}
}

const quicFixAckOnlySends = 16400

func TestQUICFixAckOnlyPacketsAreNotTracked(t *testing.T) {
	p := newQUICFixPeer(t, nil)
	ack := quicAppendACKFrame(nil, 0, 0, 0)
	for i := 0; i < quicFixAckOnlySends; i++ {
		p.qc.sendFrames(quicSpaceAppData, ack, false)
	}
	p.qc.loss.mu.Lock()
	tracked := len(p.qc.loss.sent[quicSpaceAppData])
	p.qc.loss.mu.Unlock()
	if tracked != 0 {
		t.Fatalf("%d ACK-only packets are tracked as sent and can never be removed without a peer ACK", tracked)
	}
	if !p.qc.loss.canSend() {
		t.Fatal("ACK-only traffic wedged the send path")
	}
	if p.qc.loss.hasSentPackets(quicSpaceAppData) {
		t.Fatal("ACK-only traffic keeps the connection in the timer work set")
	}
}

const quicFixAckGapPackets = 36

func TestQUICFixReplayBelowTrackedAckRangesIsDuplicate(t *testing.T) {
	p := newQUICFixPeer(t, nil)
	for i := 0; i < quicFixAckGapPackets; i++ {
		if !p.qc.recordRecvPN(quicSpaceAppData, uint64(2*i)) {
			t.Fatalf("fresh packet number %d reported as a duplicate", 2*i)
		}
	}
	if p.qc.recordRecvPN(quicSpaceAppData, 0) {
		t.Fatal("a replayed packet number below the tracked ACK ranges was accepted as new")
	}
	if p.qc.recordRecvPN(quicSpaceAppData, 2*quicFixAckGapPackets-2) {
		t.Fatal("a replay of the newest packet number was accepted as new")
	}
	if !p.qc.recordRecvPN(quicSpaceAppData, 2*quicFixAckGapPackets-3) {
		t.Fatal("a fresh packet number filling a tracked gap was rejected")
	}
}
