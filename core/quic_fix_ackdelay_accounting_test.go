//go:build linux && amd64

package core

import (
	"testing"
	"time"
)

const (
	quicFixPeerAckDelayExponent = 10
	quicFixPeerMaxAckDelayMs    = 40
)

func TestQUICFixPeerAckDelayParametersApplied(t *testing.T) {
	qc, _, _ := newQUICFixCoalescePeer(t)
	qc.writeMu.Lock()
	ptoBefore := qc.loss.ptoTimeout()
	qc.writeMu.Unlock()
	ch := &ParsedClientHello{}
	ch.quicTP = quicPeerTransportParams{seen: true, ackDelayExponent: quicFixPeerAckDelayExponent, maxAckDelayMs: quicFixPeerMaxAckDelayMs}
	qc.applyPeerTransportParams(ch)
	maxAckDelay := quicFixPeerMaxAckDelayMs * time.Millisecond
	qc.writeMu.Lock()
	defer qc.writeMu.Unlock()
	if got, want := qc.loss.ptoTimeout()-ptoBefore, maxAckDelay-quicMaxAckDelay; got != want {
		t.Errorf("PTO grew by %v after max_ack_delay=%v, want %v", got, maxAckDelay, want)
	}
	cases := []struct {
		space   int
		encoded uint64
		want    time.Duration
	}{
		{quicSpaceAppData, 20, 20 << quicFixPeerAckDelayExponent * time.Microsecond},
		{quicSpaceAppData, 1000, maxAckDelay},
		{quicSpaceAppData, 1 << 62, maxAckDelay},
		{quicSpaceInitial, 20, 0},
		{quicSpaceHandshake, 20, 0},
	}
	for _, c := range cases {
		if got := qc.peerAckDelayLocked(c.space, c.encoded); got != c.want {
			t.Errorf("space %d, ACK Delay %d: got %v, want %v", c.space, c.encoded, got, c.want)
		}
	}
}
