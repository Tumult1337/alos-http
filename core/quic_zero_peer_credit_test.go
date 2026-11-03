//go:build linux && amd64

package core

import (
	"testing"
)

func TestQUICZeroPeerCreditIncomingBidiStreams(t *testing.T) {
	peer := newZeroCreditFixture(t, zeroCreditParams(nil, nil))
	for _, id := range []uint64{0, 4} {
		stream := peer.open(t, id, "")
		if stream.maxSend != 0 {
			t.Errorf("incoming client bidi ID %d grant=%d, want 0", id, stream.maxSend)
		}
	}
}
