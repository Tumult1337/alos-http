//go:build linux && amd64

package core

import (
	"testing"
)

func uniCreditLocalGrant(conn *QUICConn) uint64 {
	stream := conn.openLocalUniStream()
	grant := stream.maxSend
	conn.releaseStream(stream)
	return grant
}

func TestQUICUniPeerCreditIndependentOfBidiCredit(t *testing.T) {
	for _, credit := range []uint64{0, 5, 1 << 21} {
		conn := uniCreditConn(t)
		uniCreditApply(t, conn, append(uniCreditParam(5, 29), uniCreditParam(7, credit)...))
		if got := uniCreditLocalGrant(conn); got != credit {
			t.Errorf("uni grant %d: local uni stream credit=%d", credit, got)
		}
		pooled := getPooledStream(0, conn)
		if pooled.maxSend != 29 {
			t.Errorf("uni grant %d: peer bidi stream credit=%d, want 29", credit, pooled.maxSend)
		}
		pooled.refCount.Store(1)
		conn.releaseStream(pooled)
	}
}
