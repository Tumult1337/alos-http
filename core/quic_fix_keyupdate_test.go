//go:build linux && amd64

package core

import "testing"

const quicFixKeyUpdatePayload = 32

func quicFixKeySet(t *testing.T, seed byte, hp headerProtector) *quicKeys {
	t.Helper()
	_, keys, err := quicDeriveInitialKeys([]byte{seed, seed, seed, seed, seed, seed, seed, seed})
	if err != nil {
		t.Fatal(err)
	}
	keys.hp = hp
	return keys
}

func quicFixReceivedPN(qc *QUICConn, pn uint64) bool {
	for _, r := range qc.ackRanges[quicSpaceAppData] {
		if pn >= r.lo && pn <= r.hi {
			return true
		}
	}
	return false
}

func quicFixDeliverShort(qc *QUICConn, keys *quicKeys, pn uint64, phase uint32) {
	payload := make([]byte, quicFixKeyUpdatePayload)
	payload[0] = quicFixPingFrame
	qc.handleShortHeaderPacket(quicBuildShortPacket(nil, qc.srcCID(), payload, pn, -1, keys, phase))
}

func TestQUICFixKeyUpdateKeepsReorderedOldPhasePackets(t *testing.T) {
	startReqStreamWorkers()
	srv := New(Config{})
	srv.Router.Build()
	qc := newQUICTestPeerFor(t, srv).qc
	oldKeys := qc.keys[quicSpaceAppData]
	qc.origHP = oldKeys.hp
	updated := quicFixKeySet(t, 0x21, oldKeys.hp)
	following := quicFixKeySet(t, 0x31, oldKeys.hp)
	qc.nextRecvKeys = updated

	quicFixDeliverShort(qc, updated, 5, 1)
	if !quicFixReceivedPN(qc, 5) || qc.recvKeyPhase != 1 {
		t.Fatalf("peer key update not accepted: pn 5 received=%v phase=%d", quicFixReceivedPN(qc, 5), qc.recvKeyPhase)
	}

	quicFixDeliverShort(qc, oldKeys, 6, 0)
	if quicFixReceivedPN(qc, 6) {
		t.Error("old-phase packet numbered after the key update was acknowledged without next keys to decrypt it")
	}

	qc.nextRecvKeys = following
	quicFixDeliverShort(qc, oldKeys, 3, 0)
	if !quicFixReceivedPN(qc, 3) {
		t.Error("packet reordered across the key update was dropped instead of decrypted with the previous keys")
	}
	if qc.keys[quicSpaceAppData] != updated || qc.recvKeyPhase != 1 {
		t.Error("previous-key packet changed the current receive keys")
	}

	quicFixDeliverShort(qc, following, 7, 0)
	if !quicFixReceivedPN(qc, 7) || qc.recvKeyPhase != 0 || qc.keys[quicSpaceAppData] != following {
		t.Errorf("second key update not accepted: pn 7 received=%v phase=%d", quicFixReceivedPN(qc, 7), qc.recvKeyPhase)
	}
}
