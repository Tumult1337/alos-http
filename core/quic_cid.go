//go:build linux && amd64

package core

import "crypto/rand"

const (
	quicMaxIssuedCIDs       = 4
	quicDefaultPeerCIDLimit = 2
	quicLocalActiveCIDLimit = 2
	quicMaxCIDLen           = 20
	quicErrConnIDLimit      = 0x09
)

type quicIssuedCID struct {
	seq uint64
	cid [quicConnIDLen]byte
}

type quicPeerCID struct {
	seq    uint64
	cid    [quicMaxCIDLen]byte
	cidLen int
	token  [quicStatelessResetTokenLen]byte
}

func quicAppendNewConnIDFrame(dst []byte, seq, retirePriorTo uint64, cid []byte, token [quicStatelessResetTokenLen]byte) []byte {
	dst = quicAppendVarint(dst, quicFrameNewConnID)
	dst = quicAppendVarint(dst, seq)
	dst = quicAppendVarint(dst, retirePriorTo)
	dst = append(dst, byte(len(cid)))
	dst = append(dst, cid...)
	dst = append(dst, token[:]...)
	return dst
}

func quicAppendRetireConnIDFrame(dst []byte, seq uint64) []byte {
	dst = quicAppendVarint(dst, quicFrameRetireConnID)
	return quicAppendVarint(dst, seq)
}

func (qc *QUICConn) issuedLimit() int {
	limit := qc.peerCIDLimit
	if limit < quicDefaultPeerCIDLimit {
		limit = quicDefaultPeerCIDLimit
	}
	return int(min(limit, quicMaxIssuedCIDs))
}

func (qc *QUICConn) issueConnectionIDs() {
	if qc.connMap == nil || qc.server == nil || qc.server.quicResets == nil {
		return
	}
	var frames []byte
	qc.cidMu.Lock()
	if len(qc.issued) == 0 {
		var first quicIssuedCID
		copy(first.cid[:], qc.srcCID())
		qc.issued = append(qc.issued, first)
		qc.nextIssueSeq = 1
	}
	for len(qc.issued) < qc.issuedLimit() {
		frames = qc.issueOneLocked(frames)
	}
	qc.cidMu.Unlock()
	if len(frames) > 0 {
		qc.sendFrames(quicSpaceAppData, frames, true)
	}
}

func (qc *QUICConn) issueOneLocked(frames []byte) []byte {
	c := quicIssuedCID{seq: qc.nextIssueSeq}
	for {
		rand.Read(c.cid[:])
		if _, taken := qc.connMap.Load(quicCIDKey(c.cid[:])); !taken {
			break
		}
	}
	qc.nextIssueSeq++
	qc.issued = append(qc.issued, c)
	qc.connMap.Store(quicCIDKey(c.cid[:]), qc)
	return quicAppendNewConnIDFrame(frames, c.seq, 0, c.cid[:], qc.server.quicResets.token(c.cid[:]))
}

func (qc *QUICConn) handleRetireConnID(seq uint64) {
	var frames []byte
	qc.cidMu.Lock()
	if seq >= max(qc.nextIssueSeq, 1) {
		qc.cidMu.Unlock()
		qc.closeWithError(quicErrProtocolViolation, "RETIRE_CONNECTION_ID for a sequence number never issued")
		return
	}
	idx := -1
	for i := range qc.issued {
		if qc.issued[i].seq == seq {
			idx = i
			break
		}
	}
	if idx < 0 {
		qc.cidMu.Unlock()
		return
	}
	if qc.issued[idx].cid == qc.rxDCID {
		qc.cidMu.Unlock()
		qc.closeWithError(quicErrProtocolViolation, "RETIRE_CONNECTION_ID for the connection ID in use")
		return
	}
	retired := qc.issued[idx].cid
	qc.issued = append(qc.issued[:idx], qc.issued[idx+1:]...)
	qc.connMap.Delete(quicCIDKey(retired[:]))
	for len(qc.issued) < qc.issuedLimit() {
		frames = qc.issueOneLocked(frames)
	}
	qc.cidMu.Unlock()
	if len(frames) > 0 {
		qc.sendFrames(quicSpaceAppData, frames, true)
	}
}

func (qc *QUICConn) unregisterIssuedCIDs(connMap *quicConnMap) {
	qc.cidMu.Lock()
	issued := qc.issued
	qc.issued = nil
	qc.cidMu.Unlock()
	for i := range issued {
		connMap.Delete(quicCIDKey(issued[i].cid[:]))
	}
}

func (qc *QUICConn) handlePeerNewConnID(f quicNewConnIDFrame) {
	if len(f.connID) == 0 || len(f.connID) > quicMaxCIDLen || f.retirePT > f.seq {
		qc.closeWithError(quicErrFrameEncoding, "malformed NEW_CONNECTION_ID")
		return
	}
	if qc.dstCIDLen == 0 {
		qc.closeWithError(quicErrProtocolViolation, "NEW_CONNECTION_ID on a zero-length connection ID")
		return
	}
	var frames []byte
	qc.cidMu.Lock()
	if !qc.peerCIDsInit {
		var first quicPeerCID
		first.cidLen = copy(first.cid[:], qc.dstCID())
		qc.peerCIDs = append(qc.peerCIDs, first)
		qc.peerCIDsInit = true
	}
	if f.seq < qc.peerRetirePT {
		qc.cidMu.Unlock()
		qc.sendFrames(quicSpaceAppData, quicAppendRetireConnIDFrame(nil, f.seq), true)
		return
	}
	for i := range qc.peerCIDs {
		p := &qc.peerCIDs[i]
		if p.seq != f.seq {
			continue
		}
		same := p.cidLen == len(f.connID) && string(p.cid[:p.cidLen]) == string(f.connID) && (p.seq == 0 || p.token == f.resetToken)
		qc.cidMu.Unlock()
		if !same {
			qc.closeWithError(quicErrProtocolViolation, "NEW_CONNECTION_ID reuses a sequence number")
		}
		return
	}
	entry := quicPeerCID{seq: f.seq, token: f.resetToken}
	entry.cidLen = copy(entry.cid[:], f.connID)
	qc.peerCIDs = append(qc.peerCIDs, entry)
	switchTo := -1
	if f.retirePT > qc.peerRetirePT {
		qc.peerRetirePT = f.retirePT
		kept := qc.peerCIDs[:0]
		for _, p := range qc.peerCIDs {
			if p.seq < f.retirePT {
				frames = quicAppendRetireConnIDFrame(frames, p.seq)
				continue
			}
			kept = append(kept, p)
		}
		qc.peerCIDs = kept
		if qc.dstCIDSeq < f.retirePT {
			switchTo = 0
			for i := range qc.peerCIDs {
				if qc.peerCIDs[i].seq < qc.peerCIDs[switchTo].seq {
					switchTo = i
				}
			}
		}
	}
	overLimit := len(qc.peerCIDs) > quicLocalActiveCIDLimit
	var next quicPeerCID
	if switchTo >= 0 {
		next = qc.peerCIDs[switchTo]
	}
	qc.cidMu.Unlock()
	if overLimit {
		qc.closeWithError(quicErrConnIDLimit, "peer issued more connection IDs than active_connection_id_limit")
		return
	}
	if switchTo >= 0 {
		qc.writeMu.Lock()
		qc.dstCIDLen = copy(qc.dstConnID[:], next.cid[:next.cidLen])
		qc.dstCIDSeq = next.seq
		qc.writeMu.Unlock()
	}
	if len(frames) > 0 {
		qc.sendFrames(quicSpaceAppData, frames, true)
	}
}
