//go:build linux && amd64

package core

import (
	"crypto/rand"
	"net"
	"net/netip"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicPathChallengeLen       = 8
	quicPathFrameLen           = 1 + quicPathChallengeLen
	quicPathProbeDatagram      = quicMinInitialDatagram
	quicPathValidationPTOs     = 3
	quicMaxPathChallenges      = 3
	quicAEADTagLen             = 16
	quicMinPNLen               = 1
	quicMaxPNLen               = 4
	quicAmplificationFactor    = 3
	quicShortHeaderMaxOverhead = 1 + quicMaxCIDLen + quicMaxPNLen + quicAEADTagLen
)

type quicOffPathBudget struct {
	addr     netip.AddrPort
	received uint64
	sent     uint64
}

func (b *quicOffPathBudget) credit(addr netip.AddrPort, size int) {
	if b.addr != addr {
		*b = quicOffPathBudget{addr: addr}
	}
	b.received += uint64(size)
}

func (b *quicOffPathBudget) remaining() int {
	limit := quicAmplificationFactor * b.received
	if b.sent >= limit {
		return 0
	}
	return int(limit - b.sent)
}

func (b *quicOffPathBudget) allows(size int) bool {
	return b.sent+uint64(size) <= quicAmplificationFactor*b.received
}

type quicPathProbe struct {
	addr       netip.AddrPort
	challenges [quicMaxPathChallenges][quicPathChallengeLen]byte
	sent       int
	lastSent   int64
	deadline   int64
}

func quicIsProbingFrame(frameType uint64) bool {
	switch frameType {
	case quicFramePathChallenge, quicFramePathResponse, quicFrameNewConnID, quicFramePadding:
		return true
	}
	return false
}

func quicAddrPort(addr net.Addr) netip.AddrPort {
	if ua, ok := addr.(*net.UDPAddr); ok && ua != nil {
		ap := ua.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

func quicAppendPathFrame(dst []byte, frameType uint64, data [quicPathChallengeLen]byte) []byte {
	dst = quicAppendVarint(dst, frameType)
	return append(dst, data[:]...)
}

func quicPadProbe(frames []byte, budget, dcidLen int) []byte {
	target := quicPathProbeDatagram - (1 + dcidLen + quicMinPNLen + quicAEADTagLen)
	if budget < quicPathProbeDatagram {
		target = budget - (1 + dcidLen + quicMaxPNLen + quicAEADTagLen)
	}
	if target > len(frames) {
		frames = append(frames, make([]byte, target-len(frames))...)
	}
	return frames
}

func (qc *QUICConn) initPath(addr net.Addr) {
	ap := quicAddrPort(addr)
	qc.pathAddr = ap
	qc.rxPath = ap
	qc.lastValidAddr = ap
}

func (qc *QUICConn) notePacketSource(from netip.AddrPort, size int) {
	qc.rxFrom = from
	qc.rxLen = size
	if !from.IsValid() || from == qc.receivePath() {
		if !qc.addressValidated.Load() {
			qc.bytesReceived.Add(uint64(size))
		}
		return
	}
	qc.writeMu.Lock()
	qc.offPath.credit(from, size)
	qc.writeMu.Unlock()
}

func (qc *QUICConn) creditDiscardedDatagram(from netip.AddrPort, size int) {
	if from == qc.currentPath() {
		if !qc.addressValidated.Load() {
			qc.bytesReceived.Add(uint64(size))
		}
		return
	}
	qc.writeMu.Lock()
	qc.offPath.credit(from, size)
	qc.writeMu.Unlock()
}

func (qc *QUICConn) receivePath() netip.AddrPort {
	if gen := qc.pathGen.Load(); gen != qc.rxPathGen {
		qc.rxPath = qc.currentPath()
		qc.rxPathGen = gen
	}
	return qc.rxPath
}

func (qc *QUICConn) setPathLocked(addr netip.AddrPort) {
	qc.pathAddr = addr
	qc.pathGen.Add(1)
}

func (qc *QUICConn) currentPath() netip.AddrPort {
	qc.pathMu.Lock()
	addr := qc.pathAddr
	qc.pathMu.Unlock()
	return addr
}

func (qc *QUICConn) ampBudgetLocked() int {
	if qc.addressValidated.Load() {
		return quicPathProbeDatagram
	}
	limit := quicAmplificationFactor * qc.bytesReceived.Load()
	sent := qc.bytesSent.Load()
	if sent >= limit {
		return 0
	}
	return int(limit - sent)
}

func (qc *QUICConn) observePacketPath(pn uint64) {
	if qc.rxFrom == qc.rxPath && qc.pathGen.Load() == qc.rxPathGen {
		return
	}
	qc.observeNewPath(pn)
}

func (qc *QUICConn) observeNewPath(pn uint64) {
	from := qc.rxFrom
	if !from.IsValid() || !qc.handshakeDone.Load() || !qc.rxNonProbing || qc.closed.Load() {
		return
	}
	if from == qc.receivePath() || int64(pn) != qc.recvLargest[quicSpaceAppData] {
		return
	}
	qc.migrateTo(from)
}

func (qc *QUICConn) setSendPathLocked(addr netip.AddrPort) {
	udp := net.UDPAddrFromAddrPort(addr)
	if qc.uringUDP != nil {
		qc.udpAddr = udp
	}
	qc.remoteAddr = udp
}

func (qc *QUICConn) migrateTo(from netip.AddrPort) {
	qc.pathMu.Lock()
	returning := from == qc.lastValidAddr
	qc.setPathLocked(from)
	qc.pathMu.Unlock()

	qc.writeMu.Lock()
	qc.setSendPathLocked(from)
	switch {
	case returning:
		qc.addressValidated.Store(true)
	case qc.offPath.addr == from:
		qc.addressValidated.Store(false)
		qc.bytesSent.Store(qc.offPath.sent)
		qc.bytesReceived.Store(qc.offPath.received)
	default:
		qc.addressValidated.Store(false)
		qc.bytesSent.Store(0)
		qc.bytesReceived.Store(uint64(qc.rxLen))
	}
	qc.offPath = quicOffPathBudget{}
	qc.writeMu.Unlock()

	if returning {
		qc.pathMu.Lock()
		qc.probing.Store(false)
		qc.pathMu.Unlock()
		return
	}
	qc.useFreshPeerCID()
	qc.startPathProbe(from)
}

func (qc *QUICConn) startPathProbe(addr netip.AddrPort) {
	now := turbo.Now()
	qc.writeMu.Lock()
	pto := qc.loss.ptoTimeout()
	qc.writeMu.Unlock()
	timeout := quicPathValidationPTOs * max(pto, quicInitialRTT*2)
	qc.pathMu.Lock()
	qc.probe = quicPathProbe{addr: addr, deadline: now + int64(timeout)}
	qc.probing.Store(true)
	qc.pathMu.Unlock()
	qc.sendPathChallenge()
}

func (qc *QUICConn) sendPathChallenge() {
	var data [quicPathChallengeLen]byte
	rand.Read(data[:])
	qc.pathMu.Lock()
	if !qc.probing.Load() {
		qc.pathMu.Unlock()
		return
	}
	qc.probe.challenges[qc.probe.sent%quicMaxPathChallenges] = data
	qc.probe.sent++
	qc.probe.lastSent = turbo.Now()
	qc.pathMu.Unlock()

	qc.writeMu.Lock()
	frames := quicPadProbe(quicAppendPathFrame(nil, quicFramePathChallenge, data), qc.ampBudgetLocked()-len(qc.pendingAck[quicSpaceAppData]), qc.dstCIDLen)
	qc.sendFramesToLocked(quicSpaceAppData, frames, false, nil)
	qc.writeMu.Unlock()
}

func (qc *QUICConn) handlePathChallenge(data [quicPathChallengeLen]byte) {
	qc.pathResponses = quicAppendPathFrame(qc.pathResponses, quicFramePathResponse, data)
}

func (qc *QUICConn) flushPathResponses() {
	responses := qc.pathResponses
	if len(responses) == 0 {
		return
	}
	qc.pathResponses = responses[:0]
	from := qc.rxFrom
	qc.writeMu.Lock()
	defer qc.writeMu.Unlock()
	chunkLen := qc.pktBudget - qc.pktBudget%quicPathFrameLen
	onPath := !from.IsValid() || from == qc.currentPath()
	for len(responses) > 0 {
		chunk := responses[:min(len(responses), chunkLen)]
		responses = responses[len(chunk):]
		if onPath {
			qc.sendFramesToLocked(quicSpaceAppData, quicPadProbe(chunk, qc.ampBudgetLocked()-len(qc.pendingAck[quicSpaceAppData]), qc.dstCIDLen), false, nil)
			continue
		}
		qc.sendFramesToLocked(quicSpaceAppData, quicPadProbe(chunk, qc.offPath.remaining(), qc.dstCIDLen), false, &qc.offPath)
	}
}

func (qc *QUICConn) handlePathResponse(data [quicPathChallengeLen]byte) {
	qc.pathMu.Lock()
	if !qc.probing.Load() {
		qc.pathMu.Unlock()
		return
	}
	matched := false
	for i := 0; i < min(qc.probe.sent, quicMaxPathChallenges); i++ {
		if qc.probe.challenges[i] == data {
			matched = true
			break
		}
	}
	if !matched {
		qc.pathMu.Unlock()
		return
	}
	addr := qc.probe.addr
	qc.probing.Store(false)
	qc.lastValidAddr = addr
	onPath := qc.pathAddr == addr
	qc.pathMu.Unlock()
	if !onPath {
		return
	}
	qc.writeMu.Lock()
	qc.addressValidated.Store(true)
	qc.loss.resetForNewPath()
	qc.writeMu.Unlock()
	qc.sendNewToken()
}

func (qc *QUICConn) checkPathProbe() {
	if !qc.probing.Load() {
		return
	}
	now := turbo.Now()
	qc.writeMu.Lock()
	pto := qc.loss.ptoTimeout()
	qc.writeMu.Unlock()
	qc.pathMu.Lock()
	if !qc.probing.Load() {
		qc.pathMu.Unlock()
		return
	}
	expired := now >= qc.probe.deadline
	addr := qc.probe.addr
	resend := !expired && time.Duration(now-qc.probe.lastSent) >= pto
	var fallback netip.AddrPort
	revert := false
	if expired {
		qc.probing.Store(false)
		if qc.pathAddr == addr {
			fallback = qc.lastValidAddr
			revert = true
			qc.setPathLocked(fallback)
		}
	}
	qc.pathMu.Unlock()

	switch {
	case revert && fallback.IsValid() && fallback != addr:
		qc.writeMu.Lock()
		qc.setSendPathLocked(fallback)
		qc.addressValidated.Store(true)
		qc.writeMu.Unlock()
	case revert:
		qc.close()
	case resend:
		qc.sendPathChallenge()
	}
}

func (qc *QUICConn) useFreshPeerCID() {
	qc.cidMu.Lock()
	pick := -1
	for i := range qc.peerCIDs {
		if qc.peerCIDs[i].seq == qc.dstCIDSeq {
			continue
		}
		if pick < 0 || qc.peerCIDs[i].seq < qc.peerCIDs[pick].seq {
			pick = i
		}
	}
	if pick < 0 {
		qc.cidMu.Unlock()
		return
	}
	next := qc.peerCIDs[pick]
	oldSeq := qc.dstCIDSeq
	kept := qc.peerCIDs[:0]
	for _, p := range qc.peerCIDs {
		if p.seq != oldSeq {
			kept = append(kept, p)
		}
	}
	qc.peerCIDs = kept
	qc.cidMu.Unlock()

	qc.writeMu.Lock()
	qc.dstCIDLen = copy(qc.dstConnID[:], next.cid[:next.cidLen])
	qc.dstCIDSeq = next.seq
	qc.writeMu.Unlock()
	qc.sendFrames(quicSpaceAppData, quicAppendRetireConnIDFrame(nil, oldSeq), true)
}
