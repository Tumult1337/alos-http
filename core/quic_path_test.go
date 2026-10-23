//go:build linux && amd64

package core

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

var (
	pathA = netip.MustParseAddrPort("127.0.0.1:50000")
	pathB = netip.MustParseAddrPort("127.0.0.1:50999")
	pathC = netip.MustParseAddrPort("10.9.8.7:4433")
)

func (p *quicTestPeer) sendFrom(from netip.AddrPort, size int, frames []byte) {
	p.t.Helper()
	pn := p.pn
	p.qc.notePacketSource(from, size)
	p.qc.processFrames(quicSpaceAppData, pn, frames)
	p.qc.observePacketPath(pn)
	p.pn++
}

func (p *quicTestPeer) packetsTo(addr netip.AddrPort) []quicSentPacketView {
	var out []quicSentPacketView
	for _, v := range p.packets() {
		if v.to == addr.String() {
			out = append(out, v)
		}
	}
	return out
}

func pathChallengeFrame(data [quicPathChallengeLen]byte) []byte {
	return quicAppendPathFrame(nil, quicFramePathChallenge, data)
}

func pathResponseFrame(data [quicPathChallengeLen]byte) []byte {
	return quicAppendPathFrame(nil, quicFramePathResponse, data)
}

func probeOnly(frame []byte) []byte {
	return append(frame, make([]byte, 1100)...)
}

func (p *quicTestPeer) lastChallengeTo(addr netip.AddrPort) [quicPathChallengeLen]byte {
	p.t.Helper()
	for _, v := range p.packetsTo(addr) {
		if n := len(v.frames.challenges); n > 0 {
			return v.frames.challenges[n-1]
		}
	}
	p.t.Fatalf("no PATH_CHALLENGE sent to %v", addr)
	return [quicPathChallengeLen]byte{}
}

func TestQUICPathChallengeAnsweredOnCurrentPath(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	data := [quicPathChallengeLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	p.sendFrom(pathA, 1200, probeOnly(pathChallengeFrame(data)))
	sent := p.packetsTo(pathA)
	if len(sent) != 1 || len(sent[0].frames.responses) != 1 || sent[0].frames.responses[0] != data {
		t.Fatalf("PATH_RESPONSE on the current path: %+v", sent)
	}
	if sent[0].size < quicPathProbeDatagram {
		t.Fatalf("PATH_RESPONSE datagram %d bytes, want at least %d", sent[0].size, quicPathProbeDatagram)
	}
}

func TestQUICProbeFromNewAddressIsAnsweredWithoutMigrating(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	data := [quicPathChallengeLen]byte{9, 9, 9, 9, 1, 1, 1, 1}
	p.sendFrom(pathB, 1200, probeOnly(pathChallengeFrame(data)))
	sent := p.packetsTo(pathB)
	if len(sent) != 1 || len(sent[0].frames.responses) != 1 || sent[0].frames.responses[0] != data {
		t.Fatalf("PATH_RESPONSE to the probing address: %+v", sent)
	}
	if sent[0].size < quicPathProbeDatagram || sent[0].size > 3*1200 {
		t.Fatalf("PATH_RESPONSE datagram %d bytes", sent[0].size)
	}
	if p.qc.currentPath() != pathA || !p.qc.addressValidated.Load() || p.qc.probing.Load() {
		t.Fatal("a probe-only packet migrated the connection")
	}

	small := [quicPathChallengeLen]byte{7}
	p.sendFrom(pathC, 60, pathChallengeFrame(small))
	toC := p.packetsTo(pathC)
	if len(toC) != 1 || toC[0].size > 3*60 {
		t.Fatalf("PATH_RESPONSE to an unvalidated address broke the 3x limit: %d packets, %d bytes", len(toC), toC[0].size)
	}
}

func TestQUICMigrationSwitchesPathAndValidates(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.sendFrom(pathA, 1200, []byte{quicFramePing})
	p.sendFrom(pathB, 1200, []byte{quicFramePing})
	if p.qc.currentPath() != pathB {
		t.Fatalf("current path %v after a non-probing packet from %v", p.qc.currentPath(), pathB)
	}
	if p.qc.addressValidated.Load() || !p.qc.probing.Load() {
		t.Fatal("new path treated as validated before PATH_RESPONSE")
	}
	challenge := p.lastChallengeTo(pathB)
	for _, v := range p.packetsTo(pathB) {
		if len(v.frames.challenges) > 0 && v.size < quicPathProbeDatagram {
			t.Fatalf("PATH_CHALLENGE datagram %d bytes, want at least %d", v.size, quicPathProbeDatagram)
		}
	}

	p.qc.loss.mu.Lock()
	p.qc.loss.cwnd = 99 * quicMaxPacketSize
	p.qc.loss.mu.Unlock()
	p.sendFrom(pathB, 1200, pathResponseFrame([quicPathChallengeLen]byte{0xde, 0xad}))
	if p.qc.addressValidated.Load() {
		t.Fatal("an unrelated PATH_RESPONSE validated the path")
	}
	p.sendFrom(pathB, 1200, pathResponseFrame(challenge))
	if !p.qc.addressValidated.Load() || p.qc.probing.Load() || p.qc.lastValidAddr != pathB {
		t.Fatal("matching PATH_RESPONSE did not validate the new path")
	}
	p.qc.loss.mu.Lock()
	cwnd := p.qc.loss.cwnd
	p.qc.loss.mu.Unlock()
	if cwnd != quicInitialWindow {
		t.Fatalf("congestion window %d after validating a new path, want reset to %d", cwnd, quicInitialWindow)
	}
}

func TestQUICReorderedPacketFromNewAddressDoesNotMigrate(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.pn = 10
	p.sendFrom(pathA, 1200, []byte{quicFramePing})
	p.pn = 5
	p.sendFrom(pathB, 1200, []byte{quicFramePing})
	if p.qc.currentPath() != pathA {
		t.Fatal("a reordered older packet from a new address migrated the connection")
	}
}

func TestQUICNoMigrationBeforeHandshakeConfirmed(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.qc.handshakeDone.Store(false)
	p.sendFrom(pathB, 1200, []byte{quicFramePing})
	if p.qc.currentPath() != pathA {
		t.Fatal("migrated before the handshake was confirmed")
	}
}

func TestQUICFailedValidationRevertsToLastValidatedPath(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.sendFrom(pathB, 1200, []byte{quicFramePing})
	p.qc.pathMu.Lock()
	p.qc.probe.deadline = turbo.Now() - 1
	p.qc.pathMu.Unlock()
	p.qc.checkPathProbe()
	if p.qc.currentPath() != pathA || !p.qc.addressValidated.Load() || p.qc.probing.Load() {
		t.Fatalf("after a failed validation: path %v validated %v", p.qc.currentPath(), p.qc.addressValidated.Load())
	}
	before := len(p.packetsTo(pathA))
	p.qc.sendFrames(quicSpaceAppData, []byte{quicFramePing}, true)
	if len(p.packetsTo(pathA)) != before+1 {
		t.Fatal("packets are not going back to the validated path")
	}
}

func TestQUICFailedValidationWithoutFallbackClosesSilently(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.qc.lastValidAddr = netip.AddrPort{}
	p.sendFrom(pathB, 1200, []byte{quicFramePing})
	p.qc.pathMu.Lock()
	p.qc.probe.deadline = turbo.Now() - 1
	p.qc.pathMu.Unlock()
	p.qc.checkPathProbe()
	if !p.qc.closed.Load() {
		t.Fatal("connection kept running with no validated path")
	}
	if got := p.sent(); len(got.closes) != 0 {
		t.Fatal("silent close sent a CONNECTION_CLOSE")
	}
}

func TestQUICLegitimatePacketUndoesSpuriousMigration(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.sendFrom(pathB, 1200, []byte{quicFramePing})
	p.sendFrom(pathA, 1200, []byte{quicFramePing})
	if p.qc.currentPath() != pathA || !p.qc.addressValidated.Load() || p.qc.probing.Load() {
		t.Fatal("a packet from the last validated address did not restore it without validation")
	}
}

func TestQUICChallengeRetransmittedEachPTO(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.sendFrom(pathB, 1200, []byte{quicFramePing})
	first := p.lastChallengeTo(pathB)
	p.qc.writeMu.Lock()
	pto := p.qc.loss.ptoTimeout()
	p.qc.writeMu.Unlock()
	p.qc.pathMu.Lock()
	p.qc.probe.lastSent = turbo.Now() - int64(10*pto)
	p.qc.pathMu.Unlock()
	p.qc.checkPathProbe()
	var all [][quicPathChallengeLen]byte
	for _, v := range p.packetsTo(pathB) {
		all = append(all, v.frames.challenges...)
	}
	if len(all) != 2 || all[0] == all[1] {
		t.Fatalf("retransmitted challenges %x, want two distinct", all)
	}
	p.sendFrom(pathB, 1200, pathResponseFrame(first))
	if !p.qc.addressValidated.Load() {
		t.Fatal("a response to the earlier challenge did not validate")
	}
}

func TestQUICMigrationUsesFreshPeerConnectionID(t *testing.T) {
	p := newCIDTestPeer(t, 2)
	p.send(peerNewCID(1, 0, 0x42))
	p.sendFrom(pathB, 1200, []byte{quicFramePing})
	if !bytes.Equal(p.qc.dstCID(), bytes.Repeat([]byte{0x42}, quicConnIDLen)) {
		t.Fatalf("destination CID %x after migration, want the unused peer CID", p.qc.dstCID())
	}
	got := p.sent()
	if len(got.retires) != 1 || got.retires[0] != 0 {
		t.Fatalf("retired %v, want the old sequence 0", got.retires)
	}
}

func TestQUICUnvalidatedPathHonoursAmplificationLimit(t *testing.T) {
	c := &countingRoutes{}
	p := newQUICTestPeer(t, func(r *Router) {
		c.route(r)
		r.GET("/big", func(req *Request, resp *Response) { resp.Status(200).Bytes(bytes.Repeat([]byte("z"), 60<<10)) })
	})
	const trigger = 200
	p.sendFrom(pathB, trigger, quicStreamBytes(0, 0, h3TestRequest("/big"), true))
	if p.qc.currentPath() != pathB {
		t.Fatal("request from a new address did not migrate")
	}
	turbo.Sleep(150 * time.Millisecond)
	total := 0
	for _, v := range p.packetsTo(pathB) {
		total += v.size
	}
	if total > 3*trigger {
		t.Fatalf("sent %d bytes to an unvalidated address after receiving %d", total, trigger)
	}
	challenge := p.lastChallengeTo(pathB)
	p.sendFrom(pathB, 1200, pathResponseFrame(challenge))
	for i := 0; i < 400 && (p.finCountTo(pathB) == 0 || p.streamBytesTo(pathB, 0) < 60<<10); i++ {
		p.ackAllFrom(pathB)
		p.qc.writeMu.Lock()
		p.qc.drainCoalescedLocked()
		p.qc.writeMu.Unlock()
		for _, frames := range p.qc.loss.ptoExpiredFrames(quicSpaceAppData, 0) {
			p.qc.sendFrames(quicSpaceAppData, frames, true)
		}
		turbo.Sleep(5 * time.Millisecond)
	}
	if p.finCountTo(pathB) == 0 {
		t.Fatal("response never completed on the validated new path")
	}
	if body := p.streamBytesTo(pathB, 0); body < 60<<10 {
		t.Fatalf("delivered %d response bytes, want at least %d", body, 60<<10)
	}
}

func (p *quicTestPeer) streamBytesTo(addr netip.AddrPort, streamID uint64) int {
	body := 0
	for _, v := range p.packetsTo(addr) {
		for _, s := range v.frames.streams {
			if s.streamID == streamID {
				body += len(s.data)
			}
		}
	}
	return body
}

func (p *quicTestPeer) finCountTo(addr netip.AddrPort) int {
	n := 0
	for _, v := range p.packetsTo(addr) {
		for _, s := range v.frames.streams {
			if s.fin && s.streamID == 0 {
				n++
			}
		}
	}
	return n
}

func receivedRanges(pns []uint64) []pnRange {
	sorted := slices.Clone(pns)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	var ranges []pnRange
	for i := len(sorted) - 1; i >= 0; i-- {
		if n := len(ranges); n > 0 && ranges[n-1].lo == sorted[i]+1 {
			ranges[n-1].lo = sorted[i]
			continue
		}
		ranges = append(ranges, pnRange{lo: sorted[i], hi: sorted[i]})
	}
	return ranges
}

func (p *quicTestPeer) ackAllFrom(addr netip.AddrPort) {
	got := p.sent()
	if len(got.pns) == 0 {
		return
	}
	p.sendFrom(addr, 60, quicAppendACKFrameRanges(nil, 0, receivedRanges(got.pns)))
}
