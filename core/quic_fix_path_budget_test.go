//go:build linux && amd64

package core

import (
	"net/netip"
	"testing"
)

const quicFixChallengesPerDatagram = 40

func quicFixChallengeBurst(n int) ([]byte, [][quicPathChallengeLen]byte) {
	var frames []byte
	var want [][quicPathChallengeLen]byte
	for i := 0; i < n; i++ {
		data := [quicPathChallengeLen]byte{0xc0, byte(i), byte(i >> 8), 1, 2, 3, 4, 5}
		want = append(want, data)
		frames = append(frames, pathChallengeFrame(data)...)
	}
	return frames, want
}

func quicFixBytesTo(p *quicTestPeer, addr netip.AddrPort) (total int, views []quicSentPacketView) {
	views = p.packetsTo(addr)
	for _, v := range views {
		total += v.size
	}
	return total, views
}

func quicFixEchoedAll(t *testing.T, views []quicSentPacketView, want [][quicPathChallengeLen]byte) {
	t.Helper()
	var got [][quicPathChallengeLen]byte
	for _, v := range views {
		got = append(got, v.frames.responses...)
	}
	if len(got) != len(want) {
		t.Fatalf("%d PATH_RESPONSE frames for %d PATH_CHALLENGE frames", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("PATH_RESPONSE %d echoes %x, want %x", i, got[i], want[i])
		}
	}
}

func TestQUICFixOffPathChallengeBurstStaysWithinAmplificationLimit(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	frames, want := quicFixChallengeBurst(quicFixChallengesPerDatagram)
	const in = 400
	if len(frames) > in {
		t.Fatalf("fixture frames %d bytes do not fit the %d-byte datagram", len(frames), in)
	}
	p.sendFrom(pathC, in, frames)
	out, views := quicFixBytesTo(p, pathC)
	if out > quicAmplificationFactor*in {
		t.Fatalf("server sent %d bytes in %d datagrams to an unvalidated address that sent %d", out, len(views), in)
	}
	if len(views) != 1 {
		t.Fatalf("%d datagrams answer one datagram of PATH_CHALLENGE frames, want 1", len(views))
	}
	quicFixEchoedAll(t, views, want)
	if p.qc.currentPath() != pathA {
		t.Fatal("a probe-only datagram migrated the connection")
	}
}

func TestQUICFixOffPathBudgetIsChargedAcrossDatagrams(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	sizes := []int{400, 100, 100, 100, 100}
	in := 0
	answered := 0
	for i, size := range sizes {
		in += size
		p.sendFrom(pathC, size, pathChallengeFrame([quicPathChallengeLen]byte{0xb0, byte(i)}))
		out, views := quicFixBytesTo(p, pathC)
		if out > quicAmplificationFactor*in {
			t.Fatalf("after %d datagrams (%d bytes) the server sent %d bytes to the unvalidated address", i+1, in, out)
		}
		answered = len(views)
	}
	if answered < 2 {
		t.Fatalf("only %d PATH_RESPONSE datagrams; the budget test needs at least 2", answered)
	}
}

func TestQUICFixOffPathBudgetFollowsTheProbingAddress(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	p.sendFrom(pathC, 1200, make([]byte, 64))
	if len(p.packetsTo(pathC)) != 0 || p.qc.currentPath() != pathA {
		t.Fatal("a PADDING-only datagram drew a reply or migrated the connection")
	}
	p.sendFrom(pathB, 30, pathChallengeFrame([quicPathChallengeLen]byte{0xa2}))
	if out, views := quicFixBytesTo(p, pathB); out > quicAmplificationFactor*30 {
		t.Fatalf("credit earned by %v let the server send %d bytes in %d datagrams to %v after 30 bytes", pathC, out, len(views), pathB)
	}
}

func TestQUICFixChallengeBurstOnCurrentPathIsOneDatagram(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	frames, want := quicFixChallengeBurst(quicFixChallengesPerDatagram)
	p.sendFrom(pathA, 1200, frames)
	views := p.packetsTo(pathA)
	if len(views) != 1 {
		t.Fatalf("%d datagrams answer one datagram of PATH_CHALLENGE frames on the current path, want 1", len(views))
	}
	quicFixEchoedAll(t, views, want)
	if views[0].size < quicPathProbeDatagram {
		t.Fatalf("PATH_RESPONSE datagram %d bytes, want at least %d", views[0].size, quicPathProbeDatagram)
	}
}

func TestQUICFixMigrationKeepsTheOffPathCharge(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	const in = 400
	p.sendFrom(pathB, in, pathChallengeFrame([quicPathChallengeLen]byte{0xd1}))
	p.sendFrom(pathB, in, append(pathChallengeFrame([quicPathChallengeLen]byte{0xd2}), quicFramePing))
	if p.qc.currentPath() != pathB {
		t.Fatalf("current path %v after a non-probing packet from %v", p.qc.currentPath(), pathB)
	}
	out, views := quicFixBytesTo(p, pathB)
	if out > quicAmplificationFactor*2*in {
		t.Fatalf("server sent %d bytes in %d datagrams to %v after receiving %d", out, len(views), pathB, 2*in)
	}
	responses := 0
	for _, v := range views {
		responses += len(v.frames.responses)
	}
	if responses != 2 {
		t.Fatalf("%d PATH_RESPONSE frames sent to %v, want 2", responses, pathB)
	}
}

func TestQUICFixOffPathResponseThatExceedsTheBudgetIsDropped(t *testing.T) {
	p := newQUICTestPeer(t, nil)
	const in = 10
	p.sendFrom(pathC, in, pathChallengeFrame([quicPathChallengeLen]byte{0xe1}))
	if out, views := quicFixBytesTo(p, pathC); out > quicAmplificationFactor*in {
		t.Fatalf("server sent %d bytes in %d datagrams to an unvalidated address that sent %d", out, len(views), in)
	}
	p.sendFrom(pathC, 400, pathChallengeFrame([quicPathChallengeLen]byte{0xe2}))
	if _, views := quicFixBytesTo(p, pathC); len(views) != 1 || len(views[0].frames.responses) != 1 || views[0].frames.responses[0] != [quicPathChallengeLen]byte{0xe2} {
		t.Fatalf("PATH_RESPONSE after the address earned budget: %+v", views)
	}
}
