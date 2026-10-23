//go:build linux && amd64

package core

import (
	"cmp"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicInitialRTT       = 100 * time.Millisecond
	quicMaxAckDelay      = 25 * time.Millisecond
	quicTimerGranularity = time.Millisecond
	quicPktThreshold     = 3
	quicTimeThreshold    = 9.0 / 8.0
	quicMaxTrackedSent   = 16384
)

const quicSendTimeLogEntries = 128

type quicSendTime struct {
	pn uint64
	at int64
}

type quicSendTimeLog struct {
	entries [quicSendTimeLogEntries]quicSendTime
	written uint64
	lastAt  int64
}

func (l *quicSendTimeLog) record(pn uint64, at int64) {
	if at == l.lastAt {
		return
	}
	l.lastAt = at
	l.entries[l.written%quicSendTimeLogEntries] = quicSendTime{pn: pn, at: at}
	l.written++
}

func (l *quicSendTimeLog) sentAt(pn uint64) (int64, bool) {
	oldest := l.written - min(l.written, quicSendTimeLogEntries)
	for i := l.written; i > oldest; i-- {
		if e := &l.entries[(i-1)%quicSendTimeLogEntries]; e.pn <= pn {
			return e.at, true
		}
	}
	return 0, false
}

type quicAckTally struct {
	largest        uint64
	largestSent    int64
	ackedInFlight  uint64
	largestTracked bool
	anyAcked       bool
}

type quicSentPacket struct {
	pn        uint64
	sent      int64
	size      int
	ackElicit bool
	frames    []byte
	framesBuf *[]byte
	inFlight  bool
	removed   bool
}

var quicFramePool = sync.Pool{
	New: func() any { b := make([]byte, 0, 256); return &b },
}

type quicLossState struct {
	mu sync.Mutex

	smoothedRTT  time.Duration
	rttVar       time.Duration
	minRTT       time.Duration
	firstRTTDone bool

	largestAcked [3]int64

	sent          [3][]quicSentPacket
	nextLiveIdx   [3][]int32
	removedCount  [3]int
	bytesInFlight int

	cwnd     uint64
	ssthresh uint64

	ptoCount int

	peerMaxAckDelay time.Duration

	appSendTimes quicSendTimeLog
}

func newQuicLossState() *quicLossState {
	ls := &quicLossState{
		smoothedRTT: quicInitialRTT,
		rttVar:      quicInitialRTT / 2,
		minRTT:      0,
		cwnd:        quicInitialWindow,
		ssthresh:    math.MaxUint64,
	}
	ls.largestAcked[0] = -1
	ls.largestAcked[1] = -1
	ls.largestAcked[2] = -1
	ls.peerMaxAckDelay = quicMaxAckDelay
	return ls
}

func (ls *quicLossState) setPeerMaxAckDelay(d time.Duration) {
	ls.mu.Lock()
	ls.peerMaxAckDelay = d
	ls.mu.Unlock()
}

func (ls *quicLossState) onPacketSent(space int, pn uint64, size int, ackElicit bool, frames []byte) {
	now := turbo.Now()
	if space == quicSpaceAppData {
		ls.appSendTimes.record(pn, now)
	}
	if !ackElicit {
		return
	}
	var framesBuf *[]byte
	var stored []byte
	if len(frames) > 0 {
		framesBuf = quicFramePool.Get().(*[]byte)
		*framesBuf = append((*framesBuf)[:0], frames...)
		stored = *framesBuf
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	sp := quicSentPacket{
		pn:        pn,
		sent:      now,
		size:      size,
		ackElicit: ackElicit,
		frames:    stored,
		framesBuf: framesBuf,
		inFlight:  ackElicit,
	}
	ls.sent[space] = append(ls.sent[space], sp)
	ls.nextLiveIdx[space] = append(ls.nextLiveIdx[space], int32(len(ls.sent[space])-1))
	ls.bytesInFlight += size
}

var errQUICAckUnsentPacket = &staticError{"ACK of a packet number that was never sent"}

func (ls *quicLossState) onAckReceived(space int, ack quicAckFrame, ackDelay time.Duration, nextPN uint64) (lossPossible bool, err error) {
	if ack.firstRange > ack.largestAck {
		return false, nil
	}
	if ack.largestAck >= nextPN {
		return false, errQUICAckUnsentPacket
	}

	ls.mu.Lock()
	defer ls.mu.Unlock()

	largest := int64(ack.largestAck)
	newlyLargest := largest > ls.largestAcked[space]
	if newlyLargest {
		ls.largestAcked[space] = largest
	}

	tally := quicAckTally{largest: ack.largestAck}

	lo := ack.largestAck - ack.firstRange
	hi := ack.largestAck
	ls.markAcked(space, lo, hi, &tally)

	for _, r := range ack.ranges {
		if lo < r.gap+2 {
			break
		}
		hi = lo - r.gap - 2
		if hi < r.count {
			break
		}
		lo = hi - r.count
		ls.markAcked(space, lo, hi, &tally)
	}

	if sent, ok := ls.largestAckedSentTime(space, &tally, newlyLargest); ok {
		latestRTT := turbo.Since(sent)
		if latestRTT < quicTimerGranularity {
			latestRTT = quicTimerGranularity
		}
		ls.updateRTT(latestRTT, ackDelay)
	}

	if tally.ackedInFlight > 0 {
		if ls.cwnd < ls.ssthresh {
			ls.cwnd += tally.ackedInFlight
		} else {
			ls.cwnd += quicMaxPacketSize * tally.ackedInFlight / ls.cwnd
		}
	}

	ls.compactIfMostlyRemoved(space)

	ls.ptoCount = 0
	first := ls.nextLive(space, 0)
	return first < len(ls.sent[space]) && int64(ls.sent[space][first].pn) <= ls.largestAcked[space], nil
}

func (ls *quicLossState) discardSpace(space int) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for i := range ls.sent[space] {
		sp := &ls.sent[space][i]
		if sp.inFlight {
			ls.bytesInFlight -= sp.size
		}
		if sp.framesBuf != nil {
			quicFramePool.Put(sp.framesBuf)
		}
	}
	ls.sent[space] = nil
	ls.nextLiveIdx[space] = nil
	ls.removedCount[space] = 0
}

func (ls *quicLossState) detectLostPackets(space int) [][]byte {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.detectLost(space, nil)
}

func (ls *quicLossState) largestAckedSentTime(space int, tally *quicAckTally, newlyLargest bool) (int64, bool) {
	switch {
	case !tally.anyAcked:
		return 0, false
	case tally.largestTracked:
		return tally.largestSent, true
	case newlyLargest && space == quicSpaceAppData:
		return ls.appSendTimes.sentAt(tally.largest)
	default:
		return 0, false
	}
}

func quicComparePN(sp quicSentPacket, pn uint64) int {
	return cmp.Compare(sp.pn, pn)
}

func (ls *quicLossState) markAcked(space int, lo, hi uint64, tally *quicAckTally) {
	sent := ls.sent[space]
	start, _ := slices.BinarySearchFunc(sent, lo, quicComparePN)
	for i := ls.nextLive(space, start); i < len(sent) && sent[i].pn <= hi; i = ls.nextLive(space, i+1) {
		sp := &sent[i]
		if sp.inFlight {
			ls.bytesInFlight -= sp.size
			tally.ackedInFlight += uint64(sp.size)
		}
		if sp.pn == tally.largest {
			tally.largestSent = sp.sent
			tally.largestTracked = true
		}
		tally.anyAcked = true
		ls.removeAt(space, i)
	}
}

func (ls *quicLossState) removeAt(space, i int) {
	sp := &ls.sent[space][i]
	if sp.framesBuf != nil {
		quicFramePool.Put(sp.framesBuf)
	}
	*sp = quicSentPacket{pn: sp.pn, removed: true}
	ls.nextLiveIdx[space][i] = int32(i + 1)
	ls.removedCount[space]++
}

func (ls *quicLossState) compactIfMostlyRemoved(space int) {
	if 2*ls.removedCount[space] > len(ls.sent[space]) {
		ls.dropRemoved(space)
	}
}

func (ls *quicLossState) nextLive(space, i int) int {
	next := ls.nextLiveIdx[space]
	for i < len(next) {
		j := int(next[i])
		if j == i {
			return i
		}
		if j < len(next) {
			next[i] = next[j]
		}
		i = int(next[i])
	}
	return len(next)
}

func (ls *quicLossState) liveSent(space int) int {
	return len(ls.sent[space]) - ls.removedCount[space]
}

func (ls *quicLossState) resetLiveIndex(space int) {
	next := ls.nextLiveIdx[space][:0]
	for i := range ls.sent[space] {
		next = append(next, int32(i))
	}
	ls.nextLiveIdx[space] = next
	ls.removedCount[space] = 0
}

func (ls *quicLossState) dropRemoved(space int) {
	sent := ls.sent[space]
	kept := sent[:0]
	for i := range sent {
		if !sent[i].removed {
			kept = append(kept, sent[i])
		}
	}
	clear(sent[len(kept):])
	ls.sent[space] = kept
	ls.resetLiveIndex(space)
}

func (ls *quicLossState) detectLost(space int, lostFrames [][]byte) [][]byte {
	if ls.largestAcked[space] < 0 {
		return lostFrames
	}
	la := uint64(ls.largestAcked[space])
	var threshold uint64
	if la+1 > quicPktThreshold {
		threshold = la - quicPktThreshold + 1
	}
	lossDelay := time.Duration(float64(max64(ls.smoothedRTT, ls.minRTT)) * quicTimeThreshold)
	if lossDelay < quicTimerGranularity {
		lossDelay = quicTimerGranularity
	}
	cutoff := turbo.Now() - int64(lossDelay)

	hadLoss := false
	sent := ls.sent[space]
	for i := ls.nextLive(space, 0); i < len(sent) && sent[i].pn <= la; i = ls.nextLive(space, i+1) {
		sp := &sent[i]
		if sp.pn >= threshold && sp.sent >= cutoff {
			continue
		}
		if sp.inFlight {
			ls.bytesInFlight -= sp.size
			hadLoss = true
		}
		if len(sp.frames) > 0 {
			lostFrames = append(lostFrames, append([]byte(nil), sp.frames...))
		}
		ls.removeAt(space, i)
	}
	ls.compactIfMostlyRemoved(space)

	if hadLoss {
		ls.ssthresh = ls.cwnd / 2
		if ls.ssthresh < 2*quicMaxPacketSize {
			ls.ssthresh = 2 * quicMaxPacketSize
		}
		ls.cwnd = ls.ssthresh
	}

	return lostFrames
}

func (ls *quicLossState) updateRTT(latestRTT, ackDelay time.Duration) {
	if ls.minRTT == 0 || latestRTT < ls.minRTT {
		ls.minRTT = latestRTT
	}

	if !ls.firstRTTDone {
		ls.smoothedRTT = latestRTT
		ls.rttVar = latestRTT / 2
		ls.firstRTTDone = true
		return
	}

	adjustedRTT := latestRTT
	if latestRTT >= ls.minRTT+ackDelay {
		adjustedRTT = latestRTT - ackDelay
	}

	diff := ls.smoothedRTT - adjustedRTT
	if diff < 0 {
		diff = -diff
	}
	ls.rttVar = (3*ls.rttVar + diff) / 4
	ls.smoothedRTT = (7*ls.smoothedRTT + adjustedRTT) / 8
}

const quicInitialWindow = 10 * quicMaxPacketSize

func (ls *quicLossState) resetForNewPath() {
	ls.mu.Lock()
	ls.smoothedRTT = quicInitialRTT
	ls.rttVar = quicInitialRTT / 2
	ls.minRTT = 0
	ls.firstRTTDone = false
	ls.cwnd = quicInitialWindow
	ls.ssthresh = math.MaxUint64
	ls.ptoCount = 0
	ls.mu.Unlock()
}

func (ls *quicLossState) ptoTimeout() time.Duration {
	pto := ls.smoothedRTT + max64(4*ls.rttVar, quicTimerGranularity) + ls.peerMaxAckDelay
	return pto * time.Duration(1<<uint(ls.ptoCount))
}

func (ls *quicLossState) claimHandshakeResend(lastSent, now int64) bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if now-lastSent < int64(ls.smoothedRTT<<uint(ls.ptoCount)) {
		return false
	}
	ls.ptoCount++
	return true
}

func (ls *quicLossState) hasSentPackets(space int) bool {
	ls.mu.Lock()
	n := ls.liveSent(space)
	ls.mu.Unlock()
	return n > 0
}

func (ls *quicLossState) canSend() bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return uint64(ls.bytesInFlight) < ls.cwnd && ls.liveSent(quicSpaceAppData) < quicMaxTrackedSent
}

func (ls *quicLossState) sendRoom() int {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.liveSent(quicSpaceAppData) >= quicMaxTrackedSent {
		return 0
	}
	return max(int(ls.cwnd)-ls.bytesInFlight, 0)
}

func (ls *quicLossState) largestAckedPN(space int) int64 {
	ls.mu.Lock()
	v := ls.largestAcked[space]
	ls.mu.Unlock()
	return v
}

func (ls *quicLossState) ptoExpiredFrames(space int) [][]byte {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	first := ls.nextLive(space, 0)
	if first == len(ls.sent[space]) {
		return nil
	}
	pto := ls.ptoTimeout()
	cutoff := turbo.Now() - int64(pto)
	if ls.sent[space][first].sent >= cutoff {
		return nil
	}

	var frames [][]byte
	remaining := ls.sent[space][:0]
	for i := range ls.sent[space] {
		sp := &ls.sent[space][i]
		if sp.removed {
			continue
		}
		if sp.ackElicit && sp.sent < cutoff {
			if sp.inFlight {
				ls.bytesInFlight -= sp.size
			}
			if len(sp.frames) > 0 {
				fcopy := make([]byte, len(sp.frames))
				copy(fcopy, sp.frames)
				frames = append(frames, fcopy)
			}
			if sp.framesBuf != nil {
				quicFramePool.Put(sp.framesBuf)
			}
		} else {
			remaining = append(remaining, *sp)
		}
	}
	ls.sent[space] = remaining
	ls.resetLiveIndex(space)
	if len(frames) > 0 {
		ls.ptoCount++
	}
	return frames
}

func max64(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
