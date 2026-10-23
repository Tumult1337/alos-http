//go:build linux && amd64

package core

import (
	"math"
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

	ls.ptoCount = 0
	sent := ls.sent[space]
	return len(sent) > 0 && int64(sent[0].pn) <= ls.largestAcked[space], nil
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

func (ls *quicLossState) markAcked(space int, lo, hi uint64, tally *quicAckTally) {
	remaining := ls.sent[space][:0]
	for i := range ls.sent[space] {
		sp := &ls.sent[space][i]
		if sp.pn >= lo && sp.pn <= hi {
			if sp.inFlight {
				ls.bytesInFlight -= sp.size
				tally.ackedInFlight += uint64(sp.size)
			}
			if sp.pn == tally.largest {
				tally.largestSent = sp.sent
				tally.largestTracked = true
			}
			tally.anyAcked = true
			if sp.framesBuf != nil {
				quicFramePool.Put(sp.framesBuf)
			}
		} else {
			remaining = append(remaining, *sp)
		}
	}
	ls.sent[space] = remaining
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
	remaining := ls.sent[space][:0]
	for i := range ls.sent[space] {
		sp := &ls.sent[space][i]
		lost := int64(sp.pn) <= ls.largestAcked[space] && (sp.pn < threshold || sp.sent < cutoff)
		if lost {
			if sp.inFlight {
				ls.bytesInFlight -= sp.size
				hadLoss = true
			}
			if len(sp.frames) > 0 {
				fcopy := make([]byte, len(sp.frames))
				copy(fcopy, sp.frames)
				lostFrames = append(lostFrames, fcopy)
			}
			if sp.framesBuf != nil {
				quicFramePool.Put(sp.framesBuf)
			}
		} else {
			remaining = append(remaining, *sp)
		}
	}
	ls.sent[space] = remaining

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
	if now-lastSent < int64(ls.ptoTimeout()) {
		return false
	}
	ls.ptoCount++
	return true
}

func (ls *quicLossState) hasSentPackets(space int) bool {
	ls.mu.Lock()
	n := len(ls.sent[space])
	ls.mu.Unlock()
	return n > 0
}

func (ls *quicLossState) canSend() bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return uint64(ls.bytesInFlight) < ls.cwnd && len(ls.sent[quicSpaceAppData]) < quicMaxTrackedSent
}

func (ls *quicLossState) sendRoom() int {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if len(ls.sent[quicSpaceAppData]) >= quicMaxTrackedSent {
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
	if len(ls.sent[space]) == 0 {
		return nil
	}
	pto := ls.ptoTimeout()
	cutoff := turbo.Now() - int64(pto)
	if ls.sent[space][0].sent >= cutoff {
		return nil
	}

	var frames [][]byte
	remaining := ls.sent[space][:0]
	for i := range ls.sent[space] {
		sp := &ls.sent[space][i]
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
