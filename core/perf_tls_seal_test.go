//go:build linux && amd64

package core

import (
	"bytes"
	"strconv"
	"testing"
)

type perfSealShape struct {
	records      int
	wireBytes    int
	firstRecord  int
	sealBatches  int
	largestBatch int
}

func (s *perfSealShape) observe(wire []byte) {
	if len(wire) == 0 {
		return
	}
	s.sealBatches++
	s.wireBytes += len(wire)
	s.largestBatch = max(s.largestBatch, len(wire))
	for len(wire) >= tlsRecordHeaderLen {
		recLen := tlsRecordHeaderLen + (int(wire[3])<<8 | int(wire[4]))
		if s.records == 0 {
			s.firstRecord = recLen
		}
		s.records++
		wire = wire[min(recLen, len(wire)):]
	}
}

func (s *perfSealShape) report(b *testing.B) {
	b.ReportMetric(float64(s.records), "records/op")
	b.ReportMetric(float64(s.wireBytes), "wire-B/op")
	b.ReportMetric(float64(s.firstRecord), "rec0-B")
	b.ReportMetric(float64(s.sealBatches), "batches/op")
	b.ReportMetric(float64(s.largestBatch), "maxbatch-B")
}

func perfTLSSealConn(tb testing.TB, tls12 bool) *epollConn {
	c := &epollConn{tls: true, worker: &epollWorker{}}
	if tls12 {
		w, _ := newTestTLS12Pair(tb)
		c.tls12 = &tls12State{writer: w}
	} else {
		c.appWriter = newTestTrafficAEAD(tb)
	}
	c.plainBuf = acquireIOBuf()
	c.writeBuf = acquireIOBuf()
	return c
}

func perfTLSEmitAndDrain(c *epollConn, shape *perfSealShape) {
	w := c.worker
	if c.h1LargeBody() {
		c.h1StartProgressiveBody(w, true)
	} else {
		c.h1WriteResponse(true)
	}
	for {
		if shape != nil {
			shape.observe(c.writeBuf[c.writeSent:])
		}
		c.writeBuf = c.writeBuf[:0]
		c.writeSent = 0
		if !c.h1PumpOut(w) {
			break
		}
	}
	c.h1ResumeDue = false
	c.dispatching = false
	c.flushQueued = false
	w.flushList = w.flushList[:0]
}

type perfTLSRespCase struct {
	size          int
	tls12         bool
	cycleWriteBuf bool
	borrowedBody  bool
}

func perfTLSPrepareResponse(c *epollConn, tc perfTLSRespCase, req *Request, body []byte, bodyText string) {
	c.resp.resetFastH1()
	c.resp.lazyReq = req
	if tc.borrowedBody {
		c.resp.Status(200).String(bodyText)
	} else {
		c.resp.Status(200).Bytes(body)
	}
	if tc.cycleWriteBuf {
		releaseIOBuf(c.writeBuf)
		c.writeBuf = acquireIOBuf()
	}
}

func perfTLSH1Response(b *testing.B, tc perfTLSRespCase) {
	c := perfTLSSealConn(b, tc.tls12)
	body := bytes.Repeat([]byte{'r'}, tc.size)
	bodyText := string(body)
	req := &Request{Method: "GET"}
	var shape perfSealShape
	perfTLSPrepareResponse(c, tc, req, body, bodyText)
	perfTLSEmitAndDrain(c, &shape)
	b.SetBytes(int64(tc.size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		perfTLSPrepareResponse(c, tc, req, body, bodyText)
		perfTLSEmitAndDrain(c, nil)
	}
	b.StopTimer()
	shape.report(b)
}

func BenchmarkPerfTLS13H1Resp64K(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 64 << 10})
}

func BenchmarkPerfTLS13H1Resp64KBufCycle(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 64 << 10, cycleWriteBuf: true})
}

func BenchmarkPerfTLS13H1Resp64KBorrowed(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 64 << 10, borrowedBody: true})
}

func BenchmarkPerfTLS13H1Resp1M(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 1 << 20})
}

func BenchmarkPerfTLS13H1Resp1MBufCycle(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 1 << 20, cycleWriteBuf: true})
}

func BenchmarkPerfTLS13H1Resp1MBorrowed(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 1 << 20, borrowedBody: true})
}

func BenchmarkPerfTLS12H1Resp64K(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 64 << 10, tls12: true})
}

func BenchmarkPerfTLS12H1Resp64KBufCycle(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 64 << 10, tls12: true, cycleWriteBuf: true})
}

func BenchmarkPerfTLS12H1Resp64KBorrowed(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 64 << 10, tls12: true, borrowedBody: true})
}

func BenchmarkPerfTLS12H1Resp1M(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 1 << 20, tls12: true})
}

func BenchmarkPerfTLS12H1Resp1MBufCycle(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 1 << 20, tls12: true, cycleWriteBuf: true})
}

func BenchmarkPerfTLS12H1Resp1MBorrowed(b *testing.B) {
	perfTLSH1Response(b, perfTLSRespCase{size: 1 << 20, tls12: true, borrowedBody: true})
}

func perfTLSSealParts(b *testing.B, size int, tls12 bool) {
	c := perfTLSSealConn(b, tls12)
	head := []byte("HTTP/1.1 200 OK\r\nServer: ALOS\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(size) + "\r\n\r\n")
	body := bytes.Repeat([]byte{'s'}, size)
	var shape perfSealShape
	c.writeBuf = c.sealTLSAppDataParts(c.writeBuf[:0], head, body)
	shape.observe(c.writeBuf)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.writeBuf = c.sealTLSAppDataParts(c.writeBuf[:0], head, body)
	}
	b.StopTimer()
	shape.report(b)
}

func BenchmarkPerfTLS13SealParts64K(b *testing.B) { perfTLSSealParts(b, 64<<10, false) }

func BenchmarkPerfTLS13SealParts1M(b *testing.B) { perfTLSSealParts(b, 1<<20, false) }

func BenchmarkPerfTLS12SealParts64K(b *testing.B) { perfTLSSealParts(b, 64<<10, true) }

func BenchmarkPerfTLS12SealParts1M(b *testing.B) { perfTLSSealParts(b, 1<<20, true) }

func perfTLSSealSmall(b *testing.B, tls12 bool) {
	c := perfTLSSealConn(b, tls12)
	req := &Request{Method: "GET"}
	var shape perfSealShape
	run := func() {
		c.resp.resetFastH1()
		c.resp.lazyReq = req
		c.resp.Status(200).String(perfTLSPlaintextBody)
		c.writeBuf = c.writeBuf[:0]
		c.h1WriteResponse(true)
	}
	run()
	shape.observe(c.writeBuf)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		run()
	}
	b.StopTimer()
	shape.report(b)
}

func BenchmarkPerfTLS13H1RespW1(b *testing.B) { perfTLSSealSmall(b, false) }

func BenchmarkPerfTLS12H1RespW1(b *testing.B) { perfTLSSealSmall(b, true) }
