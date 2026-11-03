//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

const perfTLSLockRuns = 20

func perfTLSRequireZeroAllocs(t *testing.T, name string, fn func()) {
	t.Helper()
	fn()
	if got := testing.AllocsPerRun(perfTLSLockRuns, fn); got != 0 {
		t.Fatalf("%s allocated %.1f times per call, want 0", name, got)
	}
}

func perfTLSSkipUnderRace(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
}

func TestPerfTLSLockH1ResponseZeroAlloc(t *testing.T) {
	perfTLSSkipUnderRace(t)
	for _, tls12 := range []bool{false, true} {
		for _, size := range []int{len(perfTLSPlaintextBody), 16 << 10, 64 << 10, 1 << 20} {
			tc := perfTLSRespCase{size: size, tls12: tls12, borrowedBody: true}
			c := perfTLSSealConn(t, tls12)
			body := bytes.Repeat([]byte{'z'}, size)
			bodyText := string(body)
			req := &Request{Method: "GET"}
			var shape perfSealShape
			perfTLSPrepareResponse(c, tc, req, body, bodyText)
			perfTLSEmitAndDrain(c, &shape)
			if shape.wireBytes <= size {
				t.Fatalf("tls12=%v size=%d: emitted %d wire bytes", tls12, size, shape.wireBytes)
			}
			perfTLSRequireZeroAllocs(t, "TLS H1 response emit", func() {
				perfTLSPrepareResponse(c, tc, req, body, bodyText)
				perfTLSEmitAndDrain(c, nil)
			})
		}
	}
}

func TestPerfTLSLockSealPartsZeroAlloc(t *testing.T) {
	perfTLSSkipUnderRace(t)
	head := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	for _, tls12 := range []bool{false, true} {
		for _, size := range []int{16 << 10, 64 << 10, 1 << 20} {
			c := perfTLSSealConn(t, tls12)
			body := bytes.Repeat([]byte{'p'}, size)
			perfTLSRequireZeroAllocs(t, "sealTLSAppDataParts", func() {
				c.writeBuf = c.sealTLSAppDataParts(c.writeBuf[:0], head, body)
			})
		}
	}
}

func TestPerfTLSLockRecordAEADZeroAlloc(t *testing.T) {
	perfTLSSkipUnderRace(t)
	for _, size := range []int{64, 512, MaxRecordPayload - 1} {
		w, r := newTestTrafficAEAD(t), newTestTrafficAEAD(t)
		msg := bytes.Repeat([]byte{'a'}, size)
		sealed := make([]byte, 0, size+64)
		opened := make([]byte, size+64)
		perfTLSRequireZeroAllocs(t, "TrafficAEAD seal+open", func() {
			sealed = w.EncryptAppend(sealed[:0], msg)
			n := copy(opened, sealed)
			if _, err := r.Decrypt(opened[:n]); err != nil {
				t.Fatal(err)
			}
		})
		w12, r12 := newTestTLS12Pair(t)
		perfTLSRequireZeroAllocs(t, "tls12AEAD seal+open", func() {
			sealed = w12.sealTo(sealed[:0], tlsRecAppData, msg)
			n := copy(opened, sealed)
			if _, _, ok := r12.open(opened[:n]); !ok {
				t.Fatal("tls12 open failed")
			}
		})
	}
}

func TestPerfTLSLockDecryptToAppZeroAlloc(t *testing.T) {
	perfTLSSkipUnderRace(t)
	request := []byte("GET /plaintext HTTP/1.1\r\nHost: harness.test\r\n\r\n")
	p := newTLSEpollFixPeer(t)
	wire13 := p.record(request, tlsRecAppData)
	client12, server12 := tlsEpollFixTLS12Pair(t)
	wire12 := client12.sealTo(nil, tlsRecAppData, request)
	for _, tls12 := range []bool{false, true} {
		c := p.conn
		wire := wire13
		if tls12 {
			c.tls12 = &tls12State{reader: server12}
			wire = wire12
		}
		c.readBuf = make([]byte, 0, len(wire))
		perfTLSRequireZeroAllocs(t, "epollTLSDecryptToApp", func() {
			c.readBuf = append(c.readBuf[:0], wire...)
			c.readN = len(wire)
			c.cipherOff = 0
			c.appReader.seq = 0
			server12.seq = 0
			c.appBuf = c.appBuf[:0]
			if _, gotData := p.decrypt(); !gotData || !bytes.Equal(c.appBuf, request) {
				t.Fatalf("tls12=%v: decrypted %q", tls12, c.appBuf)
			}
		})
	}
}
