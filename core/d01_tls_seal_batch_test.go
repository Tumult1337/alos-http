//go:build linux && amd64

package core

import (
	"bytes"
	"strconv"
	"testing"
)

const d01MaxRecordsPerSealBatch = 3

func d01TLSResponseBatches(t *testing.T, tls12 bool, body []byte) ([][]byte, *epollConn, []byte) {
	t.Helper()
	c := perfTLSSealConn(t, tls12)
	c.resp.resetFastH1()
	c.resp.lazyReq = &Request{Method: "GET"}
	c.resp.Status(200).Bytes(body)
	owned := c.resp.bodyBytesUnsafe()
	w := c.worker
	if c.h1LargeBody() {
		c.h1StartProgressiveBody(w, true)
	} else {
		c.h1WriteResponse(true)
	}
	var batches [][]byte
	for {
		if out := c.writeBuf[c.writeSent:]; len(out) > 0 {
			batches = append(batches, bytes.Clone(out))
		}
		if cap(c.writeBuf) > epollIOBufPoolMaxCap {
			t.Fatalf("writeBuf grew to %d bytes, above the %d byte IO pool cap", cap(c.writeBuf), epollIOBufPoolMaxCap)
		}
		c.writeBuf = c.writeBuf[:0]
		c.writeSent = 0
		if !c.h1PumpOut(w) {
			break
		}
	}
	return batches, c, owned
}

func d01SplitRecords(t *testing.T, wire []byte) [][]byte {
	t.Helper()
	var records [][]byte
	for len(wire) > 0 {
		if len(wire) < tlsRecordHeaderLen {
			t.Fatalf("truncated record header: %d bytes left", len(wire))
		}
		n := tlsRecordHeaderLen + (int(wire[3])<<8 | int(wire[4]))
		if wire[0] != 0x17 || n > len(wire) {
			t.Fatalf("malformed application data record: type %#x length %d of %d", wire[0], n, len(wire))
		}
		records = append(records, wire[:n])
		wire = wire[n:]
	}
	return records
}

func d01TLSName(size int, tls12 bool) string {
	if tls12 {
		return strconv.Itoa(size) + "/tls12"
	}
	return strconv.Itoa(size) + "/tls13"
}

func TestD01TLSProgressiveSealBatchesStayAtThreeRecords(t *testing.T) {
	for _, size := range []int{256 << 10, 1 << 20} {
		for _, tls12 := range []bool{false, true} {
			t.Run(d01TLSName(size, tls12), func(t *testing.T) {
				body := bytes.Repeat([]byte("alos-d01-"), size/9+1)[:size]
				batches, c, owned := d01TLSResponseBatches(t, tls12, body)
				minBatches := size / (d01MaxRecordsPerSealBatch * MaxRecordPayload)
				if len(batches) < minBatches {
					t.Fatalf("%d seal batches for %d bytes, want at least %d", len(batches), size, minBatches)
				}
				for i, batch := range batches {
					if n := len(d01SplitRecords(t, batch)); n > d01MaxRecordsPerSealBatch {
						t.Fatalf("batch %d holds %d records, want at most %d", i, n, d01MaxRecordsPerSealBatch)
					}
				}
				if !bytes.Equal(owned, body) {
					t.Fatal("sealing changed the response body bytes")
				}
				if cap(c.resp.body) != 0 {
					t.Fatalf("sent body buffer of capacity %d still held by the response", cap(c.resp.body))
				}
			})
		}
	}
}

func TestD01TLSMidSizeBodyStaysOneShot(t *testing.T) {
	for _, tls12 := range []bool{false, true} {
		t.Run(d01TLSName(40<<10, tls12), func(t *testing.T) {
			body := bytes.Repeat([]byte{'m'}, 40<<10)
			batches, _, _ := d01TLSResponseBatches(t, tls12, body)
			if len(batches) != 1 {
				t.Fatalf("a 40 KiB body produced %d write batches, want the single one-shot batch", len(batches))
			}
		})
	}
}

func TestD01TLSSealBatchesDecryptToResponse(t *testing.T) {
	for _, size := range []int{64 << 10, 256 << 10, 1 << 20} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			body := bytes.Repeat([]byte("seal-batch-"), size/11+1)[:size]
			batches, _, _ := d01TLSResponseBatches(t, false, body)
			reader := newTestTrafficAEAD(t)
			var plain []byte
			for _, batch := range batches {
				for _, rec := range d01SplitRecords(t, batch) {
					pt, err := reader.Decrypt(bytes.Clone(rec[tlsRecordHeaderLen:]))
					if err != nil {
						t.Fatalf("record %d does not open: %v", reader.seq, err)
					}
					if len(pt) == 0 || pt[len(pt)-1] != 0x17 {
						t.Fatalf("record %d inner content type is not application data", reader.seq)
					}
					plain = append(plain, pt[:len(pt)-1]...)
				}
			}
			head, rest, ok := bytes.Cut(plain, []byte("\r\n\r\n"))
			if !ok || !bytes.HasPrefix(head, []byte("HTTP/1.1 200")) {
				t.Fatalf("decrypted stream does not start with a 200 response head: %q", plain[:min(len(plain), 64)])
			}
			if !bytes.Contains(head, []byte("Content-Length: "+strconv.Itoa(size))) {
				t.Fatalf("response head lacks Content-Length %d: %q", size, head)
			}
			if !bytes.Equal(rest, body) {
				t.Fatalf("decrypted body differs from the response body (%d vs %d bytes)", len(rest), len(body))
			}
		})
	}
}

func TestD01TLSLargeBodyIsPooledAndSealedInPlace(t *testing.T) {
	body := bytes.Repeat([]byte{'p'}, 1<<20)
	c := perfTLSSealConn(t, false)
	c.resp.resetFastH1()
	c.resp.Status(200).Bytes(body)
	class := largeBufClassAtLeast(len(body))
	if class < 0 || cap(c.resp.body) != largeBufClassSize(class) {
		t.Fatalf("1 MiB body capacity %d is not a pooled large-buffer class", cap(c.resp.body))
	}
	if !c.resp.ownsBodyBuffer(c.resp.body[:MaxRecordPayload]) {
		t.Fatal("the pooled body must stay eligible for the in-place TLS 1.3 seal")
	}
}
