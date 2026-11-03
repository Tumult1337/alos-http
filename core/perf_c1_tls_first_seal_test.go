//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

func TestC1TLSLargeBodyFirstBatchIsShort(t *testing.T) {
	for _, size := range []int{64 << 10, 1 << 20} {
		for _, tls12 := range []bool{false, true} {
			t.Run(d01TLSName(size, tls12), func(t *testing.T) {
				body := bytes.Repeat([]byte("first-seal-"), size/11+1)[:size]
				batches, _, owned := d01TLSResponseBatches(t, tls12, body)
				if len(batches) < 2 {
					t.Fatalf("%d byte body produced %d write batches, want the progressive path", size, len(batches))
				}
				if n := len(d01SplitRecords(t, batches[0])); n != tlsFirstSealRecords {
					t.Fatalf("first write batch holds %d records, want %d", n, tlsFirstSealRecords)
				}
				for i, batch := range batches[1:] {
					if n := len(d01SplitRecords(t, batch)); n > tlsSealBatchRecords {
						t.Fatalf("batch %d holds %d records, want at most %d", i+1, n, tlsSealBatchRecords)
					}
				}
				if !bytes.Equal(owned, body) {
					t.Fatal("sealing changed the response body bytes")
				}
			})
		}
	}
}

func TestC1TLSBodyAtOneShotLimitStaysOneShot(t *testing.T) {
	for _, tls12 := range []bool{false, true} {
		c := perfTLSSealConn(t, tls12)
		limit := c.tlsOneShotBodyMax()
		t.Run(d01TLSName(limit, tls12), func(t *testing.T) {
			batches, _, _ := d01TLSResponseBatches(t, tls12, bytes.Repeat([]byte{'o'}, limit))
			if len(batches) != 1 {
				t.Fatalf("a %d byte body produced %d write batches, want the single one-shot batch", limit, len(batches))
			}
		})
	}
}
