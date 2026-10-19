//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

func benchTLSEpollFixDecrypt(b *testing.B, recordSize, records int) {
	p := newTLSEpollFixPeer(b)
	content := bytes.Repeat([]byte{'r'}, recordSize)
	var wire []byte
	for i := 0; i < records; i++ {
		wire = append(wire, p.record(content, tlsRecAppData)...)
	}
	p.conn.readBuf = make([]byte, 0, len(wire))
	p.conn.appBuf = make([]byte, 0, recordSize*records)
	b.SetBytes(int64(len(wire)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.conn.readBuf = append(p.conn.readBuf[:0], wire...)
		p.conn.readN = len(wire)
		p.conn.appReader.seq = 0
		p.conn.appBuf = p.conn.appBuf[:0]
		for p.conn.readN > 0 {
			if _, gotData := p.decrypt(); !gotData {
				b.Fatal("decrypt made no progress")
			}
		}
		if len(p.conn.appBuf) != recordSize*records {
			b.Fatalf("decrypted %d bytes, want %d", len(p.conn.appBuf), recordSize*records)
		}
	}
}

func BenchmarkTLSEpollFixDecryptRequest512(b *testing.B) { benchTLSEpollFixDecrypt(b, 512, 1) }

func BenchmarkTLSEpollFixDecryptBody64K(b *testing.B) {
	benchTLSEpollFixDecrypt(b, MaxRecordPayload, 4)
}

func BenchmarkTLSEpollFixDecryptTinyRecords1000(b *testing.B) { benchTLSEpollFixDecrypt(b, 1, 1000) }
