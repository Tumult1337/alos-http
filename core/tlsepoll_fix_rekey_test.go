//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

func TestTLSEpollFixWriteKeyRenewedBeforeUsageLimit(t *testing.T) {
	p := newTLSEpollFixPeer(t)
	p.conn.appWriter.seq = tls13RecordsPerKeyLimit - 1
	p.clientReader.seq = tls13RecordsPerKeyLimit - 1
	body := bytes.Repeat([]byte{'b'}, 3*MaxRecordPayload)
	p.conn.writeBuf = p.conn.sealTLSAppData(p.conn.writeBuf, []byte("first"))
	p.conn.writeBuf = p.conn.sealTLSAppDataParts(p.conn.writeBuf, []byte("head"), body)
	recs := p.serverRecords(t)
	if len(recs) < 3 || string(recs[0].content) != "first" {
		t.Fatalf("server sent %d records", len(recs))
	}
	if recs[1].innerType != tlsRecHandshake || !bytes.Equal(recs[1].content, []byte{24, 0, 0, 1, 0}) {
		t.Fatalf("record after the limit has inner type %d and %d bytes, want KeyUpdate(update_not_requested)", recs[1].innerType, len(recs[1].content))
	}
	var got []byte
	for _, r := range recs[2:] {
		got = append(got, r.content...)
	}
	if !bytes.Equal(got, append([]byte("head"), body...)) {
		t.Fatalf("data sealed under the renewed key did not round-trip (%d bytes)", len(got))
	}
	if p.conn.appWriter.seq >= tls13RecordsPerKeyLimit {
		t.Fatalf("write key not renewed: seq=%d", p.conn.appWriter.seq)
	}
}

func TestTLSEpollFixKeyUpdateFloodIsBounded(t *testing.T) {
	p := newTLSEpollFixPeer(t)
	var wire []byte
	for i := 0; i <= tlsMaxUselessRecords; i++ {
		wire = append(wire, p.record([]byte{24, 0, 0, 1, 1}, tlsRecHandshake)...)
		p.advanceClientWriter(t)
	}
	p.feed(wire)
	action, _ := p.decrypt()
	if action != epollActionCloseAfterFlush || !p.conn.tlsAlertSent {
		t.Fatalf("%d back-to-back KeyUpdates accepted: action=%d", tlsMaxUselessRecords+1, action)
	}
}
