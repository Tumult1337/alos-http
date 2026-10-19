//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

func TestTLSEpollFixDecryptDrainsBufferedRecordsInOneBatch(t *testing.T) {
	p := newTLSEpollFixPeer(t)
	var wire []byte
	for i := 0; i < tlsEpollFixTinyRecords; i++ {
		wire = append(wire, p.record([]byte{byte('a' + i%26)}, tlsRecAppData)...)
	}
	partial := p.record([]byte("tail"), tlsRecAppData)
	wire = append(wire, partial[:len(partial)-3]...)
	p.feed(wire)
	action, gotData := p.decrypt()
	if action != epollTLSContinue || !gotData {
		t.Fatalf("action=%d gotData=%v, want continue with data", action, gotData)
	}
	if len(p.conn.appBuf) != tlsEpollFixTinyRecords {
		t.Fatalf("one decrypt pass delivered %d of %d buffered records; each record must not cost a pass over the remaining ciphertext", len(p.conn.appBuf), tlsEpollFixTinyRecords)
	}
	if p.conn.readN != len(partial)-3 || !bytes.Equal(p.conn.readBuf[:p.conn.readN], partial[:len(partial)-3]) {
		t.Fatalf("partial record not kept at the front of the buffer: readN=%d", p.conn.readN)
	}
	p.feed(partial[len(partial)-3:])
	p.conn.appBuf = p.conn.appBuf[:0]
	if action, gotData = p.decrypt(); !gotData || string(p.conn.appBuf) != "tail" || p.conn.readN != 0 {
		t.Fatalf("completed partial record: action=%d appBuf=%q readN=%d", action, p.conn.appBuf, p.conn.readN)
	}
}

func TestTLSEpollFixEmptyRecordFloodIsRejected(t *testing.T) {
	p := newTLSEpollFixPeer(t)
	var wire []byte
	for i := 0; i < tlsMaxUselessRecords; i++ {
		wire = append(wire, p.record(nil, tlsRecAppData)...)
	}
	wire = append(wire, p.record([]byte("x"), tlsRecAppData)...)
	p.feed(wire)
	if action, gotData := p.decrypt(); !gotData || string(p.conn.appBuf) != "x" {
		t.Fatalf("%d empty records then data: action=%d appBuf=%q, want the data", tlsMaxUselessRecords, action, p.conn.appBuf)
	}
	wire = wire[:0]
	for i := 0; i <= tlsMaxUselessRecords; i++ {
		wire = append(wire, p.record(nil, tlsRecAppData)...)
	}
	p.feed(wire)
	action, _ := p.decrypt()
	p.expectFatalAlert(t, action, alertUnexpectedMessage)
}

func TestTLSEpollFixKeyUpdateRotatesKeys(t *testing.T) {
	for _, requested := range []byte{0, 1} {
		p := newTLSEpollFixPeer(t)
		wire := p.record([]byte{24, 0, 0, 1, requested}, tlsRecHandshake)
		p.advanceClientWriter(t)
		wire = append(wire, p.record([]byte("GET / HTTP/1.1\r\n"), tlsRecAppData)...)
		p.feed(wire)
		action, gotData := p.decrypt()
		if !gotData || string(p.conn.appBuf) != "GET / HTTP/1.1\r\n" {
			t.Fatalf("request_update=%d: data after KeyUpdate not decrypted: action=%d appBuf=%q", requested, action, p.conn.appBuf)
		}
		p.conn.writeBuf = p.conn.sealTLSAppData(p.conn.writeBuf, []byte("response"))
		recs := p.serverRecords(t)
		want := 1
		if requested == 1 {
			want = 2
			if recs[0].innerType != tlsRecHandshake || !bytes.Equal(recs[0].content, []byte{24, 0, 0, 1, 0}) {
				t.Fatalf("server answered update_requested with %+v, want KeyUpdate(update_not_requested)", recs[0])
			}
		}
		if len(recs) != want || string(recs[want-1].content) != "response" {
			t.Fatalf("request_update=%d: server records %+v", requested, recs)
		}
	}
}

func TestTLSEpollFixPostHandshakeMessagesValidated(t *testing.T) {
	cases := []struct {
		name string
		msg  []byte
		want tlsAlert
	}{
		{"bad request_update value", []byte{24, 0, 0, 1, 2}, alertIllegalParameter},
		{"KeyUpdate wrong length", []byte{24, 0, 0, 2, 0, 0}, alertDecodeError},
		{"data after KeyUpdate in the same record", []byte{24, 0, 0, 1, 0, 24, 0, 0, 1, 0}, alertUnexpectedMessage},
		{"NewSessionTicket from client", []byte{4, 0, 0, 0}, alertUnexpectedMessage},
		{"truncated handshake header", []byte{24, 0}, alertUnexpectedMessage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTLSEpollFixPeer(t)
			p.feed(p.record(tc.msg, tlsRecHandshake))
			action, _ := p.decrypt()
			p.expectFatalAlert(t, action, tc.want)
		})
	}
}

func TestTLSEpollFixIllegalInnerRecordsRejected(t *testing.T) {
	cases := []struct {
		name      string
		content   []byte
		innerType byte
		want      tlsAlert
	}{
		{"unknown inner type", []byte("x"), 0x42, alertUnexpectedMessage},
		{"encrypted change_cipher_spec", []byte{1}, 0x14, alertUnexpectedMessage},
		{"inner plaintext above 2^14+1", bytes.Repeat([]byte{'y'}, MaxRecordPayload+1), tlsRecAppData, alertRecordOverflow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTLSEpollFixPeer(t)
			p.feed(p.record(tc.content, tc.innerType))
			action, _ := p.decrypt()
			p.expectFatalAlert(t, action, tc.want)
		})
	}
	p := newTLSEpollFixPeer(t)
	p.feed(p.record(bytes.Repeat([]byte{'y'}, MaxRecordPayload), tlsRecAppData))
	if _, gotData := p.decrypt(); !gotData || len(p.conn.appBuf) != MaxRecordPayload {
		t.Fatalf("a full 2^14 record was not accepted: appBuf=%d", len(p.conn.appBuf))
	}
}

func TestTLSEpollFixCloseNotifyAfterDataStillDeliversData(t *testing.T) {
	p := newTLSEpollFixPeer(t)
	wire := p.record([]byte("GET / HTTP/1.1\r\n\r\n"), tlsRecAppData)
	wire = append(wire, p.record([]byte{1, 0}, tlsRecAlert)...)
	wire = append(wire, p.record([]byte("ignored"), tlsRecAppData)...)
	p.feed(wire)
	action, gotData := p.decrypt()
	if action != epollTLSContinue || !gotData || string(p.conn.appBuf) != "GET / HTTP/1.1\r\n\r\n" {
		t.Fatalf("first pass: action=%d gotData=%v appBuf=%q", action, gotData, p.conn.appBuf)
	}
	if p.conn.readN == 0 && !p.conn.tlsAppPending() {
		t.Fatal("pending close_notify is neither buffered nor reported as pending input")
	}
	if action, gotData = p.decrypt(); action != epollActionCloseAfterFlush || gotData {
		t.Fatalf("second pass: action=%d gotData=%v, want close after flush", action, gotData)
	}
}

func TestTLSEpollFixTLS12PlaintextBounded(t *testing.T) {
	client, server := tlsEpollFixTLS12Pair(t)
	_, serverWriter := tlsEpollFixTLS12Pair(t)
	p := newTLSEpollFixPeer(t)
	p.conn.tlsVersion = TLSVersion12
	p.conn.tls12 = &tls12State{reader: server, writer: serverWriter}
	p.feed(client.sealTo(nil, tlsRecAppData, bytes.Repeat([]byte{'z'}, MaxRecordPayload)))
	if _, gotData := p.decrypt(); !gotData || len(p.conn.appBuf) != MaxRecordPayload {
		t.Fatalf("a full 2^14 TLS 1.2 record was not accepted: appBuf=%d", len(p.conn.appBuf))
	}
	p.feed(client.sealTo(nil, tlsRecAppData, bytes.Repeat([]byte{'z'}, MaxRecordPayload+1)))
	if action, _ := p.decrypt(); action != epollActionCloseAfterFlush || !p.conn.tlsAlertSent {
		t.Fatalf("TLS 1.2 plaintext above 2^14 accepted: action=%d alertSent=%v", action, p.conn.tlsAlertSent)
	}
}
