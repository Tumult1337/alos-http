//go:build linux && amd64

package core

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestTLSEpollFixHijackedTLS13HonoursKeyUpdate(t *testing.T) {
	p := newTLSEpollFixPeer(t)
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(wallDeadline(harnessIOTimeout))
	_ = server.SetDeadline(wallDeadline(harnessIOTimeout))
	hc := &aead13Conn{conn: server, reader: p.conn.appReader, writer: p.conn.appWriter, hdrBuf: make([]byte, tlsRecordHeaderLen)}
	wire := p.record([]byte{24, 0, 0, 1, 1}, tlsRecHandshake)
	p.advanceClientWriter(t)
	wire = append(wire, p.record([]byte("after-update"), tlsRecAppData)...)
	go func() { _, _ = client.Write(wire) }()
	serverOut := make(chan []byte, 1)
	go func() {
		var got []byte
		for records := 0; records < 2; records++ {
			hdr := make([]byte, tlsRecordHeaderLen)
			if _, err := io.ReadFull(client, hdr); err != nil {
				break
			}
			body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
			if _, err := io.ReadFull(client, body); err != nil {
				break
			}
			got = append(append(got, hdr...), body...)
		}
		serverOut <- got
	}()
	plain := make([]byte, len("after-update"))
	if _, err := io.ReadFull(hc, plain); err != nil || string(plain) != "after-update" {
		t.Fatalf("hijacked read after KeyUpdate: %q err=%v", plain, err)
	}
	if _, err := hc.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	p.conn.writeBuf = <-serverOut
	recs := p.serverRecords(t)
	if len(recs) != 2 || recs[0].innerType != tlsRecHandshake || !bytes.Equal(recs[0].content, []byte{24, 0, 0, 1, 0}) || string(recs[1].content) != "reply" {
		t.Fatalf("server records after update_requested: %+v", recs)
	}
}

func TestTLSEpollFixTLS12RecordConnFraming(t *testing.T) {
	cases := []struct {
		name    string
		records func(client *tls12AEAD) []byte
		want    string
		wantErr error
	}{
		{"decrypted prefix then data", func(c *tls12AEAD) []byte { return c.sealTo(nil, tlsRecAppData, []byte("data")) }, "prefixdata", nil},
		{"close_notify is EOF", func(c *tls12AEAD) []byte {
			return c.sealTo(nil, tlsRecAlert, []byte{tlsAlertLevelWarning, byte(alertCloseNotify)})
		}, "prefix", io.EOF},
		{"renegotiation refused", func(c *tls12AEAD) []byte { return c.sealTo(nil, tlsRecHandshake, []byte{0, 0, 0, 0}) }, "prefix", errTLSUnexpectedRecord},
		{"fatal alert", func(c *tls12AEAD) []byte { return c.sealTo(nil, tlsRecAlert, []byte{tlsAlertLevelFatal, 40}) }, "prefix", errTLSPeerAlert},
		{"forged record", func(c *tls12AEAD) []byte { return []byte("\x17\x03\x03\x00\x05FORGE") }, "prefix", errTLSBadRecordMAC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := tlsEpollFixTLS12Pair(t)
			_, serverWriter := tlsEpollFixTLS12Pair(t)
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			go func() { _, _ = b.Write(tc.records(client)) }()
			rc := newTLS12RecordConn(a, server, serverWriter, []byte("prefix"))
			got, err := io.ReadAll(io.LimitReader(rc, int64(len(tc.want))))
			if string(got) != tc.want || err != nil {
				t.Fatalf("read %q err=%v, want %q", got, err, tc.want)
			}
			_ = a.SetReadDeadline(wallDeadline(harnessIOTimeout))
			if tc.wantErr != nil {
				if _, err := rc.Read(make([]byte, 1)); err != tc.wantErr {
					t.Fatalf("next read err=%v, want %v", err, tc.wantErr)
				}
			}
		})
	}
}
