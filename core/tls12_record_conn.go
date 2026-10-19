//go:build linux && amd64

package core

import (
	"io"
	"net"
	"sync"
)

const tls12RecordConnWriteChunk = 16 * MaxRecordPayload

var (
	errTLSUnexpectedRecord = &staticError{"tls: unexpected record after the handshake"}
	errTLSBadRecordMAC     = &staticError{"tls: bad record MAC"}
	errTLSPeerAlert        = &staticError{"tls: peer sent a fatal alert"}
	errTLSUselessRecords   = &staticError{"tls: too many ignored records"}
)

type tls12RecordConn struct {
	net.Conn

	readMu  sync.Mutex
	reader  *tls12AEAD
	plain   []byte
	record  []byte
	useless int
	readErr error

	writeMu sync.Mutex
	writer  *tls12AEAD
	sealed  []byte
}

func newTLS12RecordConn(conn net.Conn, reader, writer *tls12AEAD, decrypted []byte) *tls12RecordConn {
	return &tls12RecordConn{Conn: conn, reader: reader, writer: writer, plain: decrypted}
}

func (c *tls12RecordConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.plain) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		c.readErr = c.readRecord()
	}
	n := copy(p, c.plain)
	c.plain = c.plain[n:]
	return n, nil
}

func (c *tls12RecordConn) readRecord() error {
	if c.record == nil {
		c.record = make([]byte, tlsRecordHeaderLen+MaxRecordSize)
	}
	hdr := c.record[:tlsRecordHeaderLen]
	if _, err := io.ReadFull(c.Conn, hdr); err != nil {
		return err
	}
	length := int(hdr[3])<<8 | int(hdr[4])
	if length > MaxRecordSize {
		return ErrRecordTooLarge
	}
	rec := c.record[:tlsRecordHeaderLen+length]
	if _, err := io.ReadFull(c.Conn, rec[tlsRecordHeaderLen:]); err != nil {
		return err
	}
	if rec[0] != tlsRecAppData && rec[0] != tlsRecAlert {
		return errTLSUnexpectedRecord
	}
	typ, pt, ok := c.reader.open(rec)
	if !ok {
		return errTLSBadRecordMAC
	}
	if len(pt) > MaxRecordPayload {
		return ErrRecordTooLarge
	}
	if typ == tlsRecAlert {
		return c.handleAlert(pt)
	}
	if len(pt) == 0 {
		return c.skipUselessRecord()
	}
	c.useless = 0
	c.plain = pt
	return nil
}

func (c *tls12RecordConn) handleAlert(body []byte) error {
	if len(body) != 2 {
		return errTLSUnexpectedRecord
	}
	if tlsAlert(body[1]) == alertCloseNotify {
		return io.EOF
	}
	if body[0] == tlsAlertLevelWarning {
		return c.skipUselessRecord()
	}
	return errTLSPeerAlert
}

func (c *tls12RecordConn) skipUselessRecord() error {
	c.useless++
	if c.useless > tlsMaxUselessRecords {
		return errTLSUselessRecords
	}
	return nil
}

func (c *tls12RecordConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for written < len(p) {
		chunk := p[written:min(len(p), written+tls12RecordConnWriteChunk)]
		c.sealed = buildTLS12AppDataRecords(c.sealed[:0], c.writer, chunk)
		if _, err := c.Conn.Write(c.sealed); err != nil {
			return written, err
		}
		written += len(chunk)
	}
	return written, nil
}
