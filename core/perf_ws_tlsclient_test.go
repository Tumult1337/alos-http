//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

const (
	perfTLSHeaderLen      = 5
	perfTLSRecordCapacity = perfTLSHeaderLen + MaxRecordSize
	perfTLSCCS            = 0x14
	perfTLSAlert          = 0x15
	perfTLSHandshake      = 0x16
	perfTLSAppData        = 0x17
)

var errPerfTLSUnexpected = errors.New("perf tls client: unexpected record")

type perfKeyLog struct {
	client []byte
	server []byte
}

func (k *perfKeyLog) Write(line []byte) (int, error) {
	fields := bytes.Fields(line)
	if len(fields) != 3 {
		return len(line), nil
	}
	secret, err := hex.DecodeString(string(fields[2]))
	if err != nil {
		return len(line), nil
	}
	switch string(fields[0]) {
	case "CLIENT_TRAFFIC_SECRET_0":
		k.client = secret
	case "SERVER_TRAFFIC_SECRET_0":
		k.server = secret
	}
	return len(line), nil
}

type perfTLSClient struct {
	raw     *perfRawConn
	writer  *TrafficAEAD
	reader  *TrafficAEAD
	out     []byte
	in      []byte
	inR     int
	inW     int
	pendBuf []byte
	pend    []byte
}

func perfDialTLSClient(tb testing.TB, addr string, cfg *tls.Config) *perfTLSClient {
	tb.Helper()
	raw := perfDialRaw(tb, addr)
	keys := &perfKeyLog{}
	cfg = cfg.Clone()
	cfg.KeyLogWriter = keys
	cfg.MinVersion = tls.VersionTLS13
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		tb.Fatalf("tls handshake: %v", err)
	}
	cs := FindSuiteByID(tc.ConnectionState().CipherSuite)
	if cs == nil || keys.client == nil || keys.server == nil {
		tb.Fatalf("tls client: suite %#x or traffic secrets unavailable", tc.ConnectionState().CipherSuite)
	}
	writer, err := NewTrafficAEAD(cs.HashFn, keys.client, cs)
	if err != nil {
		tb.Fatalf("client writer: %v", err)
	}
	reader, err := NewTrafficAEAD(cs.HashFn, keys.server, cs)
	if err != nil {
		tb.Fatalf("client reader: %v", err)
	}
	return &perfTLSClient{
		raw:     raw,
		writer:  writer,
		reader:  reader,
		in:      make([]byte, 2*perfTLSRecordCapacity),
		pendBuf: make([]byte, 0, MaxRecordPayload),
	}
}

func (c *perfTLSClient) fill(n int) error {
	if c.inW-c.inR >= n {
		return nil
	}
	if c.inR > 0 {
		c.inW = copy(c.in, c.in[c.inR:c.inW])
		c.inR = 0
	}
	if n > len(c.in) {
		return ErrRecordTooLarge
	}
	for c.inW < n {
		m, err := c.raw.Read(c.in[c.inW:])
		c.inW += m
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *perfTLSClient) nextRecord() error {
	if err := c.fill(perfTLSHeaderLen); err != nil {
		return err
	}
	hdr := c.in[c.inR : c.inR+perfTLSHeaderLen]
	ct := hdr[0]
	length := int(hdr[3])<<8 | int(hdr[4])
	if err := c.fill(perfTLSHeaderLen + length); err != nil {
		return err
	}
	rec := c.in[c.inR+perfTLSHeaderLen : c.inR+perfTLSHeaderLen+length]
	c.inR += perfTLSHeaderLen + length
	if ct == perfTLSCCS {
		return nil
	}
	pt, err := c.reader.Decrypt(rec)
	if err != nil {
		return err
	}
	content, inner, err := StripInnerPlaintext(pt)
	if err != nil {
		return err
	}
	switch inner {
	case perfTLSAppData:
		c.pend = append(c.pendBuf[:0], content...)
		return nil
	case perfTLSHandshake:
		return nil
	case perfTLSAlert:
		return io.EOF
	}
	return errPerfTLSUnexpected
}

func (c *perfTLSClient) Read(p []byte) (int, error) {
	for len(c.pend) == 0 {
		if err := c.nextRecord(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.pend)
	c.pend = c.pend[n:]
	return n, nil
}

func (c *perfTLSClient) Write(p []byte) (int, error) {
	c.out = buildTLSAppDataRecords(c.out[:0], c.writer, p)
	if _, err := c.raw.Write(c.out); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *perfTLSClient) Close() error                     { return c.raw.Close() }
func (c *perfTLSClient) LocalAddr() net.Addr              { return perfRawAddr }
func (c *perfTLSClient) RemoteAddr() net.Addr             { return perfRawAddr }
func (c *perfTLSClient) SetDeadline(time.Time) error      { return nil }
func (c *perfTLSClient) SetReadDeadline(time.Time) error  { return nil }
func (c *perfTLSClient) SetWriteDeadline(time.Time) error { return nil }
