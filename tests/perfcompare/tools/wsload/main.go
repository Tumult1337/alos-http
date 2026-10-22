package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"math/bits"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/guno1928/turbo"
)

const (
	wsGUID            = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	opText            = 0x1
	opClose           = 0x8
	opPing            = 0x9
	opPong            = 0xA
	finBit            = 0x80
	maskBit           = 0x80
	maxControlPayload = 125
	readBufSize       = 64 << 10
	maxHandshakeBytes = 16 << 10
	dialTimeout       = 5 * time.Second
	ioGrace           = 2 * time.Second
	redialBackoff     = 10 * time.Millisecond
	payloadByte       = 'x'
	histSubBits       = 6
	histSub           = 1 << histSubBits
	histLinear        = 2 * histSub
	histMaxShift      = 21
	histBuckets       = histLinear + histMaxShift*histSub
)

var (
	errMaskedServerFrame = errors.New("server frame is masked")
	errServerClosed      = errors.New("server sent close")
	errLengthMismatch    = errors.New("echo length mismatch")
	errBadOpcode         = errors.New("unexpected opcode")
	errControlTooLarge   = errors.New("control frame too large")
	errHandshakeStatus   = errors.New("handshake: status is not 101")
	errHandshakeAccept   = errors.New("handshake: bad Sec-WebSocket-Accept")
	errHandshakeTooLarge = errors.New("handshake: response header too large")
	errHandshakeDeflate  = errors.New("handshake: server negotiated an extension")
	errBadALPN           = errors.New("tls: server negotiated a protocol other than http/1.1")
)

type histogram struct {
	counts [histBuckets]uint32
}

type histogramTotal struct {
	counts [histBuckets]uint64
}

func histIndex(v uint64) int {
	if v < histLinear {
		return int(v)
	}
	shift := bits.Len64(v) - (histSubBits + 1)
	if shift > histMaxShift {
		return histBuckets - 1
	}
	return histLinear + (shift-1)*histSub + int(v>>uint(shift)) - histSub
}

func histValue(idx int) uint64 {
	if idx < histLinear {
		return uint64(idx)
	}
	k := idx - histLinear
	shift := uint(k/histSub + 1)
	lower := uint64(k%histSub+histSub) << shift
	return lower + (uint64(1)<<shift)/2
}

func (h *histogram) record(v uint64) {
	h.counts[histIndex(v)]++
}

func (t *histogramTotal) add(h *histogram) {
	for i, c := range h.counts {
		t.counts[i] += uint64(c)
	}
}

func (t *histogramTotal) quantile(q float64) uint64 {
	var total uint64
	for _, c := range t.counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := uint64(q * float64(total))
	if target < 1 {
		target = 1
	}
	var cum uint64
	for i, c := range t.counts {
		cum += c
		if cum >= target {
			return histValue(i)
		}
	}
	return histValue(histBuckets - 1)
}

type target struct {
	dialAddr string
	host     string
	path     string
	tlsCfg   *tls.Config
}

func parseTarget(raw string, insecure bool) (target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return target{}, err
	}
	t := target{host: u.Host, path: u.RequestURI()}
	port := u.Port()
	switch u.Scheme {
	case "ws":
		if port == "" {
			port = "80"
		}
	case "wss":
		if port == "" {
			port = "443"
		}
		t.tlsCfg = &tls.Config{InsecureSkipVerify: insecure, NextProtos: []string{"http/1.1"}}
		if net.ParseIP(u.Hostname()) == nil {
			t.tlsCfg.ServerName = u.Hostname()
		}
	default:
		return target{}, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	t.dialAddr = net.JoinHostPort(u.Hostname(), port)
	return t, nil
}

func buildMaskedFrame(opcode byte, payload []byte, maskKey uint32) []byte {
	n := len(payload)
	frame := make([]byte, 0, n+14)
	frame = append(frame, finBit|opcode)
	switch {
	case n <= maxControlPayload:
		frame = append(frame, maskBit|byte(n))
	case n <= 0xFFFF:
		frame = append(frame, maskBit|126)
		frame = binary.BigEndian.AppendUint16(frame, uint16(n))
	default:
		frame = append(frame, maskBit|127)
		frame = binary.BigEndian.AppendUint64(frame, uint64(n))
	}
	var key [4]byte
	binary.BigEndian.PutUint32(key[:], maskKey)
	frame = append(frame, key[:]...)
	start := len(frame)
	frame = append(frame, payload...)
	for i := range n {
		frame[start+i] ^= key[i&3]
	}
	return frame
}

type wsConn struct {
	conn    net.Conn
	frame   []byte
	size    int
	maskKey [4]byte
	pong    [maxControlPayload + 6]byte
	buf     []byte
	r, w    int
}

func newWSConn(conn net.Conn, frame []byte, size int, maskKey uint32) *wsConn {
	c := &wsConn{conn: conn, frame: frame, size: size, buf: make([]byte, readBufSize)}
	binary.BigEndian.PutUint32(c.maskKey[:], maskKey)
	return c
}

func (c *wsConn) fill(n int) error {
	if c.w-c.r >= n {
		return nil
	}
	if len(c.buf)-c.r < n {
		c.w = copy(c.buf, c.buf[c.r:c.w])
		c.r = 0
	}
	for c.w-c.r < n {
		m, err := c.conn.Read(c.buf[c.w:])
		c.w += m
		if err != nil && c.w-c.r < n {
			return err
		}
	}
	return nil
}

func (c *wsConn) skip(n uint64) error {
	for n > 0 {
		if c.r == c.w {
			c.r, c.w = 0, 0
			m, err := c.conn.Read(c.buf)
			c.w = m
			if m == 0 && err != nil {
				return err
			}
		}
		k := uint64(c.w - c.r)
		if k > n {
			k = n
		}
		c.r += int(k)
		n -= k
	}
	return nil
}

func (c *wsConn) readHeader() (opcode byte, fin bool, plen uint64, err error) {
	if err = c.fill(2); err != nil {
		return
	}
	b0, b1 := c.buf[c.r], c.buf[c.r+1]
	if b1&maskBit != 0 {
		err = errMaskedServerFrame
		return
	}
	opcode, fin, plen = b0&0x0f, b0&finBit != 0, uint64(b1&0x7f)
	hdr := 2
	switch plen {
	case 126:
		if err = c.fill(4); err != nil {
			return
		}
		plen = uint64(binary.BigEndian.Uint16(c.buf[c.r+2:]))
		hdr = 4
	case 127:
		if err = c.fill(10); err != nil {
			return
		}
		plen = binary.BigEndian.Uint64(c.buf[c.r+2:])
		hdr = 10
	}
	c.r += hdr
	return
}

func (c *wsConn) answerPing(plen int) error {
	c.pong[0] = finBit | opPong
	c.pong[1] = maskBit | byte(plen)
	copy(c.pong[2:6], c.maskKey[:])
	for i := range plen {
		c.pong[6+i] = c.buf[c.r+i] ^ c.maskKey[i&3]
	}
	_, err := c.conn.Write(c.pong[:6+plen])
	return err
}

func (c *wsConn) handleControl(opcode byte, plen uint64) error {
	if plen > maxControlPayload {
		return errControlTooLarge
	}
	if err := c.fill(int(plen)); err != nil {
		return err
	}
	switch opcode {
	case opClose:
		return errServerClosed
	case opPing:
		if err := c.answerPing(int(plen)); err != nil {
			return err
		}
	case opPong:
	default:
		return errBadOpcode
	}
	c.r += int(plen)
	return nil
}

func (c *wsConn) readEcho() error {
	var total uint64
	first := true
	for {
		opcode, fin, plen, err := c.readHeader()
		if err != nil {
			return err
		}
		if opcode >= opClose {
			if err := c.handleControl(opcode, plen); err != nil {
				return err
			}
			continue
		}
		if first && opcode != opText || !first && opcode != 0 {
			return errBadOpcode
		}
		first = false
		if err := c.skip(plen); err != nil {
			return err
		}
		total += plen
		if fin {
			break
		}
	}
	if total != uint64(c.size) {
		return errLengthMismatch
	}
	return nil
}

func (c *wsConn) roundTrip() error {
	if _, err := c.conn.Write(c.frame); err != nil {
		return err
	}
	return c.readEcho()
}

func (c *wsConn) timedRoundTrip(h *histogram) error {
	start := time.Now()
	if err := c.roundTrip(); err != nil {
		return err
	}
	h.record(uint64(time.Since(start) / time.Microsecond))
	return nil
}

func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func newHandshakeKey() string {
	var raw [16]byte
	binary.LittleEndian.PutUint64(raw[:8], turbo.Uint64())
	binary.LittleEndian.PutUint64(raw[8:], turbo.Uint64())
	return base64.StdEncoding.EncodeToString(raw[:])
}

func headerValue(head []byte, name string) (string, bool) {
	for _, line := range bytes.Split(head, []byte("\r\n"))[1:] {
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		if bytes.EqualFold(bytes.TrimSpace(line[:colon]), []byte(name)) {
			return string(bytes.TrimSpace(line[colon+1:])), true
		}
	}
	return "", false
}

func (c *wsConn) handshake(t target) error {
	key := newHandshakeKey()
	req := "GET " + t.path + " HTTP/1.1\r\nHost: " + t.host +
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key +
		"\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := c.conn.Write([]byte(req)); err != nil {
		return err
	}
	terminator := []byte("\r\n\r\n")
	for {
		if end := bytes.Index(c.buf[:c.w], terminator); end >= 0 {
			head := c.buf[:end]
			c.r = end + len(terminator)
			return checkHandshake(head, key)
		}
		if c.w >= maxHandshakeBytes {
			return errHandshakeTooLarge
		}
		m, err := c.conn.Read(c.buf[c.w:])
		c.w += m
		if err != nil && m == 0 {
			return err
		}
	}
}

func checkHandshake(head []byte, key string) error {
	if !bytes.HasPrefix(head, []byte("HTTP/1.1 101")) {
		return errHandshakeStatus
	}
	accept, _ := headerValue(head, "Sec-WebSocket-Accept")
	if accept != acceptKey(key) {
		return errHandshakeAccept
	}
	if _, ok := headerValue(head, "Sec-WebSocket-Extensions"); ok {
		return errHandshakeDeflate
	}
	return nil
}

func dial(t target, frame []byte, size int, maskKey uint32, deadline time.Time) (*wsConn, error) {
	raw, err := net.DialTimeout("tcp", t.dialAddr, dialTimeout)
	if err != nil {
		return nil, err
	}
	conn := raw
	if t.tlsCfg != nil {
		tc := tls.Client(raw, t.tlsCfg)
		_ = tc.SetDeadline(time.Unix(0, turbo.UnixNano()).Add(dialTimeout))
		if err := tc.Handshake(); err != nil {
			_ = raw.Close()
			return nil, err
		}
		if p := tc.ConnectionState().NegotiatedProtocol; p != "" && p != "http/1.1" {
			_ = raw.Close()
			return nil, errBadALPN
		}
		conn = tc
	}
	_ = conn.SetDeadline(deadline)
	c := newWSConn(conn, frame, size, maskKey)
	if err := c.handshake(t); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

type loadConfig struct {
	target   target
	conns    int
	duration time.Duration
	size     int
}

type workerResult struct {
	msgs   uint64
	errors uint64
	hist   histogram
}

type loadRun struct {
	cfg     loadConfig
	frame   []byte
	maskKey uint32
	ioLimit time.Time
	endMono int64
	start   chan struct{}
	ready   sync.WaitGroup
	done    sync.WaitGroup
	results []workerResult
}

func (lr *loadRun) worker(idx int) {
	defer lr.done.Done()
	res := &lr.results[idx]
	c, err := dial(lr.cfg.target, lr.frame, lr.cfg.size, lr.maskKey, lr.ioLimit)
	if err != nil {
		res.errors++
	}
	lr.ready.Done()
	<-lr.start
	for turbo.Until(lr.endMono) > 0 {
		if c == nil {
			c, err = dial(lr.cfg.target, lr.frame, lr.cfg.size, lr.maskKey, lr.ioLimit)
			if err != nil {
				res.errors++
				turbo.Sleep(redialBackoff)
				continue
			}
		}
		if err := c.timedRoundTrip(&res.hist); err != nil {
			res.errors++
			_ = c.conn.Close()
			c = nil
			continue
		}
		res.msgs++
	}
	if c != nil {
		_ = c.conn.Close()
	}
}

func run(cfg loadConfig) (msgs, errs uint64, rate float64, p50, p99 uint64) {
	payload := bytes.Repeat([]byte{payloadByte}, cfg.size)
	lr := &loadRun{
		cfg:     cfg,
		maskKey: turbo.Uint32(),
		start:   make(chan struct{}),
		results: make([]workerResult, cfg.conns),
	}
	lr.frame = buildMaskedFrame(opText, payload, lr.maskKey)
	lr.ioLimit = time.Unix(0, turbo.UnixNano()).Add(dialTimeout + cfg.duration + ioGrace)
	lr.ready.Add(cfg.conns)
	lr.done.Add(cfg.conns)
	for i := range cfg.conns {
		go lr.worker(i)
	}
	lr.ready.Wait()
	startMono := turbo.Now()
	lr.endMono = turbo.Add(startMono, cfg.duration)
	close(lr.start)
	lr.done.Wait()
	elapsed := turbo.Since(startMono)

	var total histogramTotal
	for i := range lr.results {
		r := &lr.results[i]
		msgs += r.msgs
		errs += r.errors
		total.add(&r.hist)
	}
	if elapsed > 0 {
		rate = float64(msgs) / elapsed.Seconds()
	}
	return msgs, errs, rate, total.quantile(0.50), total.quantile(0.99)
}

func main() {
	rawURL := flag.String("url", "ws://127.0.0.1:8080/ws", "ws:// or wss:// target")
	conns := flag.Int("c", 64, "connections")
	duration := flag.Duration("d", 10*time.Second, "test duration")
	size := flag.Int("size", 64, "message payload bytes")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	flag.Parse()

	if *conns < 1 || *size < 0 || *duration <= 0 {
		fmt.Fprintln(os.Stderr, "wsload: -c must be >= 1, -size >= 0, -d > 0")
		os.Exit(2)
	}
	t, err := parseTarget(*rawURL, *insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wsload: %v\n", err)
		os.Exit(2)
	}
	msgs, errs, rate, p50, p99 := run(loadConfig{target: t, conns: *conns, duration: *duration, size: *size})
	fmt.Printf("msgs=%d rate=%.0f p50=%d p99=%d errors=%d\n", msgs, rate, p50, p99, errs)
}
