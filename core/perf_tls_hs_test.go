//go:build linux && amd64

package core

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

const perfTLSLinkReadBufSize = 64 << 10

var errPerfTLSServerClosed = errors.New("server closed the in-process TLS link")

type perfTLSAddr struct{}

func (perfTLSAddr) Network() string { return "perf" }
func (perfTLSAddr) String() string  { return "perf" }

type perfTLSLink struct {
	b         *testing.B
	srv       *Server
	conn      *epollConn
	toClient  []byte
	clientOff int
	serverErr error
}

func (l *perfTLSLink) Write(p []byte) (int, error) {
	c := l.conn
	if c.readN+len(p) > len(c.readBuf) {
		return 0, io.ErrShortBuffer
	}
	c.readN += copy(c.readBuf[c.readN:], p)
	l.b.StartTimer()
	act := c.epollProcessTLS(l.srv)
	l.b.StopTimer()
	l.toClient = append(l.toClient, c.writeBuf...)
	c.writeBuf = c.writeBuf[:0]
	if act == epollActionCloseAfterFlush {
		l.serverErr = errPerfTLSServerClosed
		return 0, l.serverErr
	}
	return len(p), nil
}

func (l *perfTLSLink) Read(p []byte) (int, error) {
	if l.clientOff >= len(l.toClient) {
		return 0, io.EOF
	}
	n := copy(p, l.toClient[l.clientOff:])
	l.clientOff += n
	if l.clientOff == len(l.toClient) {
		l.toClient, l.clientOff = l.toClient[:0], 0
	}
	return n, nil
}

func (l *perfTLSLink) Close() error                     { return nil }
func (l *perfTLSLink) LocalAddr() net.Addr              { return perfTLSAddr{} }
func (l *perfTLSLink) RemoteAddr() net.Addr             { return perfTLSAddr{} }
func (l *perfTLSLink) SetDeadline(time.Time) error      { return nil }
func (l *perfTLSLink) SetReadDeadline(time.Time) error  { return nil }
func (l *perfTLSLink) SetWriteDeadline(time.Time) error { return nil }

type perfTLSTicketSink struct{}

func (perfTLSTicketSink) Get(string) (*tls.ClientSessionState, bool) { return nil, false }
func (perfTLSTicketSink) Put(string, *tls.ClientSessionState)        {}

type perfTLSHandshakeRig struct {
	link     *perfTLSLink
	worker   *epollWorker
	readBuf  []byte
	plainBuf []byte
	appBuf   []byte
	writeBuf []byte
}

func newPerfTLSHandshakeRig(b *testing.B, srv *Server) *perfTLSHandshakeRig {
	return &perfTLSHandshakeRig{
		link:     &perfTLSLink{b: b, srv: srv},
		worker:   &epollWorker{server: srv},
		readBuf:  make([]byte, perfTLSLinkReadBufSize),
		plainBuf: acquireIOBuf(),
		appBuf:   acquireIOBuf(),
		writeBuf: acquireIOBuf(),
	}
}

func (r *perfTLSHandshakeRig) freshConn() *epollConn {
	if prev := r.link.conn; prev != nil {
		r.plainBuf, r.appBuf, r.writeBuf = prev.plainBuf, prev.appBuf, prev.writeBuf
	}
	c := &epollConn{
		tls:      true,
		worker:   r.worker,
		readBuf:  r.readBuf,
		plainBuf: r.plainBuf[:0],
		appBuf:   r.appBuf[:0],
		writeBuf: r.writeBuf[:0],
	}
	r.link.conn = c
	r.link.toClient, r.link.clientOff, r.link.serverErr = r.link.toClient[:0], 0, nil
	return c
}

func (r *perfTLSHandshakeRig) handshake(b *testing.B, cfg *tls.Config, drainTicket bool) tls.ConnectionState {
	c := r.freshConn()
	client := tls.Client(r.link, cfg)
	if err := client.Handshake(); err != nil {
		b.Fatalf("handshake: %v (server: %v)", err, r.link.serverErr)
	}
	if c.phase != tlsConnPhaseApplication {
		b.Fatalf("server phase %d after the handshake, want application", c.phase)
	}
	if drainTicket {
		var one [1]byte
		_, _ = client.Read(one[:])
	}
	return client.ConnectionState()
}

func perfTLSHandshakeServer(b *testing.B, mutate func(*Config), dropKeyPool bool) *testServer {
	perfTLSQuietLogs(b)
	var setup func(*Server)
	if dropKeyPool {
		setup = func(s *Server) {
			s.ensureTLSRuntime()
			s.x25519Pool.Close()
			s.x25519Pool = nil
		}
	}
	return newTestServer(b, testServerOptions{TLS: true, Config: mutate, Setup: setup, Routes: perfTLSRoutes})
}

func perfTLSFullHandshake(b *testing.B, version uint16, curve tls.CurveID, mutate func(*Config), dropKeyPool bool) {
	ts := perfTLSHandshakeServer(b, mutate, dropKeyPool)
	cfg := perfTLSClientConfig(ts, version)
	cfg.CurvePreferences = []tls.CurveID{curve}
	cfg.ClientSessionCache = perfTLSTicketSink{}
	rig := newPerfTLSHandshakeRig(b, ts.srv)
	b.StopTimer()
	st := rig.handshake(b, cfg, false)
	if st.Version != version || st.DidResume || (version == tls.VersionTLS13 && st.CurveID != curve) {
		b.Fatalf("negotiated version %x curve %v resumed %v", st.Version, st.CurveID, st.DidResume)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		rig.handshake(b, cfg, false)
	}
}

func perfTLSResumedHandshake(b *testing.B, version uint16) {
	ts := perfTLSHandshakeServer(b, nil, false)
	cfg := perfTLSClientConfig(ts, version)
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	rig := newPerfTLSHandshakeRig(b, ts.srv)
	drain := version == tls.VersionTLS13
	b.StopTimer()
	rig.handshake(b, cfg, drain)
	if st := rig.handshake(b, cfg, drain); !st.DidResume {
		b.Fatal("second handshake did not resume")
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		if st := rig.handshake(b, cfg, drain); !st.DidResume {
			b.Fatalf("iteration %d did not resume", i)
		}
	}
}

func BenchmarkPerfTLS13FullHandshakeX25519(b *testing.B) {
	perfTLSFullHandshake(b, tls.VersionTLS13, tls.X25519, nil, false)
}

func BenchmarkPerfTLS13FullHandshakeX25519NoKeyPool(b *testing.B) {
	perfTLSFullHandshake(b, tls.VersionTLS13, tls.X25519, nil, true)
}

func BenchmarkPerfTLS13FullHandshakeP256(b *testing.B) {
	perfTLSFullHandshake(b, tls.VersionTLS13, tls.CurveP256, nil, false)
}

func BenchmarkPerfTLS13FullHandshakeX25519MLKEM768(b *testing.B) {
	perfTLSFullHandshake(b, tls.VersionTLS13, tls.X25519MLKEM768, func(c *Config) { c.TLSPreferPostQuantum = true }, false)
}

func BenchmarkPerfTLS13ResumedHandshake(b *testing.B) {
	perfTLSResumedHandshake(b, tls.VersionTLS13)
}

func BenchmarkPerfTLS12FullHandshakeX25519(b *testing.B) {
	perfTLSFullHandshake(b, tls.VersionTLS12, tls.X25519, nil, false)
}

func BenchmarkPerfTLS12FullHandshakeP256(b *testing.B) {
	perfTLSFullHandshake(b, tls.VersionTLS12, tls.CurveP256, nil, false)
}

func BenchmarkPerfTLS12ResumedHandshake(b *testing.B) {
	perfTLSResumedHandshake(b, tls.VersionTLS12)
}
