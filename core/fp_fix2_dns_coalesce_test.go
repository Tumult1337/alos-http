//go:build linux && amd64

package core

import (
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	fpFix2ConcurrentLookups = 6
	fpFix2WaiterDeadline    = int64(time.Millisecond)
	fpFix2SweepAfter        = int64(150 * time.Millisecond)
)

type fpFix2ResolveLoop struct {
	l   *eventLoop
	exs []*Exchange
}

func fpFix2StartLookups(t *testing.T, host string, port uint16, n int) *fpFix2ResolveLoop {
	t.Helper()
	l := newLoopForTest()
	l.cfg.fill(1)
	ep, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatalf("epoll: %v", err)
	}
	l.ep = ep
	r := &fpFix2ResolveLoop{l: l}
	t.Cleanup(func() {
		for _, ex := range r.exs {
			if ex.bc != nil {
				l.closeConn(ex.bc, errFPClientClosed)
			}
		}
		_ = unix.Close(ep)
	})
	for i := 0; i < n; i++ {
		ex := &Exchange{req: &fpRequest{Method: "GET"}, done: make(chan struct{}), port: port, key: poolKey{authority: host + ":" + strconv.Itoa(int(port))}}
		ex.deadline = l.nowNano() + int64(time.Hour)
		r.exs = append(r.exs, ex)
		l.newConn(ex)
		if ex.bc == nil || ex.bc.state != connResolving {
			t.Fatalf("lookup %d is not resolving: %+v", i, ex.bc)
		}
	}
	return r
}

func (r *fpFix2ResolveLoop) socketHolders() []*backendConn {
	var holders []*backendConn
	for _, ex := range r.exs {
		if c := ex.bc; c != nil && c.state == connResolving && c.fd >= 0 {
			holders = append(holders, c)
		}
	}
	return holders
}

func (r *fpFix2ResolveLoop) onlyQuerier(t *testing.T) *backendConn {
	t.Helper()
	holders := r.socketHolders()
	if len(holders) != 1 {
		t.Fatalf("%d resolving connections own a DNS socket, want exactly 1", len(holders))
	}
	return holders[0]
}

func (r *fpFix2ResolveLoop) pump(t *testing.T, c *backendConn) {
	t.Helper()
	fpFixWaitFor(t, "the dns answer", func() bool {
		r.l.readable(c)
		return c.state != connResolving
	})
}

func fpFix2Finished(ex *Exchange) bool {
	select {
	case <-ex.done:
		return true
	default:
		return false
	}
}

func fpFix2OriginPort(t *testing.T) uint16 {
	t.Helper()
	_, port := fpFixLoopbackOrigin(t)
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port %q: %v", port, err)
	}
	return uint16(p)
}

func fpFix2AnswerLoopback(s *fpFixDNSServer, query []byte, from *net.UDPAddr) {
	s.reply(from, fpFixDNSReply(query, 0, fpFixARecord([4]byte{127, 0, 0, 1})))
}

func TestFPFix2DNSConcurrentLookupsShareOneQuery(t *testing.T) {
	host := fpFixHostName(t)
	s := fpFixStartDNS(t, fpFix2AnswerLoopback)
	r := fpFix2StartLookups(t, host, fpFix2OriginPort(t), fpFix2ConcurrentLookups)
	leader := r.onlyQuerier(t)
	r.pump(t, leader)
	if got := s.queries.Load(); got != 1 {
		t.Fatalf("%d DNS queries for %d concurrent lookups of one name, want 1", got, fpFix2ConcurrentLookups)
	}
	for i, ex := range r.exs {
		if c := ex.bc; c == nil || c.state != connConnecting || c.fd < 0 || c.dns != nil {
			t.Fatalf("lookup %d did not dial once the shared answer arrived: %+v", i, c)
		}
	}
}

func TestFPFix2DNSWaitersTakeOverWhenTheQuerierCloses(t *testing.T) {
	host := fpFixHostName(t)
	s := fpFixStartDNS(t, fpFix2AnswerLoopback)
	r := fpFix2StartLookups(t, host, fpFix2OriginPort(t), fpFix2ConcurrentLookups)
	first := r.onlyQuerier(t)
	r.l.closeConn(first, errFPClientClosed)
	if !fpFix2Finished(r.exs[0]) || r.exs[0].err != errFPClientClosed {
		t.Fatalf("closed querier's exchange: finished=%v err=%v", fpFix2Finished(r.exs[0]), r.exs[0].err)
	}
	next := r.onlyQuerier(t)
	r.pump(t, next)
	for i, ex := range r.exs[1:] {
		if c := ex.bc; c == nil || c.state != connConnecting || c.fd < 0 {
			t.Fatalf("lookup %d did not dial after the takeover: %+v", i+1, c)
		}
	}
	if got := s.queries.Load(); got > 2 {
		t.Fatalf("%d DNS queries, want at most one per querier", got)
	}
}

func TestFPFix2DNSWaiterDeadlineIsSwept(t *testing.T) {
	host := fpFixHostName(t)
	fpFixStartDNS(t, func(*fpFixDNSServer, []byte, *net.UDPAddr) {})
	r := fpFix2StartLookups(t, host, fpFix2OriginPort(t), 2)
	leader := r.onlyQuerier(t)
	waiter := r.exs[1]
	if waiter.bc == leader {
		waiter = r.exs[0]
	}
	now := r.l.nowNano()
	waiter.deadline = now + fpFix2WaiterDeadline
	r.l.sweepBackends(now + fpFix2SweepAfter)
	if !fpFix2Finished(waiter) || waiter.err != errFPTimeout {
		t.Fatalf("waiting lookup past its deadline: finished=%v err=%v", fpFix2Finished(waiter), waiter.err)
	}
	if leader.state != connResolving {
		t.Fatalf("the querier was disturbed by a waiter's timeout: state %d", leader.state)
	}
}

func TestFPFix2DNSFailureReachesEveryWaiter(t *testing.T) {
	host := fpFixHostName(t)
	s := fpFixStartDNS(t, func(s *fpFixDNSServer, query []byte, from *net.UDPAddr) {
		s.reply(from, fpFixDNSReply(query, 3))
	})
	r := fpFix2StartLookups(t, host, 80, fpFix2ConcurrentLookups)
	r.pump(t, r.onlyQuerier(t))
	for i, ex := range r.exs {
		if !fpFix2Finished(ex) || ex.err != errFPDNSFailed {
			t.Fatalf("lookup %d after NXDOMAIN: finished=%v err=%v", i, fpFix2Finished(ex), ex.err)
		}
	}
	if got := s.queries.Load(); got != 1 {
		t.Fatalf("%d DNS queries, want 1", got)
	}
}

func TestFPFix2DNSLoopCloseFailsWaiters(t *testing.T) {
	host := fpFixHostName(t)
	fpFixStartDNS(t, func(*fpFixDNSServer, []byte, *net.UDPAddr) {})
	r := fpFix2StartLookups(t, host, 80, fpFix2ConcurrentLookups)
	r.onlyQuerier(t)
	r.l.closeAll()
	for i, ex := range r.exs {
		if !fpFix2Finished(ex) || ex.err != errFPClientClosed {
			t.Fatalf("lookup %d after closeAll: finished=%v err=%v", i, fpFix2Finished(ex), ex.err)
		}
	}
	if r.l.liveConns != 0 || len(r.l.dnsInflight) != 0 {
		t.Fatalf("closeAll left liveConns=%d inflight=%d", r.l.liveConns, len(r.l.dnsInflight))
	}
}
