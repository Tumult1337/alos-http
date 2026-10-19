//go:build linux && amd64

package core

import (
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const fpFixDNSPoll = 15 * time.Millisecond

type fpFixDNSServer struct {
	conn    *net.UDPConn
	queries atomic.Int64
}

func fpFixStartDNS(t *testing.T, answer func(s *fpFixDNSServer, query []byte, from *net.UDPAddr)) *fpFixDNSServer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("dns listen: %v", err)
	}
	s := &fpFixDNSServer{conn: conn}
	go func() {
		buf := make([]byte, dnsMaxDatagram)
		for {
			n, from, rerr := conn.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			s.queries.Add(1)
			answer(s, append([]byte(nil), buf[:n]...), from)
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	fpDNSConfigOnce.Do(fpLoadDNSConfig)
	saved := fpDNSServers
	fpDNSServers = []netip.AddrPort{conn.LocalAddr().(*net.UDPAddr).AddrPort()}
	t.Cleanup(func() { fpDNSServers = saved })
	return s
}

func (s *fpFixDNSServer) reply(to *net.UDPAddr, msg []byte) {
	_, _ = s.conn.WriteToUDP(msg, to)
}

func fpFixDNSReply(query []byte, rcode byte, records ...[]byte) []byte {
	msg := []byte{query[0], query[1], 0x81, 0x80 | rcode, 0, 1, 0, byte(len(records)), 0, 0, 0, 0}
	_, questionEnd := fpReadDNSName(query, dnsHeaderLen)
	msg = append(msg, query[dnsHeaderLen:questionEnd+dnsQuestionFixedLen]...)
	for _, rec := range records {
		msg = append(msg, rec...)
	}
	return msg
}

func fpFixARecord(ip [4]byte) []byte {
	return dnsRecord(dnsTypeA, 60, ip[:])
}

func fpFixHostName(t *testing.T) string {
	host := strings.ToLower(strings.NewReplacer("/", "-", "_", "-").Replace(t.Name())) + ".fpfix.test"
	t.Cleanup(func() { fpDNSCache.Delete(host) })
	return host
}

func fpFixWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := turbo.Deadline(fpFixTestTimeout)
	for !cond() {
		if turbo.Until(deadline) <= 0 {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(fpFixDNSPoll)
	}
}

func fpFixLoopbackOrigin(t *testing.T) (string, string) {
	t.Helper()
	addr := rawOrigin(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("origin addr %q: %v", addr, err)
	}
	return addr, port
}

func fpFixClientGet(t *testing.T, authority string) (*fpResponse, error) {
	t.Helper()
	c, err := fpNew(fpConfig{Loops: 1, RequestTimeout: fpFixTestTimeout})
	if err != nil {
		t.Fatalf("fpNew: %v", err)
	}
	defer c.Close()
	return c.Do(&fpRequest{Scheme: "http", Authority: authority, Method: "GET", Path: "/"})
}

func TestFPFixDNSParserRejectsMalformedAndUnrelated(t *testing.T) {
	a := fpFixARecord([4]byte{10, 0, 0, 7})
	notResponse := dnsAnswer(7, a)
	notResponse[2] &^= dnsFlagResponse
	nxdomain := dnsAnswer(7, a)
	nxdomain[3] |= 3
	truncated := dnsAnswer(7, a)
	truncated[2] |= dnsFlagTruncated
	truncated = truncated[:len(truncated)-2]
	otherQuestion := []byte{0, 7, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 5, 'e', 'v', 'i', 'l', 'x', 0, 0, 1, 0, 1}
	otherQuestion = append(otherQuestion, a...)
	runsOffEnd := make([]byte, 270)
	copy(runsOffEnd, []byte{0, 7, 0x81, 0x00, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0})
	for _, at := range []int{14, 78, 142, 206} {
		runsOffEnd[at] = dnsMaxLabelLen
	}
	pointerAtEnd := append(dnsAnswer(7), 0xc0)
	pointerAtEnd[7] = 1
	pointerLoop := append(dnsAnswer(7), 0xc0, byte(len(dnsAnswer(7))))
	pointerLoop[7] = 1
	strangerOwner := append(dnsAnswer(7), 5, 'o', 't', 'h', 'e', 'r', 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 6, 6, 6, 6)
	strangerOwner[7] = 1
	for _, tc := range []struct {
		name string
		msg  []byte
		want error
	}{
		{"not a response", notResponse, errFPDNSUnrelated},
		{"answers another question", otherQuestion, errFPDNSUnrelated},
		{"question runs off the end", runsOffEnd, errFPDNSUnrelated},
		{"nxdomain", nxdomain, errFPDNSFailed},
		{"truncated", truncated, errFPDNSFailed},
		{"compression pointer cut off", pointerAtEnd, errFPDNSFailed},
		{"compression pointer loop", pointerLoop, errFPDNSFailed},
		{"record for a name outside the chain", strangerOwner, errFPDNSNoAddress},
	} {
		if addr, _, err := fpParseDNSResponse(tc.msg, 7, dnsTypeA, "origin.test"); err != tc.want {
			t.Errorf("%s: %v %v, want %v", tc.name, addr, err, tc.want)
		}
	}
}

func TestFPFixDNSParserFollowsCNAMEChain(t *testing.T) {
	cname := dnsRecord(dnsTypeCNAME, 60, []byte{3, 'f', 'o', 'o', 0})
	target := append([]byte{3, 'F', 'O', 'O', 0}, 0, 1, 0, 1, 0, 0, 0, 90, 0, 4, 10, 0, 0, 9)
	msg := dnsAnswer(7, cname, target)
	addr, ttl, err := fpParseDNSResponse(msg, 7, dnsTypeA, "origin.test")
	if err != nil || addr != netip.MustParseAddr("10.0.0.9") || ttl != 90 {
		t.Fatalf("chain answer: %v ttl %d %v", addr, ttl, err)
	}
}

func TestFPFixDNSResolvesInLoopAndIgnoresSpoofedReplies(t *testing.T) {
	_, port := fpFixLoopbackOrigin(t)
	host := fpFixHostName(t)
	forger, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("forger listen: %v", err)
	}
	defer forger.Close()
	spoofed := fpFixARecord([4]byte{127, 0, 0, 3})
	fpFixStartDNS(t, func(s *fpFixDNSServer, query []byte, from *net.UDPAddr) {
		_, _ = forger.WriteToUDP(fpFixDNSReply(query, 0, spoofed), from)
		wrongID := fpFixDNSReply(query, 0, spoofed)
		wrongID[0] ^= 0xff
		s.reply(from, wrongID)
		s.reply(from, fpFixDNSReply(query, 0, fpFixARecord([4]byte{127, 0, 0, 1})))
	})
	resp, err := fpFixClientGet(t, host+":"+port)
	if err != nil || resp.Status != 200 || string(resp.Body) != "ok" {
		t.Fatalf("resolved request: %v %+v", err, resp)
	}
	if e, ok := fpDNSCache.Load(host); !ok || e.ip != fpLoopbackIPv4 {
		t.Fatalf("cache holds %+v, want the genuine answer", e)
	}
}

func TestFPFixDNSFailureIsNegativelyCached(t *testing.T) {
	host := fpFixHostName(t)
	s := fpFixStartDNS(t, func(s *fpFixDNSServer, query []byte, from *net.UDPAddr) {
		s.reply(from, fpFixDNSReply(query, 3))
	})
	if _, err := fpFixClientGet(t, host+":80"); err != errFPDNSFailed {
		t.Fatalf("first lookup err = %v, want errFPDNSFailed", err)
	}
	asked := s.queries.Load()
	start := turbo.Now()
	if _, err := fpFixClientGet(t, host+":80"); err != errFPDNSFailed {
		t.Fatalf("cached failure err = %v, want errFPDNSFailed", err)
	}
	if s.queries.Load() != asked {
		t.Fatalf("a negatively cached name was queried again (%d -> %d queries)", asked, s.queries.Load())
	}
	if took := turbo.Since(start); took > fpFixFastLimit {
		t.Fatalf("cached failure took %v", took)
	}
}

func TestFPFixDNSServesStaleAnswerWhenResolverFails(t *testing.T) {
	_, port := fpFixLoopbackOrigin(t)
	host := fpFixHostName(t)
	fpStoreDNS(host, fpLoopbackIPv4, turbo.UnixNano()-1)
	fpFixStartDNS(t, func(s *fpFixDNSServer, query []byte, from *net.UDPAddr) {
		s.reply(from, fpFixDNSReply(query, 2))
	})
	resp, err := fpFixClientGet(t, host+":"+port)
	if err != nil || resp.Status != 200 {
		t.Fatalf("stale fallback: %v %+v", err, resp)
	}
}

func TestFPFixDNSQueryTimeoutMovesOn(t *testing.T) {
	host := fpFixHostName(t)
	s := fpFixStartDNS(t, func(*fpFixDNSServer, []byte, *net.UDPAddr) {})
	l := newLoopForTest()
	l.cfg.fill(1)
	ep, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatalf("epoll: %v", err)
	}
	defer unix.Close(ep)
	l.ep = ep
	ex := &Exchange{req: &fpRequest{Method: "GET"}, done: make(chan struct{}), port: 80, key: poolKey{authority: host + ":80"}}
	ex.deadline = l.nowNano() + int64(time.Hour)
	l.newConn(ex)
	c := ex.bc
	if c == nil || c.state != connResolving {
		t.Fatalf("exchange is not waiting on dns: %+v", c)
	}
	fpFixWaitFor(t, "the query", func() bool { return s.queries.Load() == 1 })
	l.sweepBackends(c.dns.deadline + 1)
	select {
	case <-ex.done:
	default:
		t.Fatal("an unanswered query did not move on once its attempt timed out")
	}
	if ex.err != errFPDNSFailed {
		t.Fatalf("err = %v, want errFPDNSFailed", ex.err)
	}
}

const fpFixFastLimit = 150 * time.Millisecond
