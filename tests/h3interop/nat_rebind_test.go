package h3interop

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/guno1928/alos-http/core"
)

const (
	relayBufSize        = 65535
	rebindDownload      = 8 << 20
	rebindAfterBytes    = 1 << 20
	relayReadChunk      = 32 << 10
	quicRetryHeaderMask = 0xf0
)

type natRelay struct {
	front    *net.UDPConn
	server   *net.UDPAddr
	mu       sync.Mutex
	back     *net.UDPConn
	client   *net.UDPAddr
	rebinds  atomic.Int32
	retries  atomic.Int32
	closed   atomic.Bool
	impair   relayImpairment
	upstream []string
}

func newNATRelay(t *testing.T, server string) *natRelay {
	t.Helper()
	return newImpairedRelay(t, server, relayImpairment{})
}

func newImpairedRelay(t *testing.T, server string, impair relayImpairment) *natRelay {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		t.Fatal(err)
	}
	r := &natRelay{front: front, server: serverAddr, impair: impair}
	r.rebind(t)
	go r.forwardFromClient()
	t.Cleanup(r.close)
	return r
}

func (r *natRelay) addr() string { return r.front.LocalAddr().String() }

func (r *natRelay) rebind(t *testing.T) {
	t.Helper()
	back, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	old := r.back
	r.back = back
	r.upstream = append(r.upstream, back.LocalAddr().String())
	r.mu.Unlock()
	if old != nil {
		old.Close()
		r.rebinds.Add(1)
	}
	go r.forwardFromServer(back)
}

func (r *natRelay) forwardFromClient() {
	buf := make([]byte, relayBufSize)
	shaper := relayShaper{cfg: r.impair}
	for {
		n, from, err := r.front.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.client = from
		back := r.back
		r.mu.Unlock()
		shaper.shape(buf[:n], func(pkt []byte) { _, _ = back.WriteToUDP(pkt, r.server) })
	}
}

func (r *natRelay) forwardFromServer(back *net.UDPConn) {
	buf := make([]byte, relayBufSize)
	shaper := relayShaper{cfg: r.impair}
	for {
		n, err := back.Read(buf)
		if err != nil {
			return
		}
		if n > 0 && buf[0]&quicRetryHeaderMask == quicRetryHeaderMask {
			r.retries.Add(1)
		}
		r.mu.Lock()
		client := r.client
		r.mu.Unlock()
		if client != nil {
			shaper.shape(buf[:n], func(pkt []byte) { _, _ = r.front.WriteToUDP(pkt, client) })
		}
	}
}

func (r *natRelay) close() {
	if r.closed.Swap(true) {
		return
	}
	r.front.Close()
	r.mu.Lock()
	if r.back != nil {
		r.back.Close()
	}
	r.mu.Unlock()
}

func TestH3SurvivesNATRebindingMidTransfer(t *testing.T) {
	hs := startH3(t, core.Config{})
	relay := newNATRelay(t, hs.addr)
	c := newClient(t)
	resp, err := c.Get(fmt.Sprintf("https://%s/big/%d", relay.addr(), rebindDownload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, relayReadChunk)
	total := 0
	for {
		n, err := resp.Body.Read(buf)
		for _, b := range buf[:n] {
			if b != 'y' {
				t.Fatalf("corrupt byte %q at offset %d", b, total)
			}
		}
		before := total
		total += n
		if before < rebindAfterBytes && total >= rebindAfterBytes {
			relay.rebind(t)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("download failed after %d bytes (rebinds %d, upstream %v): %v", total, relay.rebinds.Load(), relay.upstream, err)
		}
	}
	if total != rebindDownload || relay.rebinds.Load() != 1 {
		t.Fatalf("downloaded %d of %d bytes across %d rebinds", total, rebindDownload, relay.rebinds.Load())
	}
	status, body, err := doGet(c, relay.addr(), "/ping")
	if err != nil || status != 200 || string(body) != "pong" {
		t.Fatalf("connection unusable after the rebind: %d %q %v", status, body, err)
	}
}
