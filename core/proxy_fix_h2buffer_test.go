//go:build linux && amd64

package core

import (
	"bytes"
	"strconv"
	"testing"
)

const proxyFixHeldDeclaredLen = 32 << 20

func proxyFixH2BufferServer(t *testing.T) (*Server, string, func()) {
	t.Helper()
	release := make(chan struct{})
	o := proxyFixShapedOrigin(t, release)
	srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), nil)
	var released bool
	releaseAll := func() {
		if !released {
			released = true
			close(release)
		}
	}
	t.Cleanup(releaseAll)
	return srv, addr, releaseAll
}

func proxyFixH2Buffered(srv *Server) int64 { return srv.proxy.Load().h2Buffered.Load() }

func proxyFixSendH2(t *testing.T, c *proxyFixH2Conn, paths ...string) {
	t.Helper()
	for i, p := range paths {
		if _, err := c.Write(proxyFixH2Request(uint32(2*i+1), "GET", proxyFixDomain, p)); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
}

func TestProxyFixH2DeclaredLengthsOverConnBudgetRefused(t *testing.T) {
	_, addr, _ := proxyFixH2BufferServer(t)
	c := proxyFixH2cDial(t, addr)
	defer c.Close()
	held := "/hold/" + strconv.Itoa(proxyFixHeldDeclaredLen)
	proxyFixSendH2(t, c, held, held, held, held)

	got := c.collect(t, 2)
	refused := 0
	for sid, r := range got {
		if r.status == "503" {
			refused++
			continue
		}
		t.Fatalf("stream %d ended with status %q reset=%v, want 503 while two %d-byte bodies are pending",
			sid, r.status, r.reset, proxyFixHeldDeclaredLen)
	}
	if refused != 2 {
		t.Fatalf("%d streams refused, want 2 of 4 (%d bytes declared against the per-connection budget)", refused, 4*proxyFixHeldDeclaredLen)
	}
}

func proxyFixSetH2Budgets(t *testing.T, conn, global int64) {
	t.Helper()
	prevConn, prevGlobal := proxyH2ConnBufferBudget, proxyH2ServerBufferBudget
	proxyH2ConnBufferBudget, proxyH2ServerBufferBudget = conn, global
	t.Cleanup(func() { proxyH2ConnBufferBudget, proxyH2ServerBufferBudget = prevConn, prevGlobal })
}

const proxyFixSmallBudget = 256 << 10

func TestProxyFixH2ChunkedBodyBoundedByConnBudget(t *testing.T) {
	proxyFixSetH2Budgets(t, proxyFixSmallBudget, proxyH2ServerBufferBudget)
	_, addr, _ := proxyFixH2BufferServer(t)
	c := proxyFixH2cDial(t, addr)
	defer c.Close()
	proxyFixSendH2(t, c, "/chunked/"+strconv.Itoa(2*proxyFixSmallBudget))
	r := c.collect(t, 1)[1]
	if r.status != "503" {
		t.Fatalf("chunked body of %d bytes against a %d-byte budget: status %q, %d body bytes, want 503",
			2*proxyFixSmallBudget, proxyFixSmallBudget, r.status, len(r.body))
	}
}

func TestProxyFixH2ServerBudgetBoundsAllConns(t *testing.T) {
	proxyFixSetH2Budgets(t, proxyH2ConnBufferBudget, proxyFixSmallBudget)
	_, addr, _ := proxyFixH2BufferServer(t)
	c := proxyFixH2cDial(t, addr)
	defer c.Close()
	proxyFixSendH2(t, c, "/chunked/"+strconv.Itoa(2*proxyFixSmallBudget))
	if r := c.collect(t, 1)[1]; r.status != "503" {
		t.Fatalf("server budget: status %q, want 503", r.status)
	}
}

func TestProxyFixH2LargeBodiesDeliveredIntact(t *testing.T) {
	srv, addr, _ := proxyFixH2BufferServer(t)
	c := proxyFixH2cDial(t, addr)
	defer c.Close()
	sizes := []int{100, 200 << 10, 300 << 10, 1 << 20}
	var paths []string
	for _, n := range sizes {
		paths = append(paths, "/chunked/"+strconv.Itoa(n), "/cl/"+strconv.Itoa(n))
	}
	proxyFixSendH2(t, c, paths...)
	got := c.collect(t, len(paths))
	for i, p := range paths {
		r := got[uint32(2*i+1)]
		want := sizes[i/2]
		if r == nil || r.status != "200" || !bytes.Equal(r.body, proxyFixPattern(want)) {
			status, n := "", 0
			if r != nil {
				status, n = r.status, len(r.body)
			}
			t.Fatalf("%s: status %q with %d body bytes, want 200 with %d intact bytes", p, status, n, want)
		}
	}
	proxyFixEventually(t, "buffer budget fully released", func() bool { return proxyFixH2Buffered(srv) == 0 })
}

func TestProxyFixH2BudgetReleasedWhenClientLeaves(t *testing.T) {
	srv, addr, release := proxyFixH2BufferServer(t)
	c := proxyFixH2cDial(t, addr)
	proxyFixSendH2(t, c, "/hold/1048576")
	proxyFixEventually(t, "budget reserved for the pending body", func() bool { return proxyFixH2Buffered(srv) > 0 })
	_ = c.Close()
	release()
	proxyFixEventually(t, "budget released after the backend gave up", func() bool { return proxyFixH2Buffered(srv) == 0 })
	proxyFixAssertConnsDrain(t, srv, "h2 client left with a reserved body")
}
