//go:build linux && amd64

package core

import (
	"net"
	"testing"
)

func TestQUICFixH3RequestCountedOnce(t *testing.T) {
	srv := New(Config{})
	srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	srv.Router.Build()
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	qc := newQUICConn(srv, quicFixDiscardConn{}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}, dcid, dcid)
	qc.maxDataRemote = quicFixUnlimitedCredit
	qc.handshakeDone.Store(true)
	qc.addressValidated.Store(true)
	newH3Conn(qc)
	t.Cleanup(qc.close)
	request := h3AppendHeadersFrame(nil, quicFixGET("/ok"))
	rawBefore, totalBefore := Stats.RawReqs.Load(), Stats.TotalReqs.Load()
	quicFixServeOnce(qc, request)
	if raw, total := Stats.RawReqs.Load()-rawBefore, Stats.TotalReqs.Load()-totalBefore; raw != 1 || total != 1 {
		t.Fatalf("one HTTP/3 request counted RawReqs=%d TotalReqs=%d, want 1 and 1", raw, total)
	}
}
