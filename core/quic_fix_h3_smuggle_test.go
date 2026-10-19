//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
)

type quicFixRecordingOrigin struct {
	ln       net.Listener
	mu       sync.Mutex
	requests []string
}

func newQUICFixRecordingOrigin(t *testing.T) *quicFixRecordingOrigin {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &quicFixRecordingOrigin{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go o.serve()
	return o
}

func (o *quicFixRecordingOrigin) serve() {
	for {
		conn, err := o.ln.Accept()
		if err != nil {
			return
		}
		go o.serveConn(conn)
	}
}

func (o *quicFixRecordingOrigin) serveConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		o.mu.Lock()
		o.requests = append(o.requests, req.Method+" "+req.URL.RequestURI())
		o.mu.Unlock()
		if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
			return
		}
	}
}

func (o *quicFixRecordingOrigin) seen() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.requests...)
}

func TestQUICFixH3CRLFCannotSmuggleUpstreamRequest(t *testing.T) {
	origin := newQUICFixRecordingOrigin(t)
	p := newQUICFixPeer(t, nil)
	p.srv.AddProxyDomain(DomainConfig{Domain: "app.test", Backends: []BackendConfig{{Addr: origin.ln.Addr().String()}}})
	request := func(extra ...[2]string) []byte {
		fields := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "app.test"}, {":path", "/ok"}}
		return h3AppendHeadersFrame(nil, quicFixQPACKBlock(append(fields, extra...)...))
	}

	quicFixSendRequest(p, 0, request([2]string{"x-a", "1\r\n\r\nGET /smuggled HTTP/1.1\r\nhost: app.test\r\nx-forwarded-for: 127.0.0.1\r\nx-pad: z"}))
	if got := quicFixResponseStatus(t, p, 0); got != 400 {
		t.Errorf("smuggling request: status %d, want 400", got)
	}
	if seen := origin.seen(); len(seen) != 0 {
		t.Fatalf("CRLF in an H3 field reached the HTTP/1.1 backend as %q", seen)
	}

	quicFixSendRequest(p, 4, request([2]string{"x-a", "1"}))
	if got := quicFixResponseStatus(t, p, 4); got != 200 {
		t.Fatalf("clean proxied request: status %d, want 200", got)
	}
	if seen := origin.seen(); len(seen) != 1 || seen[0] != "GET /ok" {
		t.Fatalf("backend saw %q, want exactly [GET /ok]", seen)
	}
}
