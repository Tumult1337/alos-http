//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type proxyFixSeenRequest struct {
	uri     string
	headers http.Header
	body    []byte
}

type proxyFixRecordingOrigin struct {
	*inloopOrigin
	mu   sync.Mutex
	seen []proxyFixSeenRequest
}

func newProxyFixRecordingOrigin(t *testing.T) *proxyFixRecordingOrigin {
	t.Helper()
	o := &proxyFixRecordingOrigin{}
	o.inloopOrigin = newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		body, _ := io.ReadAll(req.Body)
		o.mu.Lock()
		o.seen = append(o.seen, proxyFixSeenRequest{uri: req.RequestURI, headers: req.Header.Clone(), body: body})
		o.mu.Unlock()
		reply := "BACKEND:" + req.RequestURI
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s", len(reply), reply)
	})
	return o
}

func (o *proxyFixRecordingOrigin) requests() []proxyFixSeenRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]proxyFixSeenRequest(nil), o.seen...)
}

const proxyFixRoutePrefix = "/public/"

func proxyFixPort80Route(t *testing.T) (*proxyFixRecordingOrigin, string) {
	t.Helper()
	o := newProxyFixRecordingOrigin(t)
	_, _, httpAddr := proxyFixStartTLS(t, Config{MaxConnsPerIP: -1}, func(s *Server) {
		s.SetHTTPRoutes([]HTTPRoute{{PathPrefix: proxyFixRoutePrefix, Backend: o.addr()}})
	})
	return o, httpAddr
}

func proxyFixRawExchange(t *testing.T, addr, raw string) string {
	t.Helper()
	c := proxyFixDial(t, addr)
	defer c.Close()
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, _ := io.ReadAll(c)
	return string(out)
}

func TestProxyFixPort80RouteRejectsTraversalOutOfPrefix(t *testing.T) {
	for _, target := range []string{
		"/public/../internal/admin",
		"/public/x/../../internal/admin",
		"/public/%2e%2e/internal/admin",
		"/public/%2E%2e/internal/admin",
		"/public/..%2finternal/admin",
		"/public//../internal/admin",
	} {
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			o, addr := proxyFixPort80Route(t)
			out := proxyFixRawExchange(t, addr, "GET "+target+" HTTP/1.1\r\nHost: "+proxyFixTLSDomain+"\r\n\r\n")
			for _, r := range o.requests() {
				if !strings.HasPrefix(r.uri, proxyFixRoutePrefix) || strings.Contains(r.uri, "..") || strings.Contains(strings.ToLower(r.uri), "%2e") {
					t.Fatalf("%s reached the backend as %q (response %q)", target, r.uri, firstLine(out))
				}
			}
			if strings.HasPrefix(out, "HTTP/1.1 200") {
				t.Fatalf("%s was proxied: %q", target, firstLine(out))
			}
		})
	}
}

func TestProxyFixPort80RouteForwardsOnlyOneRequest(t *testing.T) {
	o, addr := proxyFixPort80Route(t)
	raw := "GET /public/a HTTP/1.1\r\nHost: " + proxyFixTLSDomain + "\r\n\r\n" +
		"GET /internal/secret HTTP/1.1\r\nHost: " + proxyFixTLSDomain + "\r\n\r\n"
	out := proxyFixRawExchange(t, addr, raw)
	if !strings.Contains(out, "BACKEND:/public/a") {
		t.Fatalf("first request not answered: %q", out)
	}
	for _, r := range o.requests() {
		if r.uri != "/public/a" {
			t.Fatalf("pipelined request reached the backend as %q", r.uri)
		}
	}
}

func TestProxyFixPort80RouteFiltersHeaders(t *testing.T) {
	o, addr := proxyFixPort80Route(t)
	raw := "GET /public/h HTTP/1.1\r\nHost: " + proxyFixTLSDomain + "\r\n" +
		"Connection: X-Secret\r\nX-Secret: leak\r\nX-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\nTE: trailers\r\n\r\n"
	out := proxyFixRawExchange(t, addr, raw)
	reqs := o.requests()
	if len(reqs) != 1 {
		t.Fatalf("backend saw %d requests (response %q)", len(reqs), firstLine(out))
	}
	h := reqs[0].headers
	if h.Get("X-Secret") != "" || h.Get("Te") != "" {
		t.Fatalf("hop-by-hop headers relayed: X-Secret=%q TE=%q", h.Get("X-Secret"), h.Get("Te"))
	}
	if xff := h.Get("X-Forwarded-For"); xff != "127.0.0.1" {
		t.Fatalf("backend X-Forwarded-For = %q, want the real client 127.0.0.1", xff)
	}
	if xri := h.Get("X-Real-Ip"); xri == "6.6.6.6" {
		t.Fatalf("client-supplied X-Real-IP relayed")
	}
}

const proxyFixRouteBodySize = 200 << 10

func TestProxyFixPort80RouteRelaysWholeBody(t *testing.T) {
	o, addr := proxyFixPort80Route(t)
	body := bytes.Repeat([]byte("b"), proxyFixRouteBodySize)
	c := proxyFixDial(t, addr)
	defer c.Close()
	head := fmt.Sprintf("POST /public/upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", proxyFixTLSDomain, len(body))
	if _, err := io.WriteString(c, head); err != nil {
		t.Fatalf("write head: %v", err)
	}
	time.Sleep(proxyFixStep)
	if _, err := c.Write(body); err != nil {
		t.Fatalf("write body: %v", err)
	}
	resp, rbody := proxyFixReadResponse(t, bufio.NewReader(c))
	if resp.StatusCode != http.StatusOK || rbody != "BACKEND:/public/upload" {
		t.Fatalf("status %d body %q", resp.StatusCode, rbody)
	}
	reqs := o.requests()
	if len(reqs) != 1 || !bytes.Equal(reqs[0].body, body) {
		got := -1
		if len(reqs) == 1 {
			got = len(reqs[0].body)
		}
		t.Fatalf("backend received %d body bytes, want %d", got, len(body))
	}
}

func TestProxyFixPort80RouteServesNormalRequest(t *testing.T) {
	_, addr := proxyFixPort80Route(t)
	out := proxyFixRawExchange(t, addr, "GET /public/ok?x=1 HTTP/1.1\r\nHost: "+proxyFixTLSDomain+"\r\n\r\n")
	if !strings.HasPrefix(out, "HTTP/1.1 200") || !strings.HasSuffix(out, "BACKEND:/public/ok?x=1") {
		t.Fatalf("routed request: %q", out)
	}
}

func TestProxyFixHTTPRoutesDoNotCaptureTLSRequests(t *testing.T) {
	o := newProxyFixRecordingOrigin(t)
	_, httpsAddr, _ := proxyFixStartTLS(t, Config{MaxConnsPerIP: -1}, func(s *Server) {
		s.SetHTTPRoutes([]HTTPRoute{{PathPrefix: "/", Backend: o.addr()}})
		s.Router.GET("/account", func(req *Request, resp *Response) { resp.String("router") })
	})
	for _, proto := range []string{"http/1.1", "h2"} {
		client := &http.Client{Timeout: proxyFixIOTimeout, Transport: &http.Transport{
			ForceAttemptHTTP2: proto == "h2",
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: proxyFixTLSDomain, NextProtos: []string{proto}},
		}}
		req, _ := http.NewRequest("GET", "https://"+httpsAddr+"/account", nil)
		req.Host = proxyFixTLSDomain
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if wantMajor := map[string]int{"http/1.1": 1, "h2": 2}[proto]; resp.ProtoMajor != wantMajor {
			t.Fatalf("%s: negotiated HTTP/%d", proto, resp.ProtoMajor)
		}
		if string(body) != "router" {
			t.Fatalf("%s https /account answered %q by the port-80 route backend, want the Router", proto, body)
		}
	}
	if n := len(o.requests()); n != 0 {
		t.Fatalf("port-80 route backend received %d HTTPS requests", n)
	}
}

func TestProxyFixPlainListenerRouteRejectsEncodedTraversal(t *testing.T) {
	o := newProxyFixRecordingOrigin(t)
	_, addr := proxyFixStart(t, Config{}, nil, func(s *Server) {
		s.SetHTTPRoutes([]HTTPRoute{{PathPrefix: proxyFixRoutePrefix, Backend: o.addr()}})
	})
	for _, target := range []string{"/public/%2e%2e/internal/admin", "/public/..%2Finternal", `/public/a\..\b`} {
		proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, target))
	}
	if _, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/public/ok")); body != "BACKEND:/public/ok" {
		t.Fatalf("canonical route target answered %q", body)
	}
	for _, r := range o.requests() {
		if r.uri != "/public/ok" {
			t.Fatalf("encoded traversal %q reached the route backend", r.uri)
		}
	}
}
