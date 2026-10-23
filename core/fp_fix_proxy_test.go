//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

func fpFixStartProxy(t *testing.T, backendAddr string, tune func(*ProxyEngine)) string {
	t.Helper()
	addr := freeLoopbackAddr(t)
	srv := New(Config{Addr: addr, PlainHTTP: true, HTTPAddr: "-", Listeners: 1, MaxConnsPerIP: -1})
	srv.AddProxyDomain(DomainConfig{Domain: "origin.test", Backends: []BackendConfig{{Addr: backendAddr}}})
	if tune != nil {
		tune(srv.proxy.Load())
	}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), fpFixShutdownWait)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	waitForPort(t, addr)
	return addr
}

func fpFixGet(addr, host, path string) (int, string, error) {
	req, err := http.NewRequest("GET", "http://"+addr+path, nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = host
	client := &http.Client{Timeout: fpFixTestTimeout, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

func fpFixRawExchange(t *testing.T, addr, request string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, fpFixTestTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Unix(0, turbo.UnixNano()+int64(fpFixTestTimeout)))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write: %v", err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	return strings.TrimSpace(status)
}

func fpFixUpgradeOrigin(t *testing.T, answer string) string {
	t.Helper()
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.WriteString(conn, answer)
		_, _ = io.Copy(conn, br)
	})
	return o.addr()
}

func TestFPFixProxyRefusesUnrequestedOrMismatchedUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answer  string
		request string
	}{
		{
			"101 without client upgrade",
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
			"GET /status?code=101 HTTP/1.1\r\nHost: origin.test\r\n\r\n",
		},
		{
			"h2c upgrade",
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: origin.test\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n",
		},
		{
			"backend switches to an unrequested protocol",
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: other\r\nConnection: Upgrade\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: origin.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
		},
		{
			"backend 101 without an upgrade header",
			"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: origin.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := fpFixStartProxy(t, fpFixUpgradeOrigin(t, tc.answer), nil)
			if status := fpFixRawExchange(t, addr, tc.request); !strings.HasPrefix(status, "HTTP/1.1 502") {
				t.Fatalf("status line %q, want 502", status)
			}
		})
	}
}

func TestFPFixProxyStillTunnelsRequestedUpgrade(t *testing.T) {
	answer := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\r\n"
	addr := fpFixStartProxy(t, fpFixUpgradeOrigin(t, answer), nil)
	request := "GET /ws HTTP/1.1\r\nHost: origin.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if status := fpFixRawExchange(t, addr, request); status != "HTTP/1.1 101 Switching Protocols" {
		t.Fatalf("status line %q", status)
	}
}

func TestFPFixWorkerSurvivesResponseHookPanic(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("ok"))
	addr := fpFixStartProxy(t, o.addr(), func(pe *ProxyEngine) {
		pe.OnResponse = func(pr *ProxyResponse) {
			if pr.Path == "/boom" {
				panic("fpfix response hook")
			}
		}
	})
	boom, err := net.DialTimeout("tcp", addr, fpFixTestTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = boom.SetDeadline(time.Unix(0, turbo.UnixNano()+int64(fpFixHookPanicWait)))
	_, _ = io.WriteString(boom, "GET /boom HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	_, _ = io.Copy(io.Discard, boom)
	_ = boom.Close()
	status, body, err := fpFixGet(addr, "origin.test", "/ok")
	if err != nil || status != 200 || body != "ok" {
		t.Fatalf("after a recovered hook panic: %d %q %v", status, body, err)
	}
}

const (
	fpFixHookPanicWait = 150 * time.Millisecond
	fpFixShutdownWait  = 150 * time.Millisecond
)

func TestFPFixDNSLookupDoesNotStallWorker(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("resolved"))
	_, port, err := net.SplitHostPort(o.addr())
	if err != nil {
		t.Fatalf("origin addr: %v", err)
	}
	host := fpFixHostName(t)
	held := make(chan func(), 1)
	fpFixStartDNS(t, func(s *fpFixDNSServer, query []byte, from *net.UDPAddr) {
		select {
		case held <- func() { s.reply(from, fpFixDNSReply(query, 0, fpFixARecord([4]byte{127, 0, 0, 1}))) }:
		default:
		}
	})
	addr := fpFixStartProxy(t, host+":"+port, nil)
	proxied := make(chan string, 1)
	go func() {
		_, body, derr := fpFixGet(addr, "origin.test", "/x")
		if derr != nil {
			body = derr.Error()
		}
		proxied <- body
	}()
	var answer func()
	select {
	case answer = <-held:
	case <-time.After(fpFixTestTimeout):
		t.Fatal("the proxy never sent its dns query")
	}
	start := turbo.Now()
	if _, _, err := fpFixGet(addr, "other.test", "/unrelated"); err != nil {
		t.Fatalf("unrelated request while dns pending: %v", err)
	}
	if took := turbo.Since(start); took > fpFixFastLimit {
		t.Fatalf("unrelated request on the same worker took %v while dns was pending", took)
	}
	answer()
	if got := <-proxied; got != "resolved" {
		t.Fatalf("proxied request after the dns answer: %q", got)
	}
}
