//go:build linux && amd64

package core

import (
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

const fpG2InterimHead = "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"

func fpG2InterimResponse(interim int) string {
	return strings.Repeat(fpG2InterimHead, interim) + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
}

func TestFPH1UpstreamCapsInterimResponses(t *testing.T) {
	c := fpFixH1Conn(fpG2InterimResponse(5))
	if done, err := c.h1.advance(c); err != nil || !done || c.h1.status != 200 || string(c.h1.body) != "ok" {
		t.Fatalf("5 interim responses: done=%v err=%v status=%d body=%q", done, err, c.h1.status, c.h1.body)
	}
	c = fpFixH1Conn(fpG2InterimResponse(6))
	if done, err := c.h1.advance(c); err == nil || done {
		t.Fatalf("6 interim responses: done=%v err=%v, want an upstream error", done, err)
	}
	c = fpFixH1Conn(fpG2InterimResponse(5))
	if _, err := c.h1.advance(c); err != nil {
		t.Fatalf("first response: %v", err)
	}
	c.h1.reset()
	c.rbuf.write([]byte(fpG2InterimResponse(5)))
	if done, err := c.h1.advance(c); err != nil || !done {
		t.Fatalf("the interim count leaked into the next response on the connection: done=%v err=%v", done, err)
	}
}

func TestFPH1UpgradeAnswerCapsInterimResponses(t *testing.T) {
	for _, tc := range []struct {
		interim int
		reject  bool
	}{{5, false}, {6, true}} {
		client, server := net.Pipe()
		go func() {
			_, _ = server.Write([]byte(strings.Repeat(fpG2InterimHead, tc.interim) + "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		}()
		var p h1Parser
		_, _, err := readUpgradeAnswer(client, &p, "GET", time.Second)
		if tc.reject && err == nil {
			t.Errorf("%d interim responses before the upgrade answer were accepted", tc.interim)
		}
		if !tc.reject && (err != nil || p.status != 101) {
			t.Errorf("%d interim responses: status=%d err=%v", tc.interim, p.status, err)
		}
		_ = client.Close()
		_ = server.Close()
	}
}

func TestFPH2UpstreamCapsInterimResponses(t *testing.T) {
	interims := func(n int) []fpG2Frame {
		frames := make([]fpG2Frame, 0, n+1)
		for range n {
			frames = append(frames, fpG2Headers(0, fpG2Status("103")))
		}
		return frames
	}
	ex, rec := fpG2Run(t, append(interims(5), fpG2Headers(h2FlagEndStream, fpG2Status("200")))...)
	if ex.err != nil || ex.resp.Status != 200 || len(rec.rstCodes()) != 0 {
		t.Fatalf("5 interim blocks: status=%d err=%v rst=%v", ex.resp.Status, ex.err, rec.rstCodes())
	}
	ex, rec = fpG2Run(t, interims(6)...)
	if !fpFixExchangeFailed(ex) {
		t.Fatalf("a 6th interim block was accepted")
	}
	if got := rec.rstCodes(); !slices.Equal(got, []uint32{H2ErrProtocol}) {
		t.Fatalf("RST_STREAM codes %v, want [PROTOCOL_ERROR]", got)
	}
}
