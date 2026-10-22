//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"

	"github.com/guno1928/turbo"
)

const perfH1ScratchH1Loaders = 8

func TestPerfH1CouldBeH2Preface(t *testing.T) {
	preface := string(H2ClientPreface[:])
	cases := []struct {
		in   string
		want bool
	}{
		{"", true},
		{"P", true},
		{preface[:10], true},
		{preface, true},
		{preface + "\x00\x00\x00\x04", true},
		{"POST / HTTP/1.1\r\n", false},
		{"GET / HTTP/1.1\r\n", false},
		{"PRI * HTTP/1.1\r\n", false},
	}
	for _, tc := range cases {
		if got := couldBeH2Preface([]byte(tc.in)); got != tc.want {
			t.Fatalf("couldBeH2Preface(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func perfH1ScratchH1Loader(addr string, stop <-chan struct{}) error {
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(perfH1IODeadline))
	br := bufio.NewReader(conn)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		if _, err := conn.Write([]byte("GET /ok HTTP/1.1\r\nHost: h\r\n\r\n")); err != nil {
			return err
		}
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("h1 status %d", resp.StatusCode)
		}
	}
}

func TestPerfH1ScratchSplitH2cPrefaceIsKeptOwned(t *testing.T) {
	addr := startPlainH2Server(t)
	stop := make(chan struct{})
	errs := make(chan error, perfH1ScratchH1Loaders)
	var wg sync.WaitGroup
	for i := 0; i < perfH1ScratchH1Loaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := perfH1ScratchH1Loader(addr, stop); err != nil {
				errs <- err
			}
		}()
	}
	defer func() {
		close(stop)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("h1 loader: %v", err)
		}
	}()

	for split := 1; split < H2PrefaceLen; split += 3 {
		conn, err := net.Dial("tcp4", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_ = conn.SetDeadline(wallDeadline(perfH1IODeadline))
		rc := &h2RawConn{t: t, conn: conn}
		if _, err := conn.Write(H2ClientPreface[:split]); err != nil {
			t.Fatalf("split %d: preface head: %v", split, err)
		}
		turbo.Sleep(perfH1ScratchHold)
		if _, err := conn.Write(H2ClientPreface[split:]); err != nil {
			t.Fatalf("split %d: preface tail: %v", split, err)
		}
		rc.write(H2FrameSettings, 0, 0, nil)
		for {
			f := rc.read()
			if f.typ == H2FrameSettings && f.flags&H2FlagAck == 0 {
				rc.write(H2FrameSettings, H2FlagAck, 0, nil)
				break
			}
		}
		block := []byte{0x82, 0x86}
		block = append(block, hpackLiteralWithIndexing(4, "/ok")...)
		block = append(block, hpackLiteralWithIndexing(1, "split.test")...)
		rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, block)
		f, err := rc.awaitStreamOutcome(1)
		if err != nil {
			t.Fatalf("split %d: %v", split, err)
		}
		if f.typ != H2FrameHeaders || h2RawStatusFromHeaders(t, f.payload) != http.StatusOK {
			t.Fatalf("split %d: frame type %d, want a 200 HEADERS", split, f.typ)
		}
		_ = conn.Close()
	}
}
