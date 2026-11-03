//go:build linux && amd64

package core

import (
	"bufio"
	"crypto/tls"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	perfTLSIdleConnsDefault = 1000
	perfTLSIdleSettle       = 2*epollSweepIntervalMs*time.Millisecond + 150*time.Millisecond
)

func TestPerfTLSIdleHeapProfile(t *testing.T) {
	out := os.Getenv("ALOS_PERF_IDLE_HEAP")
	if out == "" {
		t.Skip("set ALOS_PERF_IDLE_HEAP=<file> to write an in-use heap profile of idle TLS conns")
	}
	n := perfTLSIdleConnsDefault
	if v, err := strconv.Atoi(os.Getenv("ALOS_PERF_IDLE_CONNS")); err == nil && v > 0 {
		n = v
	}
	prevRate := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	defer func() { runtime.MemProfileRate = prevRate }()
	ts := newTestServer(t, testServerOptions{TLS: true, Routes: perfTLSRoutes})
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: ts.domain, NextProtos: []string{"http/1.1"}}
	request := []byte("GET /plaintext HTTP/1.1\r\nHost: " + ts.domain + "\r\n\r\n")
	conns := make([]*tls.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for range n {
		c, err := tls.Dial("tcp4", ts.addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		if _, err := c.Write(request); err != nil {
			t.Fatal(err)
		}
		if _, err := perfReadResponseBodyLen(bufio.NewReader(c)); err != nil {
			t.Fatal(err)
		}
	}
	turbo.Sleep(perfTLSIdleSettle)
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("conns=%d heapInuse=%d heapAlloc=%d", n, ms.HeapInuse, ms.HeapAlloc)
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pprof.WriteHeapProfile(f); err != nil {
		t.Fatal(err)
	}
}
