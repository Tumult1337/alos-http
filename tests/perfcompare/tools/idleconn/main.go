package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const dialTimeout = 5 * time.Second

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "server address")
	n := flag.Int("n", 10000, "connections to open and hold")
	useTLS := flag.Bool("tls", false, "use TLS (ALPN http/1.1)")
	parallel := flag.Int("p", 256, "connections opened concurrently")
	flag.Parse()

	request := []byte("GET /plaintext HTTP/1.1\r\nHost: " + *addr + "\r\n\r\n")
	tlsConfig := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	conns := make([]net.Conn, *n)
	var opened, failed atomic.Int64
	var wg sync.WaitGroup
	slots := make(chan struct{}, *parallel)
	for i := range *n {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			c, err := open(*addr, *useTLS, tlsConfig, request)
			if err != nil {
				failed.Add(1)
				return
			}
			conns[i] = c
			opened.Add(1)
		}()
	}
	wg.Wait()
	fmt.Printf("open=%d failed=%d\n", opened.Load(), failed.Load())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	for _, c := range conns {
		if c != nil {
			c.Close()
		}
	}
}

func open(addr string, useTLS bool, cfg *tls.Config, request []byte) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	raw, err := d.Dial("tcp4", addr)
	if err != nil {
		return nil, err
	}
	c := raw
	if useTLS {
		tc := tls.Client(raw, cfg)
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
		c = tc
	}
	if _, err := c.Write(request); err != nil {
		c.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return c, nil
}
