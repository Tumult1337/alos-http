//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	tlsEpollFixEMFILEChildEnv  = "TLSEPOLLFIX_EMFILE_CHILD"
	tlsEpollFixEMFILEHeadroom  = 8
	tlsEpollFixEMFILEDials     = 48
	tlsEpollFixEMFILEWindow    = 600 * time.Millisecond
	tlsEpollFixEMFILEMaxTicks  = 15
	tlsEpollFixProcStatUTime   = 13
	tlsEpollFixProcStatSTime   = 14
	tlsEpollFixProcStatCommEnd = ") "
)

func tlsEpollFixEMFILEChild(t *testing.T) {
	ts := newTestServer(t, testServerOptions{Config: func(c *Config) { c.MaxConnsPerIP = -1 }})
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	lim.Cur = uint64(len(entries) + tlsEpollFixEMFILEHeadroom)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	fmt.Println("ADDR", ts.addr)
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func tlsEpollFixProcCPUTicks(t *testing.T, pid int) int {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	stat := string(raw)
	fields := strings.Fields(stat[strings.LastIndex(stat, tlsEpollFixProcStatCommEnd)+len(tlsEpollFixProcStatCommEnd):])
	utime, _ := strconv.Atoi(fields[tlsEpollFixProcStatUTime-2])
	stime, _ := strconv.Atoi(fields[tlsEpollFixProcStatSTime-2])
	return utime + stime
}

func TestTLSEpollFixAcceptEMFILEDoesNotSpin(t *testing.T) {
	if os.Getenv(tlsEpollFixEMFILEChildEnv) == "1" {
		tlsEpollFixEMFILEChild(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTLSEpollFixAcceptEMFILEDoesNotSpin$")
	cmd.Env = append(os.Environ(), tlsEpollFixEMFILEChildEnv+"=1", "GOMAXPROCS=2")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	lines := bufio.NewScanner(stdout)
	addr := ""
	for lines.Scan() {
		if after, ok := strings.CutPrefix(lines.Text(), "ADDR "); ok {
			addr = after
			break
		}
	}
	if addr == "" {
		t.Fatal("child server never reported its address")
	}
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for i := 0; i < tlsEpollFixEMFILEDials; i++ {
		c, err := net.DialTimeout("tcp4", addr, harnessIOTimeout)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	turbo.Sleep(tlsEpollFixEMFILEWindow / 4)
	before := tlsEpollFixProcCPUTicks(t, cmd.Process.Pid)
	turbo.Sleep(tlsEpollFixEMFILEWindow)
	used := tlsEpollFixProcCPUTicks(t, cmd.Process.Pid) - before
	t.Logf("server CPU over %v with fds exhausted: %d ticks", tlsEpollFixEMFILEWindow, used)
	if used > tlsEpollFixEMFILEMaxTicks {
		t.Fatalf("server burned %d CPU ticks in %v with a full fd table and a non-empty backlog (busy accept loop)", used, tlsEpollFixEMFILEWindow)
	}
}
