//go:build linux && amd64

package core

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	perfKTLSSolTLS        = 282
	perfKTLSTx            = 1
	perfKTLSVersion13     = 0x0304
	perfKTLSCipherAES128  = 51
	perfKTLSAES128KeyLen  = 16
	perfKTLSAES128IVLen   = 8
	perfKTLSAES128SaltLen = 4
)

type perfKTLSCryptoInfoAES128 struct {
	version    uint16
	cipherType uint16
	iv         [perfKTLSAES128IVLen]byte
	key        [perfKTLSAES128KeyLen]byte
	salt       [perfKTLSAES128SaltLen]byte
	recSeq     [8]byte
}

func perfKTLSPair(b *testing.B) (*net.TCPConn, func()) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}()
	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	return conn.(*net.TCPConn), func() {
		_ = conn.Close()
		<-done
		_ = ln.Close()
	}
}

func perfKTLSEnable(b *testing.B, conn *net.TCPConn, key, iv []byte) {
	raw, err := conn.SyscallConn()
	if err != nil {
		b.Fatal(err)
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		if serr = unix.SetsockoptString(int(fd), unix.SOL_TCP, unix.TCP_ULP, "tls"); serr != nil {
			return
		}
		info := perfKTLSCryptoInfoAES128{version: perfKTLSVersion13, cipherType: perfKTLSCipherAES128}
		copy(info.key[:], key)
		copy(info.salt[:], iv[:perfKTLSAES128SaltLen])
		copy(info.iv[:], iv[perfKTLSAES128SaltLen:])
		_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, fd, perfKTLSSolTLS, perfKTLSTx, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 0)
		if errno != 0 {
			serr = errno
		}
	})
	if err != nil || serr != nil {
		b.Skipf("kTLS TX unavailable: %v %v", err, serr)
	}
}

func perfKTLSWriter(b *testing.B) *TrafficAEAD {
	cs := tls13SuiteByID(0x1301)
	if cs == nil {
		b.Fatal("no TLS_AES_128_GCM_SHA256")
	}
	secret := sha256.Sum256([]byte("perf ktls secret"))
	w, err := NewTrafficAEAD(cs.HashFn, secret[:], cs)
	if err != nil {
		b.Fatal(err)
	}
	return w
}

func perfKTLSUserspace(b *testing.B, size int) {
	conn, done := perfKTLSPair(b)
	defer done()
	w := perfKTLSWriter(b)
	body := make([]byte, size)
	var buf []byte
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		buf = buildTLSAppDataRecordsParts(buf[:0], w, nil, body)
		if _, err := conn.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func perfKTLSKernel(b *testing.B, size int) {
	conn, done := perfKTLSPair(b)
	defer done()
	var key [16]byte
	var iv [12]byte
	binary.BigEndian.PutUint64(key[:], 0x0102030405060708)
	binary.BigEndian.PutUint32(iv[:], 0x0a0b0c0d)
	perfKTLSEnable(b, conn, key[:], iv[:])
	body := make([]byte, size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := conn.Write(body); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPerfKTLSUserspace64K(b *testing.B) { perfKTLSUserspace(b, 64<<10) }
func BenchmarkPerfKTLSKernel64K(b *testing.B)    { perfKTLSKernel(b, 64<<10) }
func BenchmarkPerfKTLSUserspace1M(b *testing.B)  { perfKTLSUserspace(b, 1<<20) }
func BenchmarkPerfKTLSKernel1M(b *testing.B)     { perfKTLSKernel(b, 1<<20) }
