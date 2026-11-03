//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var directSealSizes = []int{0, 100, 16383, 16384, 16385, 32767, 32768, 40000, 100000}

func frozenBuildTLSAppDataRecords(dst []byte, writer *TrafficAEAD, payload []byte) []byte {
	const maxContent = MaxRecordPayload - 1
	for len(payload) > 0 {
		chunk := payload[:min(len(payload), maxContent)]
		payload = payload[len(chunk):]
		inner := append(append([]byte(nil), chunk...), 0x17)
		dst = appendTLSInnerRecord(dst, writer, inner)
	}
	return dst
}

func frozenBuildTLS12AppDataRecords(dst []byte, w *tls12AEAD, payload []byte) []byte {
	for len(payload) > 0 {
		chunk := payload[:min(len(payload), MaxRecordPayload)]
		payload = payload[len(chunk):]
		dst = w.sealTo(dst, 0x17, chunk)
	}
	return dst
}

type directSealSuite struct {
	name  string
	setup func(t *testing.T, c *epollConn)
	want  func(t *testing.T, prefix, payload []byte) []byte
}

func directSealSuites(t *testing.T) []directSealSuite {
	var suites []directSealSuite
	for i := range SupportedSuites {
		cs := &SupportedSuites[i]
		secret := bytes.Repeat([]byte{5}, cs.HashLen)
		newWriter := func(t *testing.T) *TrafficAEAD {
			w, err := NewTrafficAEAD(cs.HashFn, secret, cs)
			if err != nil {
				t.Fatal(err)
			}
			return w
		}
		suites = append(suites, directSealSuite{
			name:  "tls13-" + string(rune('0'+i)),
			setup: func(t *testing.T, c *epollConn) { c.appWriter = newWriter(t) },
			want: func(t *testing.T, prefix, payload []byte) []byte {
				return frozenBuildTLSAppDataRecords(prefix, newWriter(t), payload)
			},
		})
	}
	gcm := func(t *testing.T) *tls12AEAD {
		w, _ := newTestTLS12Pair(t)
		return w
	}
	chacha := func(t *testing.T) *tls12AEAD {
		aead, err := chacha20poly1305.New(bytes.Repeat([]byte{9}, chacha20poly1305.KeySize))
		if err != nil {
			t.Fatal(err)
		}
		return &tls12AEAD{aead: aead, iv: bytes.Repeat([]byte{3}, chacha20poly1305.NonceSize), isChaCha: true}
	}
	for _, s := range []struct {
		name string
		new  func(*testing.T) *tls12AEAD
	}{{"tls12-gcm", gcm}, {"tls12-chacha", chacha}} {
		suites = append(suites, directSealSuite{
			name:  s.name,
			setup: func(t *testing.T, c *epollConn) { c.tls12 = &tls12State{writer: s.new(t)} },
			want: func(t *testing.T, prefix, payload []byte) []byte {
				return frozenBuildTLS12AppDataRecords(prefix, s.new(t), payload)
			},
		})
	}
	return suites
}

func directSealConn(t *testing.T, suite directSealSuite, method string, size int, text bool) *epollConn {
	c := &epollConn{tls: true, worker: &epollWorker{}}
	suite.setup(t, c)
	body := bytes.Repeat([]byte{'q'}, size)
	if text {
		c.resp.Status(200).String(string(body))
	} else {
		c.resp.Status(200).Bytes(body)
	}
	c.resp.lazyReq = &Request{Method: method}
	return c
}

const sameDateAttempts = 3

func buildWithinOneDate(build func() (got, want []byte)) (got, want []byte) {
	for range sameDateAttempts {
		date := currentHTTPDate()
		got, want = build()
		if bytes.Equal(got, want) || currentHTTPDate() == date {
			return got, want
		}
	}
	return got, want
}

func TestTLSDirectSealMatchesFrozenBuilders(t *testing.T) {
	for _, suite := range directSealSuites(t) {
		for _, method := range []string{"GET", "HEAD"} {
			for _, size := range directSealSizes {
				for _, text := range []bool{false, true} {
					got, want := buildWithinOneDate(func() ([]byte, []byte) {
						c := directSealConn(t, suite, method, size, text)
						plain := appendPlainResponseMode(&directSealConn(t, suite, method, size, text).resp, nil, true, true)
						c.writeBuf = []byte("prefix")
						c.h1WriteResponse(true)
						return c.writeBuf, suite.want(t, []byte("prefix"), plain)
					})
					if !bytes.Equal(got, want) {
						t.Fatalf("%s %s size=%d text=%v: sealed %d bytes, frozen builder %d", suite.name, method, size, text, len(got), len(want))
					}

					got, want = buildWithinOneDate(func() ([]byte, []byte) {
						pipelined := directSealConn(t, suite, method, size, text)
						plain := appendPlainResponseMode(&directSealConn(t, suite, method, size, text).resp, []byte("PENDING"), false, true)
						out := pipelined.h1AppendResponse([]byte("PENDING"), false)
						pipelined.h1OutEnd(out)
						return pipelined.writeBuf, suite.want(t, nil, plain)
					})
					if !bytes.Equal(got, want) {
						t.Fatalf("%s %s size=%d text=%v with pending output: sealed %d bytes, frozen builder %d", suite.name, method, size, text, len(got), len(want))
					}
				}
			}
		}
	}
}

func TestTLSRecordBuildersMatchFrozenBuilders(t *testing.T) {
	for _, suite := range directSealSuites(t) {
		for _, size := range directSealSizes {
			payload := bytes.Repeat([]byte{'p'}, size)
			c := &epollConn{tls: true}
			suite.setup(t, c)
			if got, want := c.sealTLSAppData([]byte("x"), payload), suite.want(t, []byte("x"), payload); !bytes.Equal(got, want) {
				t.Fatalf("%s size=%d: whole-payload builder differs from frozen builder", suite.name, size)
			}
		}
	}
}

func TestTLSLargeResponseBodiesAreComplete(t *testing.T) {
	bodies := map[string][]byte{}
	for name, size := range map[string]int{"/16k": 16 << 10, "/64k": 64 << 10, "/300k": 300 << 10} {
		body := make([]byte, size)
		for i := range body {
			body[i] = byte(i * 7)
		}
		bodies[name] = body
	}
	ts := newTestServer(t, testServerOptions{TLS: true, Routes: func(r *Router) {
		for name, body := range bodies {
			r.GET(name, func(req *Request, resp *Response) { resp.Status(200).Bytes(body) })
		}
	}})
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		cfg := ts.tlsConfig("http/1.1")
		cfg.MinVersion, cfg.MaxVersion = version, version
		tr := &http.Transport{TLSClientConfig: cfg}
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		for path, want := range bodies {
			for rep := 0; rep < 3; rep++ {
				resp, err := client.Get(ts.url(path))
				if err != nil {
					t.Fatalf("%x %s rep %d: %v", version, path, rep, err)
				}
				got, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					t.Fatalf("%x %s rep %d: read body: %v", version, path, rep, err)
				}
				if resp.TLS == nil || resp.TLS.Version != version {
					t.Fatalf("%x %s rep %d: negotiated a different TLS version", version, path, rep)
				}
				if resp.StatusCode != 200 || !bytes.Equal(got, want) {
					t.Fatalf("%x %s rep %d: status=%d len=%d want %d", version, path, rep, resp.StatusCode, len(got), len(want))
				}
			}
		}
		tr.CloseIdleConnections()
	}
}
