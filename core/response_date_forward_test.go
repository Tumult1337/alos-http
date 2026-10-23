//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestResponseDateReceiptBeforeBodyAndPublicControl(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		connection := fpFixH1Conn("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
		connection.cur.req.ensureResponseDate = enabled
		done, err := connection.h1.advance(connection)
		if done || err != nil {
			t.Fatalf("head-only advance done=%v err=%v", done, err)
		}
		initial := dateValues(connection.h1.stringHeaders())
		if enabled {
			dateRequireCurrent(t, connection.h1.stringHeaders())
		} else if len(initial) != 0 {
			t.Fatal("generic upstream response gained Date")
		}
		connection.rbuf.write([]byte("ok"))
		done, err = connection.h1.advance(connection)
		if !done || err != nil || string(connection.h1.body) != "ok" {
			t.Fatalf("body completion done=%v err=%v body=%q", done, err, connection.h1.body)
		}
		if got := dateValues(connection.h1.stringHeaders()); fmt.Sprint(got) != fmt.Sprint(initial) {
			t.Fatalf("Date changed while body arrived: %q -> %q", initial, got)
		}
	}
	for _, value := range []string{"", "opaque", "Tue, 15 Nov 1994 08:12:31 GMT"} {
		connection := fpFixH1Conn("HTTP/1.1 200 OK\r\nContent-Length: 0\r\ndAtE: " + value + "\r\n\r\n")
		connection.cur.req.ensureResponseDate = true
		if done, err := connection.h1.advance(connection); !done || err != nil {
			t.Fatalf("done=%v err=%v", done, err)
		}
		if got := dateValues(connection.h1.stringHeaders()); len(got) != 1 || got[0] != value {
			t.Fatalf("supplied Date=%q, want %q", got, value)
		}
	}
}

func TestResponseDateFallbackProxyAndCache(t *testing.T) {
	backend := rawOrigin(t, func(connection net.Conn) {
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	engine := NewProxyEngine()
	engine.Cache = proxyFixRuledCache(1 << 20)
	defer engine.Stop()
	engine.AddDomain(DomainConfig{Domain: proxyFixDomain, Backends: []BackendConfig{{Addr: backend}}})
	domain := engine.Lookup(proxyFixDomain)
	request := &Request{Method: "GET", Path: "/receipt", Host: proxyFixDomain, RemoteAddr: "127.0.0.1:1"}
	response := &Response{StatusCode: 200}
	if err := engine.forwardRequestFP(request, response, domain.backends[0], &domain.config, proxyCacheTarget{path: fpProxyPath(request), storable: true}); err != nil {
		t.Fatal(err)
	}
	dateRequireCurrent(t, response.Headers)
	original := dateValues(response.Headers)[0]
	entry, ok := engine.activeCache().GetFP("GET", proxyFixDomain, "/receipt", true)
	if !ok {
		t.Fatal("response was not cached")
	}
	if got := dateValues(entry.headers); len(got) != 1 || got[0] != original {
		t.Fatalf("cache lost receipt Date: %q", got)
	}
	replay := &Response{StatusCode: 200}
	engine.activeCache().ServeCached(entry, request, replay)
	if got := dateValues(dateH1Fields(t, appendPlainResponse(replay, nil))); len(got) != 1 || got[0] != original {
		t.Fatalf("cache replay Date=%q want %q", got, original)
	}
}

func TestResponseDateWorkerProxyAndLocalFailure(t *testing.T) {
	backend := rawOrigin(t, func(connection net.Conn) {
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	observed := make(chan []string, 2)
	_, address := proxyFixStart(t, Config{}, proxyFixSingleBackend(backend), func(server *Server) {
		server.OnProxyResponse(func(response *ProxyResponse) { observed <- dateValues(response.Headers) })
	})
	response, body := proxyFixRoundTrip(t, address, proxyFixGet(proxyFixDomain, "/receipt"))
	if response.StatusCode != 200 || body != "ok" {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
	if values := response.Header.Values("Date"); len(values) != 1 {
		t.Fatalf("worker Date=%q", values)
	}
	select {
	case fields := <-observed:
		if len(fields) != 1 {
			t.Fatalf("receipt Date absent before hook: %q", fields)
		}
	case <-time.After(proxyFixCeiling):
		t.Fatal("response hook did not run")
	}
	_, failedAddress := proxyFixStart(t, Config{}, []DomainConfig{{Domain: proxyFixDomain}}, nil)
	failed, _ := proxyFixRoundTrip(t, failedAddress, proxyFixGet(proxyFixDomain, "/local-error"))
	if failed.StatusCode != 502 || len(failed.Header.Values("Date")) != 1 {
		t.Fatalf("local failure status=%d Date=%q", failed.StatusCode, failed.Header.Values("Date"))
	}
}

func TestResponseDateForwardedUpgrade(t *testing.T) {
	for _, value := range []string{"missing", "", "opaque"} {
		t.Run("fallback-"+value, func(t *testing.T) {
			client, backend := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer backend.Close()
				head := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
				if value != "missing" {
					head += "dAtE: " + value + "\r\n"
				}
				_, _ = io.WriteString(backend, head+"\r\n")
			}()
			var parser h1Parser
			if _, _, err := readUpgradeAnswer(client, &parser, "GET", proxyFixIOTimeout); err != nil {
				t.Fatal(err)
			}
			fields := dateH1Fields(t, appendTunnelResponseHead(nil, parser.hdr))
			if value == "missing" {
				dateRequireCurrent(t, fields)
			} else if got := dateValues(fields); len(got) != 1 || got[0] != value {
				t.Fatalf("upgrade Date=%q, want %q", got, value)
			}
			<-done
		})
	}
	origin := newProxyFixUpgradeOrigin(t)
	defer origin.startReading()
	_, address := proxyFixStart(t, Config{}, proxyFixSingleBackend(origin.ln.Addr().String()), nil)
	connection := proxyFixDial(t, address)
	defer connection.Close()
	_, err := io.WriteString(connection, "GET /ws HTTP/1.1\r\nHost: "+proxyFixDomain+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 || len(response.Header.Values("Date")) != 1 {
		t.Fatalf("worker upgrade status=%d Date=%q", response.StatusCode, response.Header.Values("Date"))
	}
}

func TestResponseDateWriteH1EncryptedPaths(t *testing.T) {
	for _, shape := range []string{"small", "large-body", "large-head"} {
		t.Run(shape, func(t *testing.T) {
			suite := &SupportedSuites[0]
			fixture := bytes.Repeat([]byte{7}, suite.HashLen)
			writer, err := NewTrafficAEAD(suite.HashFn, fixture, suite)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewTrafficAEAD(suite.HashFn, fixture, suite)
			if err != nil {
				t.Fatal(err)
			}
			response := &Response{StatusCode: 200}
			response.String("ok")
			if shape == "large-body" {
				response.String(strings.Repeat("b", 2*MaxRecordPayload))
			}
			if shape == "large-head" {
				response.SetHeader("X-Large", strings.Repeat("v", MaxRecordPayload))
			}
			connection := &captureConn{}
			if err := WriteH1Response(connection, writer, response); err != nil {
				t.Fatal(err)
			}
			var plain []byte
			wire := connection.buf
			for len(wire) > 0 {
				if len(wire) < 5 {
					t.Fatal("short TLS record")
				}
				size := int(wire[3])<<8 | int(wire[4])
				if size > len(wire)-5 {
					t.Fatal("truncated TLS record")
				}
				record, err := reader.Decrypt(bytes.Clone(wire[5 : 5+size]))
				if err != nil {
					t.Fatal(err)
				}
				if len(record) == 0 || record[len(record)-1] != 0x17 {
					t.Fatal("wrong TLS inner record type")
				}
				plain = append(plain, record[:len(record)-1]...)
				wire = wire[5+size:]
			}
			parsed, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(plain)), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(parsed.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != string(response.GetBody()) || parsed.Header.Get("Content-Length") != strconv.Itoa(response.BodyLen()) {
				t.Fatal("encrypted response body/framing changed")
			}
			dateRequireCurrent(t, dateH1Fields(t, plain))
		})
	}
}

func TestResponseDateRawRedirectErrors(t *testing.T) {
	for _, request := range []struct {
		target, host string
		status       int
	}{
		{"/", "bad host", 400},
		{"/.well-known/acme-challenge/public-fixture", "example.test", 404},
	} {
		t.Run(strconv.Itoa(request.status), func(t *testing.T) {
			server := New(Config{Addr: ":443"})
			client, connection := net.Pipe()
			done := make(chan struct{})
			go func() { defer close(done); server.handleHTTPRedirect(connection) }()
			defer func() { _ = client.Close(); <-done }()
			_ = client.SetDeadline(time.Now().Add(proxyFixCeiling))
			if _, err := io.WriteString(client, "GET "+request.target+" HTTP/1.1\r\nHost: "+request.host+"\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != request.status || len(response.Header.Values("Date")) != 1 {
				t.Fatalf("raw error status=%d Date=%q", response.StatusCode, response.Header.Values("Date"))
			}
		})
	}
}
