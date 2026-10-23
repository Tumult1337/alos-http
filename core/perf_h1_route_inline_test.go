//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

func ranOnEventLoop() bool {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, ".runInlineQueue") {
			return true
		}
		if !more {
			return false
		}
	}
}

func reportDispatchMode(resp *Response, body string) {
	mode := "async"
	if ranOnEventLoop() {
		mode = "inline"
	}
	resp.Status(200).String(mode + ":" + body)
}

func startRouteInlineServer(t *testing.T, useTLS bool) string {
	t.Helper()
	addr := reserveLocalAddr(t)
	cfg := Config{
		Addr:            addr,
		HTTPAddr:        "-",
		LogRequests:     false,
		MaxConnsPerIP:   -1,
		Listeners:       1,
		StreamBodyAbove: 1024,

		DisableInlineHandlers: true,
	}
	if useTLS {
		cfg.Certs = []CertConfig{{Domain: "inline.test", Source: CertSelfSigned}}
	} else {
		cfg.PlainHTTP = true
	}
	s := New(cfg)
	s.Router.GET("/in", func(req *Request, resp *Response) { reportDispatchMode(resp, "in") }).Inline()
	s.Router.GET("/out", func(req *Request, resp *Response) { reportDispatchMode(resp, "out") })
	s.Router.GET("/p/:id", func(req *Request, resp *Response) { reportDispatchMode(resp, req.ParamValue("id")) }).Inline()
	s.Router.POST("/body", func(req *Request, resp *Response) {
		body := req.Body
		if stream := req.BodyStream(); stream != nil {
			body, _ = io.ReadAll(stream)
		}
		reportDispatchMode(resp, fmt.Sprintf("%d", len(body)))
	}).Inline()
	go func() {
		if useTLS {
			_ = s.ListenAndServeTLS()
		} else {
			_ = s.ListenAndServe()
		}
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := inlineDial(addr, useTLS)
		if err == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("route-inline server never came up")
	return ""
}

func TestPerfH1RouteInlineDispatch(t *testing.T) {
	big := strings.Repeat("b", 4096)
	for _, useTLS := range []bool{false, true} {
		name := "plain"
		if useTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			addr := startRouteInlineServer(t, useTLS)
			conn, err := inlineDial(addr, useTLS)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			br := bufio.NewReader(conn)
			fmt.Fprint(conn, "GET /in HTTP/1.1\r\nHost: inline.test\r\n\r\n"+
				"GET /out HTTP/1.1\r\nHost: inline.test\r\n\r\n"+
				"GET /p/42 HTTP/1.1\r\nHost: inline.test\r\n\r\n"+
				"HEAD /in HTTP/1.1\r\nHost: inline.test\r\n\r\n"+
				"POST /body HTTP/1.1\r\nHost: inline.test\r\nContent-Length: 5\r\n\r\nhello"+
				"POST /body HTTP/1.1\r\nHost: inline.test\r\nContent-Length: 4096\r\n\r\n"+big+
				"GET /in HTTP/1.1\r\nHost: inline.test\r\n\r\n")
			want := []struct {
				method string
				body   string
			}{
				{"GET", "inline:in"},
				{"GET", "async:out"},
				{"GET", "inline:42"},
				{"HEAD", ""},
				{"POST", "inline:5"},
				{"POST", "async:4096"},
				{"GET", "inline:in"},
			}
			for i, w := range want {
				resp, err := http.ReadResponse(br, &http.Request{Method: w.method})
				if err != nil {
					t.Fatalf("response %d: %v", i, err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 || string(body) != w.body {
					t.Fatalf("response %d: %d %q, want 200 %q", i, resp.StatusCode, body, w.body)
				}
			}
		})
	}
}
