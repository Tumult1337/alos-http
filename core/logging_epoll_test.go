//go:build linux && amd64

package core

import (
	"bytes"
	"io"
	"log/slog"
	"sync"
	"testing"
)

type panicReports struct {
	mu      sync.Mutex
	reports []panicReport
}

type panicReport struct {
	path           string
	value          any
	stackHasRouter bool
}

func (p *panicReports) hook(req *Request, recovered any, stack []byte) {
	r := panicReport{value: recovered, stackHasRouter: bytes.Contains(stack, []byte("panickingTestHandler"))}
	if req != nil {
		r.path = req.Path
	}
	p.mu.Lock()
	p.reports = append(p.reports, r)
	p.mu.Unlock()
}

func (p *panicReports) snapshot() []panicReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]panicReport(nil), p.reports...)
}

func TestPanicReportEpoll(t *testing.T) {
	cases := []struct {
		name   string
		tls    bool
		alpn   string
		inline bool
	}{
		{name: "h1-dispatched-tls", tls: true, alpn: "http/1.1"},
		{name: "h2-tls", tls: true, alpn: "h2"},
		{name: "h1-dispatched-plain"},
		{name: "h1-inline-plain", inline: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture := captureLibraryLogger(t)
			reports := &panicReports{}
			ts := newTestServer(t, testServerOptions{
				TLS: tc.tls,
				Config: func(cfg *Config) {
					cfg.PlainHTTP = !tc.tls
					cfg.InlineHandlers, cfg.DisableInlineHandlers = tc.inline, !tc.inline
					cfg.Logger = slog.New(capture)
					cfg.OnPanic = reports.hook
				},
				Routes: func(r *Router) {
					r.GET("/boom", panickingTestHandler)
					r.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
				},
			})
			client := ts.client(t, tc.alpn)
			resp, err := client.Get(ts.url("/boom"))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != 500 || string(body) != "Internal Server Error" {
				t.Fatalf("status %d body %q", resp.StatusCode, body)
			}
			if tc.alpn == "h2" && resp.ProtoMajor != 2 {
				t.Fatalf("negotiated %s, want HTTP/2", resp.Proto)
			}
			got := reports.snapshot()
			if len(got) != 1 || got[0].path != "/boom" || got[0].value != "boom from the handler" || !got[0].stackHasRouter {
				t.Fatalf("reports %+v", got)
			}
			if r, ok := capture.find("recovered panic"); !ok || r.Level != slog.LevelError {
				t.Fatal("panic was not logged at Error level")
			}

			resp, err = client.Get(ts.url("/ok"))
			if err != nil {
				t.Fatal(err)
			}
			body, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != 200 || string(body) != "ok" {
				t.Fatalf("connection unusable after the panic: status %d body %q", resp.StatusCode, body)
			}
			if n := len(reports.snapshot()); n != 1 {
				t.Fatalf("a successful request produced a panic report (%d total)", n)
			}
		})
	}
}

func TestLoggingSilentOnSuccessPath(t *testing.T) {
	capture := captureLibraryLogger(t)
	ts := newTestServer(t, testServerOptions{
		Config: func(cfg *Config) {
			cfg.PlainHTTP = true
			cfg.Logger = slog.New(capture)
		},
		Routes: func(r *Router) {
			r.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
		},
	})
	client := ts.client(t, "")
	before := len(capture.snapshot())
	for range 20 {
		resp, err := client.Get(ts.url("/ok"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	if after := capture.snapshot(); len(after) != before {
		t.Fatalf("successful requests logged %d records: %v", len(after)-before, after[before:])
	}
}
