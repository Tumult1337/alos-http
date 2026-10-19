//go:build linux && amd64

package core

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.records = append(h.records, r.Clone())
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) find(msg string) (slog.Record, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Message == msg {
			return r, true
		}
	}
	return slog.Record{}, false
}

func (h *captureHandler) snapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	msgs := make([]string, len(h.records))
	for i, r := range h.records {
		msgs[i] = r.Message
	}
	return msgs
}

func recordAttr(r slog.Record, key string) (string, bool) {
	var val string
	found := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val, found = a.Value.String(), true
			return false
		}
		return true
	})
	return val, found
}

func captureLibraryLogger(t *testing.T) *captureHandler {
	t.Helper()
	prev := libLogger.Load()
	t.Cleanup(func() { libLogger.Store(prev) })
	return &captureHandler{}
}

func captureStdLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	prevLogger := libLogger.Load()
	libLogger.Store(nil)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
		libLogger.Store(prevLogger)
	})
	return &buf
}

func TestLoggingDefaultHandlerFormat(t *testing.T) {
	buf := captureStdLog(t)
	logger().Info("certificate added", "domain", "a.test", "note", "two words", "empty", "")
	logger().With("component", "proxy").WithGroup("backend").Warn("unhealthy", "addr", "10.0.0.1:80", slog.Group("check", "fails", 3))
	got := buf.String()
	for _, want := range []string{
		"[INFO] certificate added domain=a.test note=\"two words\" empty=\"\"\n",
		"[WARN] unhealthy component=proxy backend.addr=10.0.0.1:80 backend.check.fails=3\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q missing %q", got, want)
		}
	}
	buf.Reset()
	logger().Info("injected", "value", "a\nb=c")
	if line := buf.String(); strings.Count(line, "\n") != 1 || !strings.Contains(line, `value="a\nb=c"`) {
		t.Errorf("a newline in a value was not escaped: %q", line)
	}
}

func TestLoggingDebugFollowsDebugFlag(t *testing.T) {
	buf := captureStdLog(t)
	prev := debugFlag.Load()
	t.Cleanup(func() { debugFlag.Store(prev) })

	debugFlag.Store(false)
	Dbg("hidden %d", 1)
	logger().Debug("hidden too")
	if buf.Len() != 0 {
		t.Fatalf("debug output with the flag off: %q", buf.String())
	}
	debugFlag.Store(true)
	Dbg("shown %d", 2)
	DbgHex("payload", []byte{0xde, 0xad})
	if got := buf.String(); !strings.Contains(got, "[DEBUG] shown 2\n") || !strings.Contains(got, "[DEBUG] payload bytes=2 hex=dead\n") {
		t.Fatalf("debug output with the flag on: %q", got)
	}
}

func TestLoggingUsesConfiguredLogger(t *testing.T) {
	capture := captureLibraryLogger(t)
	srv := New(Config{Addr: "127.0.0.1:0", HTTPAddr: "-", LogRequests: false, Logger: slog.New(capture)})
	if err := srv.AddSelfSignedCert("log.test"); err != nil {
		t.Fatal(err)
	}
	r, ok := capture.find("certificate added")
	if !ok {
		t.Fatal("no record for the added certificate")
	}
	if domain, _ := recordAttr(r, "domain"); domain != "log.test" || r.Level != slog.LevelInfo {
		t.Fatalf("record %v domain %q", r.Level, domain)
	}
	NewProxyEngine().AddDomain(DomainConfig{Domain: ""})
	if r, ok := capture.find("proxy domain rejected: empty domain name"); !ok || r.Level != slog.LevelWarn {
		t.Fatal("rejected proxy domain was not logged as a warning through the configured logger")
	}
}

func panickingTestHandler(req *Request, resp *Response) {
	panic("boom from the handler")
}

func TestRecoveryReportsPanic(t *testing.T) {
	capture := captureLibraryLogger(t)
	var gotReq *Request
	var gotValue any
	var gotStack []byte
	srv := New(Config{Addr: "127.0.0.1:0", HTTPAddr: "-", LogRequests: false, Logger: slog.New(capture),
		OnPanic: func(req *Request, recovered any, stack []byte) { gotReq, gotValue, gotStack = req, recovered, stack }})
	req := &Request{Method: "GET", Path: "/boom", server: srv}
	resp := &Response{}
	resp.Reset()
	Recovery()(panickingTestHandler)(req, resp)
	if resp.StatusCode != 500 {
		t.Fatalf("status %d, want 500", resp.StatusCode)
	}
	if gotReq != req || gotValue != "boom from the handler" || !bytes.Contains(gotStack, []byte("panickingTestHandler")) {
		t.Fatalf("hook got req=%v value=%v stack has handler=%v", gotReq == req, gotValue, bytes.Contains(gotStack, []byte("panickingTestHandler")))
	}
	r, ok := capture.find("recovered panic")
	if !ok || r.Level != slog.LevelError {
		t.Fatal("panic not logged at Error level")
	}
	if path, _ := recordAttr(r, "path"); path != "/boom" {
		t.Fatalf("logged path %q", path)
	}
	if stack, _ := recordAttr(r, "stack"); !strings.Contains(stack, "panickingTestHandler") {
		t.Fatal("logged stack lacks the handler frame")
	}

	orphan := &Request{Method: "GET", Path: "/orphan"}
	resp.Reset()
	Recovery()(panickingTestHandler)(orphan, resp)
	if resp.StatusCode != 500 {
		t.Fatalf("request without a server: status %d", resp.StatusCode)
	}
}
