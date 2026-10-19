//go:build linux && amd64

package core

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"runtime/debug"
	"strconv"
	"sync/atomic"
)

const stdLogCallDepth = 4

var (
	libLogger     atomic.Pointer[slog.Logger]
	defaultLogger = slog.New(stdLogHandler{})
)

func logger() *slog.Logger {
	if l := libLogger.Load(); l != nil {
		return l
	}
	return defaultLogger
}

func useLogger(l *slog.Logger) {
	if l != nil {
		libLogger.Store(l)
	}
}

func (s *Server) logger() *slog.Logger {
	if s != nil && s.config.Logger != nil {
		return s.config.Logger
	}
	return logger()
}

func (s *Server) reportPanic(req *Request, recovered any) {
	defer recoverPanicReporter()
	stack := debug.Stack()
	attrs := []any{"panic", fmt.Sprint(recovered), "stack", string(stack)}
	if req != nil {
		attrs = append(attrs, "method", req.Method, "path", req.Path)
	}
	s.logger().Error("recovered panic", attrs...)
	if s != nil && s.config.OnPanic != nil {
		s.config.OnPanic(req, recovered, stack)
	}
}

type stdLogHandler struct {
	prefix string
	attrs  []byte
}

func (h stdLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo || debugFlag.Load()
}

func (h stdLogHandler) Handle(_ context.Context, r slog.Record) error {
	buf := make([]byte, 0, 128)
	buf = append(buf, '[')
	buf = append(buf, r.Level.String()...)
	buf = append(buf, "] "...)
	buf = append(buf, r.Message...)
	buf = append(buf, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		buf = appendLogAttr(buf, h.prefix, a)
		return true
	})
	return log.Output(stdLogCallDepth, string(buf))
}

func (h stdLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	formatted := append([]byte(nil), h.attrs...)
	for _, a := range attrs {
		formatted = appendLogAttr(formatted, h.prefix, a)
	}
	return stdLogHandler{prefix: h.prefix, attrs: formatted}
}

func (h stdLogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return stdLogHandler{prefix: h.prefix + name + ".", attrs: h.attrs}
}

func appendLogAttr(dst []byte, prefix string, a slog.Attr) []byte {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return dst
	}
	if a.Value.Kind() == slog.KindGroup {
		if a.Key != "" {
			prefix += a.Key + "."
		}
		for _, ga := range a.Value.Group() {
			dst = appendLogAttr(dst, prefix, ga)
		}
		return dst
	}
	dst = append(dst, ' ')
	dst = append(dst, prefix...)
	dst = append(dst, a.Key...)
	dst = append(dst, '=')
	v := a.Value.String()
	if logValueNeedsQuote(v) {
		return strconv.AppendQuote(dst, v)
	}
	return append(dst, v...)
}

func logValueNeedsQuote(v string) bool {
	if v == "" {
		return true
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c <= ' ' || c == '"' || c == '=' || c >= 0x7f {
			return true
		}
	}
	return false
}

func recoverPanicReporter() {
	if r := recover(); r != nil {
		logger().Error("panic while reporting a recovered panic", "panic", fmt.Sprint(r))
	}
}
