//go:build linux && amd64

package core

import (
	"strings"
	"sync"
	"time"

	"github.com/guno1928/turbo"
)

const sseHeartbeatComment = "ping"

// SSEWriter streams Server-Sent Events to the client. Obtain one from
// Response.SSE and emit events with Send, SendData, or SendID.
type SSEWriter struct {
	sw StreamWriter
	mu sync.Mutex
}

// SSE switches the response into Server-Sent Events mode, writing the
// text/event-stream headers, and returns an SSEWriter. Returns nil if the
// connection does not support streaming.
//
// Example: sse := resp.SSE(); if sse == nil { return }
// Example: sse := resp.SSE(); defer sse.Close()
func (r *Response) SSE() *SSEWriter {
	sw := r.EnsureStreamWriter()
	if sw == nil {
		return nil
	}
	headers := [][2]string{
		{"Cache-Control", "no-cache"},
		{"Connection", "keep-alive"},
	}
	sw.WriteHeader(200, headers, "text/event-stream")
	r.SetStreamer(sw)
	return &SSEWriter{sw: sw}
}

func appendSSELines(dst []byte, prefix, text string) []byte {
	for {
		end := strings.IndexAny(text, "\r\n")
		if end < 0 {
			dst = append(dst, prefix...)
			dst = append(dst, text...)
			return append(dst, '\n')
		}
		dst = append(dst, prefix...)
		dst = append(dst, text[:end]...)
		dst = append(dst, '\n')
		if text[end] == '\r' && end+1 < len(text) && text[end+1] == '\n' {
			end++
		}
		text = text[end+1:]
	}
}

func appendSSEField(dst []byte, name, value string) []byte {
	dst = append(dst, name...)
	dst = append(dst, ": "...)
	for i := 0; i < len(value); i++ {
		if c := value[i]; c != '\r' && c != '\n' {
			dst = append(dst, c)
		}
	}
	return append(dst, '\n')
}

func (w *SSEWriter) writeBlock(block []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.sw.WriteChunk(block); err != nil {
		return err
	}
	return w.sw.Flush()
}

func (w *SSEWriter) sendBlock(build func([]byte) []byte) error {
	bp := MediumBufPool.Get().(*[]byte)
	block := append(build((*bp)[:0]), '\n')
	err := w.writeBlock(block)
	*bp = block[:0]
	putBoxedBufCapped(&MediumBufPool, bp, largeBufPoolMaxCap)
	return err
}

// Send writes a named event with a data payload and flushes it to the client.
//
// Example: sse.Send("message", "hello")
// Example: sse.Send("update", `{"count":5}`)
func (w *SSEWriter) Send(event, data string) error {
	return w.sendBlock(func(b []byte) []byte {
		return appendSSELines(appendSSEField(b, "event", event), "data: ", data)
	})
}

// SendData writes an unnamed data-only event and flushes it to the client.
//
// Example: sse.SendData("tick")
// Example: sse.SendData("line1\nline2")
func (w *SSEWriter) SendData(data string) error {
	return w.sendBlock(func(b []byte) []byte { return appendSSELines(b, "data: ", data) })
}

// SendID writes an event carrying an id field, allowing clients to resume with
// Last-Event-ID, and flushes it to the client.
//
// Example: sse.SendID("42", "message", "hello")
// Example: sse.SendID("e1", "update", `{"ok":true}`)
func (w *SSEWriter) SendID(id, event, data string) error {
	return w.sendBlock(func(b []byte) []byte {
		return appendSSELines(appendSSEField(appendSSEField(b, "id", id), "event", event), "data: ", data)
	})
}

func (w *SSEWriter) SendComment(text string) error {
	return w.sendBlock(func(b []byte) []byte { return appendSSELines(b, ": ", text) })
}

func (w *SSEWriter) StartHeartbeat(interval time.Duration) (stop func()) {
	if interval <= 0 {
		return func() {}
	}
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		ticker := turbo.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if w.SendComment(sseHeartbeatComment) != nil {
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(done) })
		<-exited
	}
}

// Close ends the event stream and closes the underlying connection.
func (w *SSEWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sw.Close()
}
