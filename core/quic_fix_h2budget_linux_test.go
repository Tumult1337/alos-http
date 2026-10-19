//go:build linux && amd64

package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicFixH2HogStreams     = 40
	quicFixH2HogBytes       = 1792 << 10
	quicFixH2VictimBytes    = 1536 << 10
	quicFixH2DefaultBudget  = 64 << 20
	quicFixH2SettlePolls    = 4
	quicFixH2SettleInterval = 25 * time.Millisecond
	quicFixH2SettleCeiling  = 3 * time.Second
)

type quicFixStallingBody struct {
	remaining int
	release   <-chan struct{}
}

func (b *quicFixStallingBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		<-b.release
		return 0, io.ErrUnexpectedEOF
	}
	n := min(len(p), b.remaining)
	clear(p[:n])
	b.remaining -= n
	return n, nil
}

func newQUICFixH2CClient() *http.Client {
	tr := &http.Transport{Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: tr}
}

func quicFixAwaitBudgetSettled(t *testing.T, srv *Server) int64 {
	t.Helper()
	deadline := turbo.Deadline(quicFixH2SettleCeiling)
	last, stable := int64(-1), 0
	for turbo.Until(deadline) > 0 {
		cur := srv.inFlightBodyBytes.Load()
		if cur > 0 && cur == last {
			stable++
			if stable >= quicFixH2SettlePolls {
				return cur
			}
		} else {
			stable = 0
		}
		last = cur
		turbo.Sleep(quicFixH2SettleInterval)
	}
	return srv.inFlightBodyBytes.Load()
}

func TestQUICFixOneH2ConnCannotStarveOtherUploads(t *testing.T) {
	ts := newTestServer(t, testServerOptions{Routes: func(r *Router) {
		r.POST("/up", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	}})
	url := "http://" + ts.addr + "/up"
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { close(release); cancel() })
	hog := newQUICFixH2CClient()
	for i := 0; i < quicFixH2HogStreams; i++ {
		go func() {
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, &quicFixStallingBody{remaining: quicFixH2HogBytes, release: release})
			if resp, err := hog.Do(req); err == nil {
				resp.Body.Close()
			}
		}()
	}
	held := quicFixAwaitBudgetSettled(t, ts.srv)
	if held > quicFixH2DefaultBudget/2 {
		t.Errorf("one HTTP/2 connection holds %d bytes of the %d byte in-flight body budget", held, quicFixH2DefaultBudget)
	}
	victim := newQUICFixH2CClient()
	resp, err := victim.Post(url, "application/octet-stream", bytes.NewReader(make([]byte, quicFixH2VictimBytes)))
	if err != nil {
		t.Fatalf("victim upload on its own connection failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("victim upload: status %d, want 200", resp.StatusCode)
	}
}
