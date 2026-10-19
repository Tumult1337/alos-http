package h3interop

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/guno1928/alos-http/core"
)

const (
	quicLongHeaderBit    = 0x80
	impairedDropEvery    = 23
	impairedSwapEvery    = 4
	impairedDownloadSize = 1 << 20
	impairedUploadSize   = 512 << 10
)

type relayImpairment struct {
	dropEvery int
	swapEvery int
}

type relayShaper struct {
	cfg   relayImpairment
	count int
	held  []byte
}

func (s *relayShaper) shape(pkt []byte, send func([]byte)) {
	if len(pkt) == 0 || pkt[0]&quicLongHeaderBit != 0 {
		send(pkt)
		return
	}
	s.count++
	if s.cfg.dropEvery > 0 && s.count%s.cfg.dropEvery == 0 {
		return
	}
	if s.held != nil {
		send(pkt)
		send(s.held)
		s.held = nil
		return
	}
	if s.cfg.swapEvery > 0 && s.count%s.cfg.swapEvery == 0 {
		s.held = append([]byte(nil), pkt...)
		return
	}
	send(pkt)
}

func TestRelayShaperDropsAndSwapsShortHeaderPackets(t *testing.T) {
	s := relayShaper{cfg: relayImpairment{dropEvery: 3, swapEvery: 2}}
	var out []byte
	for i := byte(1); i <= 7; i++ {
		s.shape([]byte{0x40, i}, func(p []byte) { out = append(out, p[1]) })
	}
	s.shape([]byte{0xc0, 99}, func(p []byte) { out = append(out, p[1]) })
	if want := []byte{1, 4, 2, 5, 7, 99}; !bytes.Equal(out, want) {
		t.Fatalf("shaped order %v, want %v", out, want)
	}
}

func impairedClient(t *testing.T, hs *h3Server) (*http.Client, string) {
	t.Helper()
	relay := newImpairedRelay(t, hs.addr, relayImpairment{dropEvery: impairedDropEvery, swapEvery: impairedSwapEvery})
	return newClient(t), relay.addr()
}

func TestH3DownloadSurvivesLossAndReordering(t *testing.T) {
	hs := startH3(t, core.Config{})
	c, addr := impairedClient(t, hs)
	resp, err := c.Get(fmt.Sprintf("https://%s/big/%d", addr, impairedDownloadSize))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("download failed after %d bytes: %v", len(body), err)
	}
	if len(body) != impairedDownloadSize || bytes.Count(body, []byte("y")) != impairedDownloadSize {
		t.Fatalf("downloaded %d bytes, want %d intact", len(body), impairedDownloadSize)
	}
}

func TestH3UploadSurvivesLossAndReordering(t *testing.T) {
	hs := startH3(t, core.Config{})
	c, addr := impairedClient(t, hs)
	payload := make([]byte, impairedUploadSize)
	for i := range payload {
		payload[i] = byte(i*7 + i>>9)
	}
	resp, err := c.Post(fmt.Sprintf("https://%s/echo", addr), "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	echoed, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || !bytes.Equal(echoed, payload) {
		t.Fatalf("echo: status %d, %d of %d bytes, equal=%v, err %v", resp.StatusCode, len(echoed), len(payload), bytes.Equal(echoed, payload), err)
	}
}
