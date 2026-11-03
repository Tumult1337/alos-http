//go:build linux && amd64

package core

import (
	"strconv"
	"testing"
)

func TestPerfH1SharedPromoteArenaKeepsEveryRequestIntact(t *testing.T) {
	var arena promoteArena
	type kept struct{ path, host, ua string }
	var held []kept
	buf := make([]byte, 0, 512)
	for i := 0; i < 3*promoteArenaChunk/64; i++ {
		id := strconv.Itoa(i)
		buf = append(buf[:0], "GET /item/"+id+" HTTP/1.1\r\nHost: h"+id+".example\r\nUser-Agent: agent-"+id+"\r\n\r\n"...)
		var req Request
		req.resetFastH1()
		end, _, _, _, _, _, _, ok := parseH1RequestHead(buf, &req, 8192, 100)
		if !ok {
			t.Fatalf("request %d did not parse", i)
		}
		promoteRequestHeadArena(&req, buf[:end], &arena)
		held = append(held, kept{req.Path, req.Host, req.Header("User-Agent")})
		for j := range buf {
			buf[j] = 'X'
		}
	}
	for i, k := range held {
		id := strconv.Itoa(i)
		if k.path != "/item/"+id || k.host != "h"+id+".example" || k.ua != "agent-"+id {
			t.Fatalf("request %d changed after later requests were promoted: %+v", i, k)
		}
	}
}
