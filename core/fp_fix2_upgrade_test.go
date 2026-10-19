//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

func TestFPFix2UpgradeGrantedAcceptsRequestedLists(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested string
		granted   []string
		want      bool
	}{
		{"single token", "websocket", []string{"websocket"}, true},
		{"layered list", "websocket, foo/2", []string{"websocket, foo/2"}, true},
		{"list in another order", "websocket, foo/2", []string{"FOO/2,WebSocket"}, true},
		{"empty list elements ignored", "websocket", []string{" , websocket ,"}, true},
		{"list split over two lines", "websocket, foo", []string{"websocket", "foo"}, true},
		{"unrequested member", "websocket", []string{"websocket, foo"}, false},
		{"h2c member", "websocket, h2c", []string{"websocket, h2c"}, false},
		{"h2c on a second line", "websocket, h2c", []string{"websocket", "h2c"}, false},
		{"only empty elements", "websocket", []string{","}, false},
		{"empty value", "websocket", []string{""}, false},
		{"no upgrade field", "websocket", nil, false},
		{"nothing requested", "", []string{"websocket"}, false},
	} {
		var p h1Parser
		for _, v := range tc.granted {
			p.hdr = append(p.hdr, [2][]byte{[]byte("upgrade"), []byte(v)})
		}
		ex := &Exchange{req: &fpRequest{Upgrade: tc.requested}}
		if got := p.upgradeGranted(ex); got != tc.want {
			t.Errorf("%s: granted=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFPFix2ProxyTunnelsLayeredUpgradeList(t *testing.T) {
	answer := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket, foo/2\r\nConnection: Upgrade\r\n\r\n"
	addr := fpFixStartProxy(t, fpFixUpgradeOrigin(t, answer), nil)
	request := "GET /ws HTTP/1.1\r\nHost: origin.test\r\nUpgrade: websocket, foo/2\r\nConnection: Upgrade\r\n\r\n"
	if status := fpFixRawExchange(t, addr, request); status != "HTTP/1.1 101 Switching Protocols" {
		t.Fatalf("status line %q", status)
	}
}

func TestFPFix2ProxyRefusesUpgradeListWithUnrequestedMember(t *testing.T) {
	answer := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket, h2c\r\nConnection: Upgrade\r\n\r\n"
	addr := fpFixStartProxy(t, fpFixUpgradeOrigin(t, answer), nil)
	request := "GET /ws HTTP/1.1\r\nHost: origin.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if status := fpFixRawExchange(t, addr, request); !strings.HasPrefix(status, "HTTP/1.1 502") {
		t.Fatalf("status line %q, want 502", status)
	}
}
