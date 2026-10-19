//go:build linux && amd64

package core

import (
	"fmt"
	"strings"
	"testing"
)

func TestConnectionNominations(t *testing.T) {
	cases := []struct {
		name    string
		headers [][2]string
		yes     []string
		no      []string
	}{
		{
			name:    "no Connection header",
			headers: [][2]string{{"X-Secret", "1"}},
			no:      []string{"X-Secret", "connection", ""},
		},
		{
			name:    "single token, any case",
			headers: [][2]string{{"connection", "X-Secret"}},
			yes:     []string{"X-Secret", "x-secret", "X-SECRET"},
			no:      []string{"X-Secre", "X-Secrets", "X-Other"},
		},
		{
			name:    "list with OWS and empty elements",
			headers: [][2]string{{"Connection", " ,  x-a ,\tX-B,, ,x-c\t"}},
			yes:     []string{"X-A", "x-b", "X-C"},
			no:      []string{"", " x-a", "X-D"},
		},
		{
			name:    "every Connection field line contributes",
			headers: [][2]string{{"Connection", "x-one"}, {"X-Two", "2"}, {"CONNECTION", "x-two"}},
			yes:     []string{"x-one", "X-Two"},
		},
		{
			name:    "standard hop-by-hop tokens are not recorded",
			headers: [][2]string{{"Connection", "keep-alive, Upgrade, close, x-a"}},
			yes:     []string{"x-a", "close"},
			no:      []string{"Keep-Alive", "upgrade"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nominated := connectionNominations(tc.headers)
			for _, name := range tc.yes {
				if !nominated.nominates(name) {
					t.Errorf("%q not nominated", name)
				}
			}
			for _, name := range tc.no {
				if nominated.nominates(name) {
					t.Errorf("%q nominated", name)
				}
			}
		})
	}
}

func TestConnectionNominationsBeyondInlineCapacity(t *testing.T) {
	const total = maxConnectionTokens * 3
	tokens := make([]string, total)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("X-Tok-%d", i)
	}
	nominated := connectionNominations([][2]string{
		{"Connection", strings.Join(tokens[:total/2], ",")},
		{"Connection", strings.Join(tokens[total/2:], ", ")},
	})
	for _, tok := range tokens {
		if !nominated.nominates(tok) || !nominated.nominates(strings.ToUpper(tok)) {
			t.Fatalf("%q lost past the inline capacity", tok)
		}
	}
	if nominated.nominates("X-Tok-999") {
		t.Fatal("unlisted token nominated")
	}
}

func TestConnectionNominationsAllocFreeWithoutCustomTokens(t *testing.T) {
	headers := [][2]string{{"Accept", "*/*"}, {"Connection", "keep-alive, Upgrade"}, {"Upgrade", "websocket"}}
	allocs := testing.AllocsPerRun(100, func() {
		nominated := connectionNominations(headers)
		if nominated.nominates("accept") || nominated.nominates("upgrade") {
			t.Fatal("wrong nominations")
		}
	})
	if allocs != 0 {
		t.Fatalf("%v allocs per request, want 0", allocs)
	}
}

func connectionTokenRequest() *Request {
	return &Request{
		Method: "GET", Path: "/t", Host: "app.test", RemoteAddr: "203.0.113.7:5000",
		Headers: [][2]string{
			{"X-Secret", "1"},
			{"Connection", "X-Secret, x-also"},
			{"X-Also", "2"},
			{"X-Keep", "3"},
		},
	}
}

func assertConnectionTokensStripped(t *testing.T, wire string) {
	t.Helper()
	lower := strings.ToLower(wire)
	for _, banned := range []string{"\r\nx-secret:", "\r\nx-also:", "x-secret, x-also"} {
		if strings.Contains(lower, banned) {
			t.Errorf("upstream request still carries %q:\n%s", banned, wire)
		}
	}
	if !strings.Contains(wire, "\r\nX-Keep: 3\r\n") {
		t.Errorf("unnominated header dropped:\n%s", wire)
	}
}

func TestProxyConnectionTokens(t *testing.T) {
	wire := string(appendProxyRequest(nil, connectionTokenRequest(), "127.0.0.1:9000"))
	assertConnectionTokensStripped(t, wire)
}

func referenceNominations(values []string) map[string]bool {
	ref := map[string]bool{}
	for _, v := range values {
		for _, token := range strings.Split(v, ",") {
			token = trimASCIISpace(token)
			if token != "" && !isHopByHopFold(token) {
				ref[ToLowerASCII(token)] = true
			}
		}
	}
	return ref
}

func FuzzConnectionTokens(f *testing.F) {
	f.Add("X-Secret, x-also", "X-Secret\nX-Also\nX-Keep")
	f.Add("keep-alive, Upgrade", "Upgrade\nKeep-Alive\nX-A")
	f.Add(strings.Repeat("x-t,", 40), "X-T\nx-u")
	f.Add(" ,\t,, ", "")
	f.Add("\u0130x", "\u0131x\nIX")
	f.Fuzz(func(t *testing.T, connection, names string) {
		values := strings.Split(connection, "\n")
		headers := make([][2]string, 0, len(values)+8)
		for _, v := range values {
			headers = append(headers, [2]string{"Connection", v})
		}
		for _, name := range strings.Split(names, "\n") {
			headers = append(headers, [2]string{name, "v"})
		}
		nominated := connectionNominations(headers)
		ref := referenceNominations(values)
		for _, h := range headers {
			if got, want := nominated.nominates(h[0]), ref[ToLowerASCII(h[0])]; got != want {
				t.Fatalf("nominates(%q) = %v, reference %v (Connection %q)", h[0], got, want, connection)
			}
		}
		wire := string(appendProxyRequest(nil, &Request{Method: "GET", Path: "/", Headers: headers}, "127.0.0.1:80"))
		head, _, _ := strings.Cut(wire, "\r\n\r\n")
		for _, h := range headers {
			if ref[ToLowerASCII(h[0])] && strings.Contains(head+"\r\n", "\r\n"+h[0]+": "+h[1]+"\r\n") {
				t.Fatalf("nominated %q relayed in %q", h[0], head)
			}
		}
	})
}
