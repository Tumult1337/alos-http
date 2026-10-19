//go:build linux && amd64

package core

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	appFix3StreamBody     = "streamed-body"
	appFix3HandlerVary    = "Accept-Encoding"
	appFix3StreamedPath   = "/stream"
	appFix3BufferedPath   = "/buffered"
	appFix3ProxyLargeSize = 1 << 20
	appFix3ProxyChunked   = 200_000
	appFix3ProxySmallSize = 16
	appFix3CORSPrefix     = "Access-Control-"
)

var appFix3ExactPolicy = CORSConfig{
	AllowOrigins:     []string{proxyFixCORSOrigin},
	AllowMethods:     []string{"GET", "POST"},
	AllowHeaders:     []string{"X-Token"},
	ExposeHeaders:    []string{"X-Trace"},
	AllowCredentials: true,
	MaxAge:           600,
}

var appFix3WildcardPolicy = CORSConfig{AllowOrigins: []string{"*"}, ExposeHeaders: []string{"X-Trace"}}

func appFix3Routes(handled *atomic.Int64) func(*Router) {
	return func(r *Router) {
		r.GET(appFix3StreamedPath, func(req *Request, resp *Response) {
			handled.Add(1)
			sw := resp.EnsureStreamWriter()
			if sw == nil {
				resp.Status(http.StatusInternalServerError).String("no stream")
				return
			}
			resp.SetStreamer(sw)
			if sw.WriteHeader(http.StatusOK, [][2]string{{"Vary", appFix3HandlerVary}}, "text/plain") != nil {
				return
			}
			_ = sw.WriteChunk([]byte(appFix3StreamBody))
			_ = sw.Close()
		})
		r.GET(appFix3BufferedPath, func(req *Request, resp *Response) {
			handled.Add(1)
			resp.SetHeader("Vary", appFix3HandlerVary)
			resp.Status(http.StatusOK).String(appFix3StreamBody)
		})
	}
}

func appFix3CORSView(h http.Header) string {
	var parts []string
	for name, values := range h {
		if strings.HasPrefix(name, appFix3CORSPrefix) {
			parts = append(parts, name+"="+strings.Join(values, "|"))
		}
	}
	var vary []string
	for _, v := range h.Values("Vary") {
		for _, token := range strings.Split(v, ",") {
			if token = strings.TrimSpace(token); token != "" {
				vary = append(vary, token)
			}
		}
	}
	sort.Strings(parts)
	sort.Strings(vary)
	return strings.Join(parts, "; ") + " / Vary=" + strings.Join(vary, ",")
}

func appFix3AssertCORS(t *testing.T, what string, got, want http.Header, wantOrigin string) {
	t.Helper()
	if acao := got.Get("Access-Control-Allow-Origin"); acao != wantOrigin {
		t.Fatalf("%s: Access-Control-Allow-Origin=%q, want %q (headers %v)", what, acao, wantOrigin, got)
	}
	if g, w := appFix3CORSView(got), appFix3CORSView(want); g != w {
		t.Fatalf("%s: CORS view differs from the buffered response\n got: %s\nwant: %s", what, g, w)
	}
}

func appFix3AssertNoCORS(t *testing.T, what string, h http.Header) {
	t.Helper()
	if g, w := appFix3CORSView(h), " / Vary="+appFix3HandlerVary; g != w {
		t.Fatalf("%s without a CORS policy: CORS view %q, want %q", what, g, w)
	}
}

func appFix3RawGet(path string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: x\r\nOrigin: " + proxyFixCORSOrigin + "\r\n\r\n"
}

func appFix3H1(t *testing.T, ts *testServer, path string) http.Header {
	t.Helper()
	resp, body := ts.rawH1(t, appFix3RawGet(path))
	if resp.StatusCode != http.StatusOK || string(body) != appFix3StreamBody {
		t.Fatalf("h1 GET %s: status %d body %q", path, resp.StatusCode, body)
	}
	return resp.Header
}

func appFix3H2(t *testing.T, ts *testServer, path string) http.Header {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.url(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", proxyFixCORSOrigin)
	resp, err := ts.client(t, "h2").Do(req)
	if err != nil {
		t.Fatalf("h2 GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("h2 GET %s: read body: %v", path, err)
	}
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK || string(body) != appFix3StreamBody {
		t.Fatalf("h2 GET %s: proto %d status %d body %q", path, resp.ProtoMajor, resp.StatusCode, body)
	}
	return resp.Header
}

type appFix3H1Case struct {
	name   string
	tls    bool
	inline bool
}

func appFix3H1Cases() []appFix3H1Case {
	return []appFix3H1Case{
		{name: "epoll-plain"},
		{name: "epoll-tls", tls: true},
		{name: "inline-plain", inline: true},
		{name: "inline-tls", tls: true, inline: true},
	}
}

func appFix3Server(t *testing.T, useTLS, inline bool, policy *CORSConfig, handled *atomic.Int64) *testServer {
	t.Helper()
	return newTestServer(t, testServerOptions{
		TLS:    useTLS,
		Routes: appFix3Routes(handled),
		Config: func(c *Config) { c.InlineHandlers = inline },
		Setup: func(s *Server) {
			if policy != nil {
				s.SetCORS(*policy)
			}
		},
	})
}

func TestAppFix3StreamCORSMatchesBufferedH1(t *testing.T) {
	policies := map[string]struct {
		cfg        CORSConfig
		wantOrigin string
	}{
		"exact":    {appFix3ExactPolicy, proxyFixCORSOrigin},
		"wildcard": {appFix3WildcardPolicy, "*"},
	}
	for policyName, policy := range policies {
		for _, tc := range appFix3H1Cases() {
			t.Run(policyName+"/"+tc.name, func(t *testing.T) {
				var handled atomic.Int64
				ts := appFix3Server(t, tc.tls, tc.inline, &policy.cfg, &handled)
				buffered := appFix3H1(t, ts, appFix3BufferedPath)
				streamed := appFix3H1(t, ts, appFix3StreamedPath)
				appFix3AssertCORS(t, "h1 streamed handler response", streamed, buffered, policy.wantOrigin)
			})
		}
	}
}

func TestAppFix3StreamCORSMatchesBufferedH2(t *testing.T) {
	var handled atomic.Int64
	ts := appFix3Server(t, true, false, &appFix3ExactPolicy, &handled)
	buffered := appFix3H2(t, ts, appFix3BufferedPath)
	streamed := appFix3H2(t, ts, appFix3StreamedPath)
	appFix3AssertCORS(t, "h2 streamed handler response", streamed, buffered, proxyFixCORSOrigin)
}

func TestAppFix3StreamCORSPreflightUnchanged(t *testing.T) {
	var handled atomic.Int64
	ts := appFix3Server(t, false, false, &appFix3ExactPolicy, &handled)
	raw := "OPTIONS " + appFix3StreamedPath + " HTTP/1.1\r\nHost: x\r\nOrigin: " + proxyFixCORSOrigin +
		"\r\nAccess-Control-Request-Method: GET\r\n\r\n"
	resp, body := ts.rawH1(t, raw)
	if resp.StatusCode != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("preflight: status %d body %q, want 204 with no body", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != proxyFixCORSOrigin {
		t.Fatalf("preflight: Access-Control-Allow-Origin=%q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "GET, POST" {
		t.Fatalf("preflight: Access-Control-Allow-Methods=%q", got)
	}
	if n := handled.Load(); n != 0 {
		t.Fatalf("preflight reached the streaming handler %d times", n)
	}
}

func TestAppFix3StreamNoCORSControl(t *testing.T) {
	for _, tc := range appFix3H1Cases() {
		t.Run(tc.name, func(t *testing.T) {
			var handled atomic.Int64
			ts := appFix3Server(t, tc.tls, tc.inline, nil, &handled)
			appFix3AssertNoCORS(t, "h1 streamed handler response", appFix3H1(t, ts, appFix3StreamedPath))
		})
	}
	t.Run("h2", func(t *testing.T) {
		var handled atomic.Int64
		ts := appFix3Server(t, true, false, nil, &handled)
		appFix3AssertNoCORS(t, "h2 streamed handler response", appFix3H2(t, ts, appFix3StreamedPath))
	})
}

func appFix3ProxyPaths() map[string]string {
	return map[string]string{
		"content-length-over-buffer-limit": fmt.Sprintf("/cl/%d", appFix3ProxyLargeSize),
		"unknown-length":                   fmt.Sprintf("/chunked/%d", appFix3ProxyChunked),
	}
}

func appFix3ProxyBufferedPath() string { return fmt.Sprintf("/cl/%d", appFix3ProxySmallSize) }

func appFix3ProxyH1(t *testing.T, addr, path string, wantLen int) http.Header {
	t.Helper()
	resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, path, "Origin: "+proxyFixCORSOrigin))
	if resp.StatusCode != http.StatusOK || len(body) != wantLen {
		t.Fatalf("h1 proxied GET %s: status %d with %d body bytes, want 200 with %d", path, resp.StatusCode, len(body), wantLen)
	}
	return resp.Header
}

func appFix3H2RequestWithOrigin(streamID uint32, path string) []byte {
	block := proxyFixAppendHPACKLiteral(nil, proxyFixHpackStaticMethod, http.MethodGet)
	block = append(block, proxyFixHpackStaticSchemeHTTP)
	block = proxyFixAppendHPACKLiteral(block, proxyFixHpackStaticPath, path)
	block = proxyFixAppendHPACKLiteral(block, proxyFixHpackStaticAuthority, proxyFixDomain)
	block = append(block, 0, byte(len("origin")))
	block = append(block, "origin"...)
	block = append(block, byte(len(proxyFixCORSOrigin)))
	block = append(block, proxyFixCORSOrigin...)
	return proxyFixAppendH2Frame(nil, h2FrameHeaders, h2FlagEndStream|h2FlagEndHeaders, streamID, block)
}

func appFix3ProxyH2(t *testing.T, addr, path string, wantLen int) http.Header {
	t.Helper()
	const streamID = 1
	c := proxyFixH2cDial(t, addr)
	defer c.Close()
	if _, err := c.Write(appFix3H2RequestWithOrigin(streamID, path)); err != nil {
		t.Fatalf("write h2 request: %v", err)
	}
	header := http.Header{}
	status := ""
	bodyLen := 0
	for {
		f := c.readFrame(t)
		if f.typ == h2FrameGoAway {
			t.Fatalf("h2 proxied GET %s: GOAWAY", path)
		}
		if f.streamID != streamID {
			continue
		}
		switch f.typ {
		case h2FrameHeaders:
			fields, err := c.dec.Decode(f.payload)
			if err != nil {
				t.Fatalf("decode h2 response headers: %v", err)
			}
			for _, kv := range fields {
				if kv[0] == ":status" {
					status = kv[1]
				} else if !strings.HasPrefix(kv[0], ":") {
					header.Add(kv[0], kv[1])
				}
			}
		case h2FrameData:
			bodyLen += len(f.payload)
		case h2FrameRSTStream:
			t.Fatalf("h2 proxied GET %s: stream reset", path)
		default:
			continue
		}
		if f.flags&h2FlagEndStream != 0 {
			break
		}
	}
	if status != "200" || bodyLen != wantLen {
		t.Fatalf("h2 proxied GET %s: status %q with %d body bytes, want 200 with %d", path, status, bodyLen, wantLen)
	}
	return header
}

func appFix3ProxyLen(path string) int {
	_, sizeText, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	n, _ := strconv.Atoi(sizeText)
	return n
}

func TestAppFix3StreamCORSProxiedStreams(t *testing.T) {
	o := proxyFixShapedOrigin(t, nil)
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
		s.SetCORS(appFix3ExactPolicy)
	})
	bufferedPath := appFix3ProxyBufferedPath()
	bufferedH1 := appFix3ProxyH1(t, addr, bufferedPath, appFix3ProxySmallSize)
	bufferedH2 := appFix3ProxyH2(t, addr, bufferedPath, appFix3ProxySmallSize)
	for name, path := range appFix3ProxyPaths() {
		t.Run(name, func(t *testing.T) {
			wantLen := appFix3ProxyLen(path)
			appFix3AssertCORS(t, "h1 proxied stream", appFix3ProxyH1(t, addr, path, wantLen), bufferedH1, proxyFixCORSOrigin)
			appFix3AssertCORS(t, "h2 proxied stream", appFix3ProxyH2(t, addr, path, wantLen), bufferedH2, proxyFixCORSOrigin)
		})
	}
}

func TestAppFix3StreamNoCORSControlProxied(t *testing.T) {
	o := proxyFixShapedOrigin(t, nil)
	_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), nil)
	for name, path := range appFix3ProxyPaths() {
		t.Run(name, func(t *testing.T) {
			wantLen := appFix3ProxyLen(path)
			for proto, h := range map[string]http.Header{
				"h1": appFix3ProxyH1(t, addr, path, wantLen),
				"h2": appFix3ProxyH2(t, addr, path, wantLen),
			} {
				if g := appFix3CORSView(h); g != " / Vary=" {
					t.Fatalf("%s proxied stream without a CORS policy: CORS view %q, want none", proto, g)
				}
			}
		})
	}
}
