//go:build linux && amd64

package core

import (
	"net/http"
	"testing"
	"time"
)

const (
	proxyFix4CarryIP      = "192.0.2.9"
	proxyFix4CarryPath    = "/carry"
	proxyFix4HandledBody  = "handled"
	proxyFix4UnusedPrefix = "/elsewhere"
)

type proxyFix4CarryFixture struct {
	s       *Server
	w       *epollWorker
	req     *Request
	limited RateLimitRule
	unused  RateLimitRule
	probe   *proxyFix3HookProbe
}

func newProxyFix4CarryFixture(t *testing.T) *proxyFix4CarryFixture {
	t.Helper()
	f := &proxyFix4CarryFixture{probe: &proxyFix3HookProbe{}}
	f.limited = proxyFix3LimitRule(proxyFix3CustomLimit(f.probe))
	f.unused = RateLimitRule{Path: proxyFix4UnusedPrefix, MaxReqs: 1, Window: time.Minute}
	f.s = New(Config{Addr: "127.0.0.1:0", PlainHTTP: true})
	f.s.SetRateLimitRules([]RateLimitRule{f.limited})
	t.Cleanup(f.s.rateLimitEngine.Load().Stop)
	f.s.Router.GET(proxyFix4CarryPath, func(req *Request, resp *Response) { resp.String(proxyFix4HandledBody) })
	f.s.Router.Build()
	f.w = &epollWorker{server: f.s}
	f.req = &Request{Method: "GET", Path: proxyFix4CarryPath, RemoteAddr: proxyFix4CarryIP + ":40000"}
	return f
}

func (f *proxyFix4CarryFixture) loopOutcome() proxyAdmitOutcome {
	return f.w.proxiedRateLimitOutcome(proxyFix4CarryIP, f.req, &Response{})
}

func (f *proxyFix4CarryFixture) dispatch(t *testing.T, wantStatus int, wantBody string) {
	t.Helper()
	resp := &Response{}
	resp.Reset()
	f.s.dispatch(f.req, resp)
	if resp.StatusCode != wantStatus || string(resp.GetBody()) != wantBody {
		t.Fatalf("dispatch: status %d body %q, want %d %q", resp.StatusCode, resp.GetBody(), wantStatus, wantBody)
	}
	if f.req.loopRateLimitRefusal.refused() {
		t.Fatal("dispatch left the loop's rate-limit refusal on the request")
	}
}

func TestProxyFix4LoopRefusalIsCarriedNotRechecked(t *testing.T) {
	f := newProxyFix4CarryFixture(t)
	if got := f.loopOutcome(); got != proxyAdmitted {
		t.Fatalf("first loop check: outcome %d, want admitted", got)
	}
	if got := f.loopOutcome(); got != proxyAdmitDispatch {
		t.Fatalf("refused loop check with a limit hook: outcome %d, want dispatch", got)
	}
	if n := f.probe.calls.Load(); n != 0 {
		t.Fatalf("limit hook ran %d times in the loop", n)
	}
	f.s.SetRateLimitRules([]RateLimitRule{f.unused})
	f.dispatch(t, http.StatusTooManyRequests, proxyFix3LimitedBody)
	if n := f.probe.calls.Load(); n != 1 {
		t.Fatalf("limit hook ran %d times for one refusal", n)
	}
	f.dispatch(t, http.StatusOK, proxyFix4HandledBody)
}

func TestProxyFix4LoopRefusalDoesNotOutliveAnEarlyDispatchExit(t *testing.T) {
	f := newProxyFix4CarryFixture(t)
	f.loopOutcome()
	if got := f.loopOutcome(); got != proxyAdmitDispatch {
		t.Fatalf("refused loop check with a limit hook: outcome %d, want dispatch", got)
	}
	f.s.SetCORS(CORSConfig{AllowOrigins: []string{"*"}})
	f.req.Method = "OPTIONS"
	f.dispatch(t, http.StatusNoContent, "")
	f.s.SetRateLimitRules([]RateLimitRule{f.unused})
	f.req.Method = "GET"
	f.dispatch(t, http.StatusOK, proxyFix4HandledBody)
	if n := f.probe.calls.Load(); n != 0 {
		t.Fatalf("limit hook ran %d times, want none: the preflight returned before the rate-limit step", n)
	}
}

func TestProxyFix4HooklessLoopRefusalIsAnsweredInLoop(t *testing.T) {
	f := newProxyFix4CarryFixture(t)
	f.s.SetRateLimitRules([]RateLimitRule{proxyFix3LimitRule(nil)})
	f.loopOutcome()
	resp := &Response{}
	resp.Reset()
	blockedBefore := Stats.BlockedReqs.Load()
	if got := f.w.proxiedRateLimitOutcome(proxyFix4CarryIP, f.req, resp); got != proxyAdmitAnswered {
		t.Fatalf("refused loop check without limit hooks: outcome %d, want answered in the loop", got)
	}
	if f.req.loopRateLimitRefusal.refused() {
		t.Fatal("a hookless refusal was carried to dispatch")
	}
	if resp.StatusCode != http.StatusTooManyRequests || string(resp.GetBody()) != proxyFix4DefaultBody || proxyFixHeaderValue(resp.Headers, "retry-after") == "" {
		t.Fatalf("hookless refusal: status %d body %q retry-after %q", resp.StatusCode, resp.GetBody(), proxyFixHeaderValue(resp.Headers, "retry-after"))
	}
	if n := Stats.BlockedReqs.Load() - blockedBefore; n != 1 {
		t.Fatalf("blocked counter rose by %d for one refusal", n)
	}
}
