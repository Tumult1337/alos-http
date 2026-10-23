//go:build linux && amd64

package core

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bytedance/sonic"
)

func TestPerfCoreBytes1MSteadyStateZeroAlloc(t *testing.T) {
	perfCoreSkipAllocLockUnderRace(t)
	body := perfCoreBody(perfCoreBody1M)
	resp := perfCoreResp()
	resp.Bytes(body)
	allocs := testing.AllocsPerRun(50, func() {
		resp.resetFastH1()
		resp.Bytes(body)
	})
	if allocs != 0 {
		t.Fatalf("1MB Bytes after warm-up allocates %.1f/op, want 0", allocs)
	}
	if !bytes.Equal(resp.GetBody(), body) {
		t.Fatal("1MB body corrupted")
	}
}

func TestPerfCoreResetDoesNotRetainLargeBody(t *testing.T) {
	for _, reset := range []func(*Response){(*Response).Reset, (*Response).resetFastH1} {
		resp := perfCoreResp()
		resp.Bytes(perfCoreBody(perfCoreBody1M))
		reset(resp)
		if cap(resp.body) > bufferShrinkThreshold {
			t.Fatalf("reset kept a %d-byte body buffer on the response", cap(resp.body))
		}
		resp.Bytes([]byte("small"))
		if string(resp.GetBody()) != "small" {
			t.Fatalf("body after reset = %q", resp.GetBody())
		}
	}
}

func TestPerfCoreBytesNoCopy(t *testing.T) {
	src := []byte("zero-copy body")
	resp := perfCoreResp()
	resp.Status(200).BytesNoCopy(src)
	if resp.ContentType != "application/octet-stream" || resp.BodyLen() != len(src) || string(resp.GetBody()) != string(src) {
		t.Fatalf("BytesNoCopy: type %q len %d body %q", resp.ContentType, resp.BodyLen(), resp.GetBody())
	}
	if &resp.bodyBytesUnsafe()[0] != &src[0] {
		t.Fatal("BytesNoCopy copied the body")
	}
	out := appendPlainResponseMode(resp, nil, true, true)
	if !bytes.HasSuffix(out, src) || !bytes.Contains(out, []byte("Content-Length: "+strconv.Itoa(len(src)))) {
		t.Fatalf("serialized: %q", out)
	}
	resp.resetFastH1()
	if resp.BodyLen() != 0 {
		t.Fatal("reset kept the no-copy body")
	}
	if raceEnabled {
		return
	}
	if allocs := testing.AllocsPerRun(100, func() {
		resp.resetFastH1()
		resp.BytesNoCopy(src)
	}); allocs != 0 {
		t.Fatalf("BytesNoCopy allocates %.1f/op", allocs)
	}
}

func TestPerfCoreJSONMarshalMatchesSonic(t *testing.T) {
	values := []any{
		perfCoreMessage{Message: "Hello, World!"},
		&perfCoreMessage{Message: "<script>&amp; \xff"},
		map[string]any{"a": []int{1, 2}},
		[]string{"x", "y"},
		nil,
	}
	resp := perfCoreResp()
	for _, v := range values {
		want, err := sonic.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		resp.resetFastH1()
		if err := resp.JSONMarshal(v); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(resp.GetBody(), want) || resp.ContentType != "application/json; charset=utf-8" {
			t.Fatalf("JSONMarshal(%T) = %q, sonic.Marshal = %q", v, resp.GetBody(), want)
		}
		j := AcquireJSON()
		got, err := j.MarshalInto(v)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("MarshalInto(%T) = %q %v, want %q", v, got, err, want)
		}
		j.Release()
	}
	resp.resetFastH1()
	if err := resp.JSONMarshal(func() {}); err == nil || resp.StatusCode != 500 || string(resp.GetBody()) != "json marshal error" {
		t.Fatalf("unsupported value: err %v status %d body %q", err, resp.StatusCode, resp.GetBody())
	}
	j := AcquireJSON()
	if got, err := j.MarshalInto(make(chan int)); err == nil || got != nil {
		t.Fatalf("MarshalInto(chan) = %q %v", got, err)
	}
	j.Release()
}

const perfCoreSonicEncodeIntoAllocs = 1

func TestPerfCoreJSONMarshalAllocBudget(t *testing.T) {
	perfCoreSkipAllocLockUnderRace(t)
	msg := &perfCoreMessage{Message: perfCoreHello}
	resp := perfCoreResp()
	_ = resp.JSONMarshal(msg)
	if allocs := testing.AllocsPerRun(200, func() {
		resp.resetFastH1()
		_ = resp.JSONMarshal(msg)
	}); allocs > perfCoreSonicEncodeIntoAllocs {
		t.Fatalf("JSONMarshal(pointer) allocates %.1f/op", allocs)
	}
	j := AcquireJSON()
	_, _ = j.MarshalInto(msg)
	if allocs := testing.AllocsPerRun(200, func() {
		_, _ = j.MarshalInto(msg)
	}); allocs > perfCoreSonicEncodeIntoAllocs {
		t.Fatalf("MarshalInto(pointer) allocates %.1f/op", allocs)
	}
	j.Release()
}

func TestPerfCoreCookieParseZeroAlloc(t *testing.T) {
	perfCoreSkipAllocLockUnderRace(t)
	req := perfCoreBrowserReq()
	req.Cookie("sid")
	if allocs := testing.AllocsPerRun(200, func() {
		perfCoreBrowserNextRequest(req)
		perfCoreSinkString = req.Cookie("sid")
	}); allocs != 0 {
		t.Fatalf("cookie parse allocates %.1f/op", allocs)
	}
	if perfCoreSinkString != "8f14e45fceea167a5a36dedd4bea2543" {
		t.Fatalf("sid = %q", perfCoreSinkString)
	}
}

func TestPerfCoreCookiePairCapAcrossHeaders(t *testing.T) {
	var first, second strings.Builder
	for i := 0; i < 700; i++ {
		first.WriteString("a" + strconv.Itoa(i) + "=1; ")
		second.WriteString("b" + strconv.Itoa(i) + "=2; ")
	}
	req := &Request{Headers: [][2]string{{"Cookie", first.String()}, {"X", "y"}, {"cookie", second.String()}}}
	cookies := req.Cookies()
	if len(cookies) != maxCookiePairs {
		t.Fatalf("parsed %d cookies, want %d", len(cookies), maxCookiePairs)
	}
	if cookies[0].Name != "a0" || cookies[699].Name != "a699" || cookies[700].Name != "b0" || cookies[999].Name != "b299" {
		t.Fatalf("order: %s %s %s %s", cookies[0].Name, cookies[699].Name, cookies[700].Name, cookies[999].Name)
	}
	if req.Cookie("b300") != "" || req.Cookie("b299") != "2" {
		t.Fatal("cap boundary lookup wrong")
	}
	if got := parseCookieHeader(first.String() + second.String()); len(got) != maxCookiePairs {
		t.Fatalf("single header parsed %d", len(got))
	}
}

func TestPerfCoreRateLimitEngineCheckHitZeroAlloc(t *testing.T) {
	rle := NewRateLimitEngine()
	defer rle.Stop()
	rle.SetRules([]RateLimitRule{{Path: "/mw", MaxReqs: 3, Window: time.Hour}})
	for _, ip := range []string{"192.0.2.7", "192.0.2.8"} {
		for i := 0; i < 3; i++ {
			if ok, _, _ := rle.Check(ip, "/mw"); !ok {
				t.Fatalf("%s request %d refused", ip, i)
			}
		}
		if ok, _, _ := rle.Check(ip, "/mw"); ok {
			t.Fatalf("%s request 4 allowed", ip)
		}
	}
	if n := rle.clients.Len(); n != 2 {
		t.Fatalf("entries = %d, want 2", n)
	}
	rle.SetRules([]RateLimitRule{{Path: "/mw", MaxReqs: 1 << 40, Window: time.Hour}})
	rle.Check("192.0.2.9", "/mw")
	if raceEnabled {
		return
	}
	if allocs := testing.AllocsPerRun(200, func() { rle.Check("192.0.2.9", "/mw") }); allocs != 0 {
		t.Fatalf("Check on a known client allocates %.1f/op", allocs)
	}
}

func perfCoreSkipAllocLockUnderRace(t *testing.T) {
	t.Helper()
	if raceEnabled {
		t.Skip("allocation budgets are meaningless under the race detector")
	}
}
