//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

const appFix2SessionCookie = "alos_session"

func appFix2SessionLogin(handler HandlerFunc, cookie string) string {
	req := &Request{Method: "GET", Path: "/login"}
	if cookie != "" {
		req.Headers = [][2]string{{"Cookie", appFix2SessionCookie + "=" + cookie}}
	}
	resp := &Response{}
	resp.Reset()
	handler(req, resp)
	for _, h := range resp.Headers {
		if EqualFoldASCII(h[0], "Set-Cookie") && strings.HasPrefix(h[1], appFix2SessionCookie+"=") {
			value := strings.TrimPrefix(h[1], appFix2SessionCookie+"=")
			if end := strings.IndexByte(value, ';'); end >= 0 {
				value = value[:end]
			}
			return value
		}
	}
	return ""
}

func TestAppFix2SessionCookieOnlyForStoredSession(t *testing.T) {
	store := NewMemorySessionStoreWithMaxEntries(1)
	handler := Sessions(SessionConfig{Store: store})(func(req *Request, resp *Response) {
		GetSession(req).Set("user", "u")
		resp.Status(200).String("ok")
	})
	first := appFix2SessionLogin(handler, "")
	if first == "" {
		t.Fatal("first session got no cookie")
	}
	if _, ok := store.Get(first); !ok {
		t.Fatal("first session cookie names an id the store does not hold")
	}
	second := appFix2SessionLogin(handler, "")
	if second == "" {
		t.Fatal("store at its cap refused a new session")
	}
	if _, ok := store.Get(second); !ok {
		t.Fatalf("session cookie %q names an id the store does not hold", second)
	}
	if again := appFix2SessionLogin(handler, second); again != second {
		t.Fatalf("existing session at the cap got cookie %q, want %q", again, second)
	}
}

type appFix2RecordingStore struct {
	saved map[string]map[string]any
}

func (s *appFix2RecordingStore) Get(id string) (map[string]any, bool) {
	data, ok := s.saved[id]
	return data, ok
}

func (s *appFix2RecordingStore) Save(id string, data map[string]any, maxAge int) {
	s.saved[id] = data
}

func (s *appFix2RecordingStore) Delete(id string) {
	delete(s.saved, id)
}

func TestAppFix2SessionCustomStoreStillGetsCookie(t *testing.T) {
	store := &appFix2RecordingStore{saved: map[string]map[string]any{}}
	handler := Sessions(SessionConfig{Store: store})(func(req *Request, resp *Response) {
		GetSession(req).Set("user", "u")
	})
	id := appFix2SessionLogin(handler, "")
	if _, ok := store.saved[id]; id == "" || !ok {
		t.Fatalf("custom store session cookie %q, saved ids %v", id, store.saved)
	}
}

func BenchmarkAppFix2SessionModifiedRequest(b *testing.B) {
	store := NewMemorySessionStore()
	handler := Sessions(SessionConfig{Store: store})(func(req *Request, resp *Response) {
		GetSession(req).Set("n", 1)
	})
	id := appFix2SessionLogin(handler, "")
	headers := [][2]string{{"Cookie", appFix2SessionCookie + "=" + id}}
	req := &Request{Method: "GET", Path: "/"}
	resp := &Response{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		*req = Request{Method: "GET", Path: "/", Headers: headers}
		resp.Reset()
		handler(req, resp)
	}
}
