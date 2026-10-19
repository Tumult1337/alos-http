//go:build linux && amd64

package core

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	appFix3SessionCap         = 64
	appFix3SessionFloodFactor = 10
	appFix3SessionMaxAge      = 3600
	appFix3SessionUserKey     = "user"
	appFix3SessionUser        = "alice"
	appFix3ClockPoll          = 2 * time.Millisecond
	appFix3PollDeadline       = 2 * time.Second
)

func appFix3WaitForClockAfter(t *testing.T, stamp int64) {
	t.Helper()
	deadline := turbo.Deadline(appFix3PollDeadline)
	for turbo.UnixNano() <= stamp {
		if turbo.Until(deadline) <= 0 {
			t.Fatal("turbo clock did not advance")
		}
		time.Sleep(appFix3ClockPoll)
	}
}

func appFix3SessionApp(store SessionStore) (HandlerFunc, *string, *string) {
	role := "anon"
	seen := ""
	handler := Sessions(SessionConfig{Store: store, MaxAge: appFix3SessionMaxAge})(func(req *Request, resp *Response) {
		sess := GetSession(req)
		seen = sess.GetString(appFix3SessionUserKey)
		if role != "" {
			sess.Set(appFix3SessionUserKey, role)
		}
		resp.Status(200).String("ok")
	})
	return handler, &role, &seen
}

func appFix3Flood(handler HandlerFunc, n int) int {
	refused := 0
	for i := 0; i < n; i++ {
		if appFix2SessionLogin(handler, "") == "" {
			refused++
		}
	}
	return refused
}

func TestAppFix3SessionFloodAtCapStillAdmitsRealLogin(t *testing.T) {
	store := NewMemorySessionStoreWithMaxEntries(appFix3SessionCap)
	handler, role, seen := appFix3SessionApp(store)

	*role = "anon"
	refused := appFix3Flood(handler, appFix3SessionFloodFactor*appFix3SessionCap)
	appFix3WaitForClockAfter(t, turbo.UnixNano())

	*role = appFix3SessionUser
	login := appFix2SessionLogin(handler, "")
	if login == "" {
		t.Fatal("real login after a cookie-less flood at the cap got no session cookie")
	}
	if _, ok := store.Get(login); !ok {
		t.Fatal("real login cookie names a session the store does not hold")
	}
	if refused != 0 {
		t.Fatalf("%d of %d cookie-less creates at the cap got no session cookie", refused, appFix3SessionFloodFactor*appFix3SessionCap)
	}
	appFix3WaitForClockAfter(t, turbo.UnixNano())

	*role = "anon"
	if refused := appFix3Flood(handler, appFix3SessionCap/2); refused != 0 {
		t.Fatalf("%d cookie-less creates after the login got no session cookie", refused)
	}

	*role = ""
	if again := appFix2SessionLogin(handler, login); again != "" {
		t.Fatalf("read-only request with the login cookie got a new cookie %q", again)
	}
	if *seen != appFix3SessionUser {
		t.Fatalf("request with the login cookie saw user %q, want %q", *seen, appFix3SessionUser)
	}
}

func TestAppFix3SessionMemoryBoundedAtCap(t *testing.T) {
	store := NewMemorySessionStoreWithMaxEntries(appFix3SessionCap)
	data := map[string]any{"n": 1}
	const saves = 50 * appFix3SessionCap
	for i := 0; i < saves; i++ {
		id := "flood-" + strconv.Itoa(i)
		store.Save(id, data, appFix3SessionMaxAge)
		if _, ok := store.Get(id); !ok {
			t.Fatalf("save %d at the cap was not stored", i)
		}
		if n := store.tracked.Load(); n > appFix3SessionCap {
			t.Fatalf("tracked %d sessions after save %d, cap %d", n, i, appFix3SessionCap)
		}
		if i%appFix3SessionCap == 0 {
			st := store.entries.Stats()
			if st.LiveEntries > appFix3SessionCap || st.UsedSlots > appFix3SessionCap {
				t.Fatalf("after save %d: live %d, used slots %d, cap %d", i, st.LiveEntries, st.UsedSlots, appFix3SessionCap)
			}
		}
	}
	if n := store.entries.Len(); n > appFix3SessionCap {
		t.Fatalf("store holds %d sessions after %d saves, cap %d", n, saves, appFix3SessionCap)
	}
}

func TestAppFix3SessionConcurrentFloodStaysBounded(t *testing.T) {
	const workers = 4
	store := NewMemorySessionStoreWithMaxEntries(appFix3SessionCap)
	data := map[string]any{"n": 1}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 20*appFix3SessionCap; i++ {
				store.Save("w"+strconv.Itoa(w)+"-"+strconv.Itoa(i), data, appFix3SessionMaxAge)
			}
		}(w)
	}
	wg.Wait()
	if n := store.entries.Len(); n > appFix3SessionCap+workers {
		t.Fatalf("store holds %d sessions after a concurrent flood, cap %d plus %d in flight", n, appFix3SessionCap, workers)
	}
	store.Save("after-flood", data, appFix3SessionMaxAge)
	if _, ok := store.Get("after-flood"); !ok {
		t.Fatal("session saved after a concurrent flood was not stored")
	}
}

func TestAppFix3SessionExpiredSessionsReclaimedBeforeEviction(t *testing.T) {
	const (
		shortLived = 16
		shortTTL   = 150 * time.Millisecond
		poll       = 15 * time.Millisecond
	)
	store := NewMemorySessionStoreWithMaxEntries(appFix3SessionCap)
	data := map[string]any{"n": 1}
	for i := 0; i < shortLived; i++ {
		store.saveWithTTL("short-"+strconv.Itoa(i), data, shortTTL)
	}
	for i := shortLived; i < appFix3SessionCap; i++ {
		store.Save("long-"+strconv.Itoa(i), data, appFix3SessionMaxAge)
	}
	deadline := turbo.Deadline(appFix3PollDeadline)
	for store.entries.Has("short-" + strconv.Itoa(shortLived-1)) {
		if turbo.Until(deadline) <= 0 {
			t.Fatal("short-lived sessions never expired")
		}
		time.Sleep(poll)
	}
	for i := 0; i < shortLived; i++ {
		if _, ok := store.Get("short-" + strconv.Itoa(i)); ok {
			t.Fatalf("expired session short-%d is still readable", i)
		}
	}

	store.Save("newcomer", data, appFix3SessionMaxAge)
	for i := shortLived; i < appFix3SessionCap; i++ {
		if _, ok := store.Get("long-" + strconv.Itoa(i)); !ok {
			t.Fatalf("live session long-%d was evicted although expired sessions freed enough room", i)
		}
	}
	if _, ok := store.Get("newcomer"); !ok {
		t.Fatal("new session at the cap was not stored")
	}
	want := int64(appFix3SessionCap - shortLived + 1)
	if st := store.entries.Stats(); st.UsedSlots != want || st.LiveEntries != want {
		t.Fatalf("after reclaim: used slots %d, live %d, want %d (expired entries not physically reclaimed)", st.UsedSlots, st.LiveEntries, want)
	}
	if n := store.tracked.Load(); n != want {
		t.Fatalf("tracked %d sessions after reclaim, want %d", n, want)
	}
}
