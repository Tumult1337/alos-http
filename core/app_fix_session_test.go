//go:build linux && amd64

package core

import (
	"strconv"
	"testing"
)

const appFixDefaultSessionCap = 100_000

func TestAppFixMemorySessionStoreDefaultIsBounded(t *testing.T) {
	store := NewMemorySessionStore()
	data := map[string]any{"cart": 1}
	for i := 0; i < appFixDefaultSessionCap+50; i++ {
		store.Save("anon-"+strconv.Itoa(i), data, 86400)
	}
	if n := store.entries.Len(); n > appFixDefaultSessionCap {
		t.Fatalf("default MemorySessionStore holds %d sessions after %d anonymous saves, want at most %d", n, appFixDefaultSessionCap+50, appFixDefaultSessionCap)
	}
}

func TestAppFixMemorySessionStoreCapEvictsNearestExpiry(t *testing.T) {
	store := NewMemorySessionStoreWithMaxEntries(3)
	for i := 0; i < 5; i++ {
		store.Save("s"+strconv.Itoa(i), map[string]any{"n": i}, 60+i)
	}
	for i := 0; i < 2; i++ {
		if _, ok := store.Get("s" + strconv.Itoa(i)); ok {
			t.Fatalf("session s%d nearest expiry survived admitting new sessions at the cap", i)
		}
	}
	for i := 2; i < 5; i++ {
		if _, ok := store.Get("s" + strconv.Itoa(i)); !ok {
			t.Fatalf("session s%d was lost although older sessions were evictable", i)
		}
	}
	store.Save("s2", map[string]any{"n": 99}, 60)
	if got, _ := store.Get("s2"); got["n"] != 99 {
		t.Fatalf("updating an existing session at the cap failed: %v", got)
	}
	for _, id := range []string{"s3", "s4"} {
		if _, ok := store.Get(id); !ok {
			t.Fatalf("updating an existing session at the cap evicted %s", id)
		}
	}
	store.Delete("s3")
	store.Save("s5", map[string]any{"n": 5}, 60)
	for _, id := range []string{"s2", "s4", "s5"} {
		if _, ok := store.Get(id); !ok {
			t.Fatalf("deleting a session did not free a slot: %s missing", id)
		}
	}
}
