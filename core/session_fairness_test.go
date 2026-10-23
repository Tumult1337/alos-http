//go:build linux && amd64

package core

import (
	"strconv"
	"testing"
)

const (
	sessionFairCapacity = 100
	sessionFairUsers    = 40
	sessionFairFlood    = 1000
	sessionFairMaxAge   = 3600
)

func TestMemorySessionStoreFloodKeepsReturningSessions(t *testing.T) {
	s := NewMemorySessionStoreWithMaxEntries(sessionFairCapacity)
	for i := range sessionFairUsers {
		s.Save("user"+strconv.Itoa(i), map[string]any{"uid": i}, sessionFairMaxAge)
	}
	for i := range sessionFairUsers {
		if _, ok := s.Get("user" + strconv.Itoa(i)); !ok {
			t.Fatalf("user%d missing before the flood", i)
		}
	}
	for i := range sessionFairFlood {
		s.Save("anon"+strconv.Itoa(i), map[string]any{"csrf": i}, sessionFairMaxAge)
	}
	lost := 0
	for i := range sessionFairUsers {
		if _, ok := s.Get("user" + strconv.Itoa(i)); !ok {
			lost++
		}
	}
	if lost != 0 {
		t.Fatalf("a flood of never-returned sessions evicted %d of %d returning sessions", lost, sessionFairUsers)
	}
	if n := s.entries.Len(); n > sessionFairCapacity {
		t.Fatalf("store holds %d sessions, cap %d", n, sessionFairCapacity)
	}
	if _, ok := s.Get("anon" + strconv.Itoa(sessionFairFlood-1)); !ok {
		t.Fatal("the newest flood session was not stored")
	}
}

func TestMemorySessionStoreResaveKeepsReturningStatus(t *testing.T) {
	s := NewMemorySessionStoreWithMaxEntries(sessionFairCapacity)
	for i := range sessionFairUsers {
		id := "user" + strconv.Itoa(i)
		s.Save(id, map[string]any{"uid": i}, sessionFairMaxAge)
		data, _ := s.Get(id)
		data["seen"] = true
		s.Save(id, data, sessionFairMaxAge)
	}
	for i := range sessionFairFlood {
		s.Save("anon"+strconv.Itoa(i), map[string]any{"csrf": i}, sessionFairMaxAge)
	}
	for i := range sessionFairUsers {
		if _, ok := s.Get("user" + strconv.Itoa(i)); !ok {
			t.Fatalf("user%d lost after a re-save and a flood", i)
		}
	}
}

func TestMemorySessionStoreEvictsSoonestExpiringReturningSessionWhenAllReturn(t *testing.T) {
	s := NewMemorySessionStoreWithMaxEntries(sessionFairCapacity)
	for i := range sessionFairCapacity {
		id := "user" + strconv.Itoa(i)
		s.Save(id, map[string]any{"uid": i}, sessionFairMaxAge+i)
		s.Get(id)
	}
	s.Save("late", map[string]any{}, sessionFairMaxAge)
	if _, ok := s.Get("user0"); ok {
		t.Fatal("the soonest-expiring returning session survived a full-store save")
	}
	if _, ok := s.Get("user" + strconv.Itoa(sessionFairCapacity-1)); !ok {
		t.Fatal("the latest-expiring returning session was evicted")
	}
}
