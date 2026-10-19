//go:build linux && amd64

package core

import (
	"strconv"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	appFixShardKeys        = 500
	appFixShardRangeWithin = 150 * time.Millisecond
)

func appFixFilledShardMap() *ShardedMap[string, int] {
	m := NewShardedMap[string, int](StringHash)
	for i := 0; i < appFixShardKeys; i++ {
		m.Store("k"+strconv.Itoa(i), i)
	}
	return m
}

func appFixRangeReturns(t *testing.T, what string, m *ShardedMap[string, int], fn func(string, int) bool) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		m.Range(fn)
		close(done)
	}()
	select {
	case <-done:
	case <-turbo.After(appFixShardRangeWithin):
		t.Fatalf("Range whose callback calls %s did not return within %v (self-deadlock on the shard lock)", what, appFixShardRangeWithin)
	}
}

func appFixShardMapLen(m *ShardedMap[string, int]) int {
	n := 0
	m.Range(func(string, int) bool { n++; return true })
	return n
}

func TestAppFixShardedMapRangeCallbackMayDelete(t *testing.T) {
	m := appFixFilledShardMap()
	appFixRangeReturns(t, "Delete", m, func(k string, _ int) bool { m.Delete(k); return true })
	if n := appFixShardMapLen(m); n != 0 {
		t.Fatalf("%d entries left after deleting every key from inside Range", n)
	}
}

func TestAppFixShardedMapRangeCallbackMayStore(t *testing.T) {
	m := appFixFilledShardMap()
	appFixRangeReturns(t, "Store", m, func(k string, v int) bool { m.Store(k, v+1); return true })
	for i := 0; i < appFixShardKeys; i++ {
		if v, ok := m.Load("k" + strconv.Itoa(i)); !ok || v != i+1 {
			t.Fatalf("key k%d = %d ok=%v after a Store from inside Range, want %d", i, v, ok, i+1)
		}
	}
}

func TestAppFixShardedMapRangeStopsEarly(t *testing.T) {
	m := appFixFilledShardMap()
	visited := 0
	m.Range(func(string, int) bool { visited++; return visited < 3 })
	if visited != 3 {
		t.Fatalf("Range visited %d entries after the callback returned false on the third, want 3", visited)
	}
}
