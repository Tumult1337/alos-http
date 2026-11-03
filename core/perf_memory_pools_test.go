//go:build linux && amd64

package core

import (
	"bytes"
	"runtime"
	"testing"
	"unsafe"
)

func TestPerfMemoryLargeBufClasses(t *testing.T) {
	prev := 0
	for class := range largeBufClassCount {
		size := largeBufClassSize(class)
		if size <= prev {
			t.Fatalf("class %d size %d not above previous %d", class, size, prev)
		}
		if size%(8<<10) != 0 {
			t.Fatalf("class %d size %d is not page-rounded", class, size)
		}
		prev = size
	}
	if largeBufClassSize(0) != 1<<largeBufMinShift || prev != 1<<largeBufMaxShift {
		t.Fatalf("class range [%d, %d]", largeBufClassSize(0), prev)
	}
	for _, n := range []int{1, 1 << 17, 1<<17 + 1, 1 << 20, 1<<20 + 200, 3 << 20, 1 << 22} {
		class := largeBufClassAtLeast(n)
		if class < 0 || largeBufClassSize(class) < n || (class > 0 && largeBufClassSize(class-1) >= n) {
			t.Fatalf("AtLeast(%d) = class %d", n, class)
		}
	}
	if largeBufClassAtLeast(1<<22+1) != -1 || largeBufClassAtMost(1<<largeBufMinShift-1) != -1 {
		t.Fatal("out-of-range sizes mapped to a class")
	}
	for _, n := range []int{1 << 17, 1<<20 + 200, 5 << 20} {
		class := largeBufClassAtMost(n)
		if largeBufClassSize(class) > n || (class+1 < largeBufClassCount && largeBufClassSize(class+1) <= n) {
			t.Fatalf("AtMost(%d) = class %d", n, class)
		}
	}
}

func TestPerfMemoryLargeBufReuseWhileReachable(t *testing.T) {
	p := largeBufPool{maxPerClass: largeBufMaxPerClass}
	b := p.get(1<<20 + 100)
	if cap(b) < 1<<20+100 || len(b) != 0 {
		t.Fatalf("get returned len %d cap %d", len(b), cap(b))
	}
	b = append(b, "secret"...)
	p.put(b)
	again := p.get(1<<20 + 100)
	if unsafe.SliceData(again) != unsafe.SliceData(b) || len(again) != 0 || cap(again) != cap(b) {
		t.Fatal("pooled buffer not reused, or reused with stale length or a different capacity")
	}
	if other := p.get(1<<20 + 100); unsafe.SliceData(other) == unsafe.SliceData(again) {
		t.Fatal("one pooled buffer handed out twice")
	}
	runtime.KeepAlive(b)
}

func TestPerfMemoryLargeBufCollectedBuffersAreNotServed(t *testing.T) {
	p := largeBufPool{maxPerClass: largeBufMaxPerClass}
	class := largeBufClassAtLeast(1 << 20)
	p.put(make([]byte, 0, largeBufClassSize(class)))
	runtime.GC()
	runtime.GC()
	if live := dropCollectedLargeBufs(append([]weakLargeBuf(nil), p.classes[class]...)); len(live) != 0 {
		t.Fatalf("%d unreachable pooled buffers survived two GC cycles", len(live))
	}
	if b := p.get(1 << 20); cap(b) != largeBufClassSize(class) || len(b) != 0 {
		t.Fatalf("get after collection returned len %d cap %d", len(b), cap(b))
	}
	if n := len(p.classes[class]); n != 0 {
		t.Fatalf("collected entries left in the class list: %d", n)
	}
}

func TestPerfMemoryLargeBufBounds(t *testing.T) {
	const maxPerClass = 4
	p := largeBufPool{maxPerClass: maxPerClass}
	p.put(make([]byte, 0, 1<<17-1))
	p.put(make([]byte, 0, 1<<22+1))
	p.put(make([]byte, 0, 1<<20+8<<10))
	for class := range largeBufClassCount {
		if n := len(p.classes[class]); n != 0 {
			t.Fatalf("out-of-range or foreign-sized buffer pooled in class %d", class)
		}
	}
	class := largeBufClassAtLeast(1 << 22)
	held := make([][]byte, 0, maxPerClass+2)
	for range maxPerClass + 2 {
		b := make([]byte, 0, 1<<22)
		held = append(held, b)
		p.put(b)
	}
	if n := len(p.classes[class]); n != maxPerClass {
		t.Fatalf("class holds %d entries, want the cap %d", n, maxPerClass)
	}
	if b := p.get(5 << 20); cap(b) != 5<<20 {
		t.Fatalf("oversize get returned cap %d", cap(b))
	}
	runtime.KeepAlive(held)
}

func TestPerfMemoryLargeBufFullClassDropsCollectedEntries(t *testing.T) {
	const maxPerClass = 2
	p := largeBufPool{maxPerClass: maxPerClass}
	class := largeBufClassAtLeast(1 << 18)
	for range maxPerClass {
		p.put(make([]byte, 0, largeBufClassSize(class)))
	}
	runtime.GC()
	runtime.GC()
	keep := make([]byte, 0, largeBufClassSize(class))
	p.put(keep)
	if n := len(p.classes[class]); n != 1 {
		t.Fatalf("full class kept %d entries after its collected ones were dropped, want 1", n)
	}
	if got := p.get(1 << 18); unsafe.SliceData(got) != unsafe.SliceData(keep) {
		t.Fatal("live buffer not served after pruning")
	}
}

func TestPerfMemoryGrowAndAppendPooledKeepContent(t *testing.T) {
	head := bytes.Repeat([]byte("h"), 100)
	body := bytes.Repeat([]byte("b"), 1<<20)
	grown := growIOBuf(append([]byte(nil), head...), len(body))
	if !bytes.Equal(grown, head) || cap(grown) < len(head)+len(body) {
		t.Fatalf("growIOBuf len %d cap %d", len(grown), cap(grown))
	}
	small := make([]byte, 3, 64)
	if got := growIOBuf(small, 10); unsafe.SliceData(got) != unsafe.SliceData(small) {
		t.Fatal("growIOBuf replaced a buffer that already fits")
	}
	self := append(make([]byte, 0, 4096), "abc"...)
	big := bytes.Repeat([]byte("x"), 200<<10)
	out := appendPooled(self[:0], big)
	if !bytes.Equal(out, big) {
		t.Fatal("appendPooled lost content")
	}
	aliased := appendPooled(out[:0], out)
	if !bytes.Equal(aliased, big) {
		t.Fatal("appendPooled corrupted a self-copy")
	}
	if recycled := recycleBodyBuf(aliased); recycled != nil {
		t.Fatal("large body buffer kept after recycle")
	}
	keep := make([]byte, 10, 4096)
	if got := recycleBodyBuf(keep); unsafe.SliceData(got) != unsafe.SliceData(keep) || len(got) != 0 {
		t.Fatal("small body buffer not kept for reuse")
	}
}

func TestPerfMemoryLargeBufZeroAllocsSteadyState(t *testing.T) {
	p := largeBufPool{maxPerClass: largeBufMaxPerClass}
	b := p.get(1 << 20)
	p.put(b)
	allocs := testing.AllocsPerRun(100, func() {
		p.put(p.get(1 << 20))
	})
	if allocs != 0 {
		t.Fatalf("large pool round trip allocates %.1f per op", allocs)
	}
	runtime.KeepAlive(b)
}

func BenchmarkPerfMemoryLargeWriteBuf(b *testing.B) {
	const bodySize = 1 << 20
	body := bytes.Repeat([]byte("b"), bodySize)
	head := bytes.Repeat([]byte("h"), 160)
	b.Run("current_append_growth_then_drop", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(bodySize)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := acquireIOBuf()
				buf = append(buf, head...)
				buf = append(buf, body...)
				releasePooledBuf(&epollIOBufPool, buf, epollIOBufPoolMaxCap)
			}
		})
	})
	b.Run("pooled_grow_then_release", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(bodySize)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := acquireIOBuf()
				buf = append(buf, head...)
				buf = append(growIOBuf(buf, len(body)), body...)
				releaseIOBuf(buf)
			}
		})
	})
}
