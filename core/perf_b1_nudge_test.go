//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestB1NudgeFiresOnlyWhenLargeTrafficStops(t *testing.T) {
	var n largeBufNudge
	total := uint64(0)
	step := func(recent uint64) bool {
		total += recent
		return n.observe(total)
	}
	for i := range 20 {
		if step(500 << 20) {
			t.Fatalf("tick %d: steady large-body traffic reported quiet", i)
		}
	}
	if step(400 << 20) {
		t.Fatal("a 20% dip reported quiet")
	}
	if !step(1 << 20) {
		t.Fatal("traffic falling to 1/500 of its peak not reported quiet")
	}
	if !step(0) {
		t.Fatal("quiet must persist until settled")
	}
	n.settle()
	for i := range 5 {
		if step(0) {
			t.Fatalf("tick %d: settled nudge fired again with no traffic", i)
		}
	}
	for i := range 5 {
		if step(64 << 10) {
			t.Fatalf("tick %d: low steady traffic after settling reported quiet", i)
		}
	}
}

func TestB1NudgeIgnoresStartupTotal(t *testing.T) {
	var n largeBufNudge
	if n.observe(10 << 30) {
		t.Fatal("first observation reported quiet")
	}
	if !n.observe(10 << 30) {
		t.Fatal("no traffic after the first observation not reported quiet")
	}
}

func TestB1LargeBufGetCountsBytes(t *testing.T) {
	p := largeBufPool{maxPerClass: largeBufMaxPerClass}
	before := p.getBytes.Load()
	p.put(p.get(64 << 10))
	p.get(1 << 20)
	if got := p.getBytes.Load() - before; got != 64<<10+1<<20 {
		t.Fatalf("getBytes advanced by %d", got)
	}
}

func TestB1SentBodyReleaseKeepsSmallAndTextBodies(t *testing.T) {
	var r Response
	r.Bytes(bytes.Repeat([]byte{'s'}, 1000))
	small := unsafe.SliceData(r.body)
	r.releaseSentBody()
	if unsafe.SliceData(r.body) != small || len(r.body) != 1000 {
		t.Fatal("a small owned body must not be released")
	}
	r.Bytes(bytes.Repeat([]byte{'b'}, 64<<10))
	if cap(r.body) != largeBufClassSize(largeBufClassAtLeast(64<<10)) {
		t.Fatalf("64 KiB body capacity %d is not a pooled class", cap(r.body))
	}
	r.releaseSentBody()
	if cap(r.body) != 0 {
		t.Fatalf("sent 64 KiB body still held, capacity %d", cap(r.body))
	}
	shared := bytes.Repeat([]byte{'n'}, 64<<10)
	r.BytesNoCopy(shared)
	r.releaseSentBody()
	if got := r.bodyBytesUnsafe(); unsafe.SliceData(got) != unsafe.SliceData(shared) || len(got) != len(shared) {
		t.Fatal("releasing must never touch a no-copy body")
	}
}

func TestB1NudgeRetriesAreBounded(t *testing.T) {
	var n largeBufNudge
	n.observe(100 << 20)
	if !n.observe(100 << 20) {
		t.Fatal("quiet not reported")
	}
	for i := 1; i < largeNudgeTries; i++ {
		n.retry()
		if !n.retrying() || !n.observe(100<<20) {
			t.Fatalf("retry %d: nudge stopped before its retry budget", i)
		}
	}
	n.retry()
	if n.retrying() || n.observe(100<<20) {
		t.Fatal("nudge kept firing after its retry budget")
	}
}

func TestB1MidSizeBuffersPoolStronglyWithinBudget(t *testing.T) {
	p := largeBufPool{maxPerClass: largeBufMaxPerClass}
	class := largeBufClassAtLeast(64 << 10)
	size := largeBufClassSize(class)
	want := largeBufStrongBudget / size
	held := make([][]byte, 0, want+2)
	for range want + 2 {
		b := make([]byte, 0, size)
		held = append(held, b)
		if !p.put(b) {
			t.Fatal("class-sized buffer refused")
		}
	}
	if len(p.strong[class]) != want || p.strongBytes != want*size {
		t.Fatalf("strong stash holds %d buffers (%d bytes), want %d within the %d byte budget", len(p.strong[class]), p.strongBytes, want, largeBufStrongBudget)
	}
	if len(p.classes[class]) != 2 {
		t.Fatalf("over-budget buffers: %d weak entries, want 2", len(p.classes[class]))
	}
	if b := p.get(64 << 10); unsafe.SliceData(b) != unsafe.SliceData(held[len(held)-1]) {
		t.Fatal("the most recently released buffer is not served first")
	}
	for range want + 1 {
		p.get(64 << 10)
	}
	if p.strongBytes != 0 || len(p.strong[class]) != 0 {
		t.Fatalf("strong stash not drained: %d bytes", p.strongBytes)
	}
	if big := p.put(make([]byte, 0, largeBufClassSize(largeBufClassAtLeast(1<<20)))); !big || p.strongBytes != 0 {
		t.Fatal("buffers above the strong cap must stay weakly pooled")
	}
}

func TestB1LargeBufClassLookupMatchesLinearScan(t *testing.T) {
	atLeast := func(n int) int {
		for class := range largeBufClassCount {
			if largeBufClassSize(class) >= n {
				return class
			}
		}
		return -1
	}
	atMost := func(n int) int {
		for class := largeBufClassCount - 1; class >= 0; class-- {
			if largeBufClassSize(class) <= n {
				return class
			}
		}
		return -1
	}
	check := func(n int) {
		if got, want := largeBufClassAtLeast(n), atLeast(n); got != want {
			t.Fatalf("AtLeast(%d) = %d, want %d", n, got, want)
		}
		if got, want := largeBufClassAtMost(n), atMost(n); got != want {
			t.Fatalf("AtMost(%d) = %d, want %d", n, got, want)
		}
	}
	for n := 0; n <= 1<<largeBufMinShift+2; n++ {
		check(n)
	}
	for class := range largeBufClassCount {
		size := largeBufClassSize(class)
		for d := -2; d <= 2; d++ {
			check(size + d)
		}
	}
	for n := 1 << largeBufMinShift; n <= 1<<largeBufMaxShift+1<<12; n += 4093 {
		check(n)
	}
}
