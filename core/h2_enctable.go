//go:build linux && amd64

package core

import "strings"

const (
	h2EncTableMaxSize    = 4096
	h2EncIndexMaxValue   = 128
	hpackDynamicIndexMin = len(HpackStaticTable)
)

type hpackEncEntry struct {
	name  string
	value string
}

type hpackEncTable struct {
	entries       []hpackEncEntry
	size          int
	maxSize       int
	pendingUpdate bool
	gen           uint32
	headMemo      *h2HeadMemo
}

func (t *hpackEncTable) reset() {
	clear(t.entries)
	t.entries = t.entries[:0]
	t.size = 0
	t.maxSize = h2EncTableMaxSize
	t.pendingUpdate = false
	t.gen++
}

func (t *hpackEncTable) setPeerLimit(limit uint32) {
	newMax := int(min(limit, h2EncTableMaxSize))
	if newMax == t.maxSize {
		return
	}
	t.maxSize = newMax
	t.evictTo(newMax)
	t.pendingUpdate = true
	t.gen++
}

func (t *hpackEncTable) evictTo(limit int) {
	drop := 0
	for t.size > limit && drop < len(t.entries) {
		t.size -= hpackEncEntrySize(t.entries[drop].name, t.entries[drop].value)
		drop++
	}
	if drop == 0 {
		return
	}
	t.gen++
	n := copy(t.entries, t.entries[drop:])
	clear(t.entries[n:])
	t.entries = t.entries[:n]
}

func hpackEncEntrySize(name, value string) int {
	return len(name) + len(value) + hpackEntryOverhead
}

func (t *hpackEncTable) find(name, value string) int {
	for i := len(t.entries) - 1; i >= 0; i-- {
		if e := &t.entries[i]; e.value == value && e.name == name {
			return hpackDynamicIndexMin + len(t.entries) - 1 - i
		}
	}
	return 0
}

func (t *hpackEncTable) add(name, value string) {
	size := hpackEncEntrySize(name, value)
	if size > t.maxSize {
		t.evictTo(0)
		return
	}
	t.evictTo(t.maxSize - size)
	t.entries = append(t.entries, hpackEncEntry{name: strings.Clone(name), value: strings.Clone(value)})
	t.size += size
	t.gen++
}

func (t *hpackEncTable) beginBlock(enc *HpackEncoder) {
	if t.pendingUpdate {
		enc.EncodeInt(0x20, 5, uint64(t.maxSize))
		t.pendingUpdate = false
	}
}

func (t *hpackEncTable) encodeField(enc *HpackEncoder, staticNameIdx int, lowerName, value string) {
	if idx := t.find(lowerName, value); idx > 0 {
		enc.EncodeIndexed(uint64(idx))
		return
	}
	if len(value) > h2EncIndexMaxValue || hpackEncEntrySize(lowerName, value) > t.maxSize {
		if staticNameIdx > 0 {
			enc.encodeStaticFieldCached(staticNameIdx, value)
			return
		}
		enc.Buf = append(enc.Buf, 0x00)
		enc.EncodeString(lowerName)
		enc.EncodeString(value)
		return
	}
	if staticNameIdx > 0 {
		enc.EncodeInt(0x40, 6, uint64(staticNameIdx))
	} else {
		enc.Buf = append(enc.Buf, 0x40)
		enc.EncodeString(lowerName)
	}
	enc.EncodeString(value)
	t.add(lowerName, value)
}

func h2IndexableResponseField(name string) (string, bool) {
	switch len(name) {
	case 4:
		if EqualFoldASCII(name, "vary") {
			return "vary", true
		}
	case 7:
		if EqualFoldASCII(name, "alt-svc") {
			return "alt-svc", true
		}
	case 13:
		if EqualFoldASCII(name, "cache-control") {
			return "cache-control", true
		}
	case 15:
		if EqualFoldASCII(name, "x-frame-options") {
			return "x-frame-options", true
		}
	case 16:
		if EqualFoldASCII(name, "content-encoding") {
			return "content-encoding", true
		}
	case 22:
		if EqualFoldASCII(name, "x-content-type-options") {
			return "x-content-type-options", true
		}
	case 25:
		if EqualFoldASCII(name, "strict-transport-security") {
			return "strict-transport-security", true
		}
	case 27:
		if EqualFoldASCII(name, "access-control-allow-origin") {
			return "access-control-allow-origin", true
		}
	case 29:
		if EqualFoldASCII(name, "access-control-expose-headers") {
			return "access-control-expose-headers", true
		}
	case 32:
		if EqualFoldASCII(name, "access-control-allow-credentials") {
			return "access-control-allow-credentials", true
		}
	}
	return "", false
}
