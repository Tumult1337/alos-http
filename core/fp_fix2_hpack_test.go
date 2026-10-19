//go:build linux && amd64

package core

import "testing"

const (
	fpFix2NewestDynIndex  = 62
	fpFix2DecoderListSize = 1 << 16
	fpFix2HpackTableSize  = 4096
)

func fpFix2Block(build func(e *hpackEncoder)) []byte {
	e := &hpackEncoder{}
	build(e)
	return e.buf
}

func fpFix2IndexedLiteral(name, value string) []byte {
	return fpFix2Block(func(e *hpackEncoder) {
		e.buf = append(e.buf, 0x40)
		e.appendString(name)
		e.appendString(value)
	})
}

func fpFix2NameRefLiteral(value string) []byte {
	return fpFix2Block(func(e *hpackEncoder) {
		e.encodeInt(0x00, 4, fpFix2NewestDynIndex)
		e.appendString(value)
	})
}

func fpFix2FullRef() []byte {
	return fpFix2Block(func(e *hpackEncoder) { e.encodeInt(0x80, 7, fpFix2NewestDynIndex) })
}

func TestFPFix2HpackNameRefInheritsOnlyNameValidity(t *testing.T) {
	var d hpackDecoder
	d.init(fpFix2HpackTableSize, fpFix2DecoderListSize)
	for _, step := range []struct {
		name      string
		block     []byte
		malformed bool
	}{
		{"literal with an illegal value is indexed", fpFix2IndexedLiteral("x-trace", "abc "), true},
		{"name-only reference with a legal value", fpFix2NameRefLiteral("abc"), false},
		{"name-only reference with an illegal value", fpFix2NameRefLiteral(" abc"), true},
		{"full reference to the illegal-value entry", fpFix2FullRef(), true},
		{"literal with an illegal name is indexed", fpFix2IndexedLiteral("X-Bad", "v"), true},
		{"name-only reference to the illegal name", fpFix2NameRefLiteral("ok"), true},
		{"full reference to the illegal-name entry", fpFix2FullRef(), true},
		{"legal literal is indexed", fpFix2IndexedLiteral("x-ok", "v"), false},
		{"full reference to the legal entry", fpFix2FullRef(), false},
	} {
		out, malformed, err := d.decode(step.block, nil)
		if err != nil || malformed != step.malformed || len(out) != 1 {
			t.Errorf("%s: malformed=%v err=%v fields=%q, want malformed=%v", step.name, malformed, err, out, step.malformed)
		}
	}
}
