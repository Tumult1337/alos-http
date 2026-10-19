//go:build linux && amd64

package core

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

type h1ScanVariant struct {
	name string
	scan func([]byte) (int, bool)
}

var h1ScanArchVariants []h1ScanVariant

func h1ScanVariants() []h1ScanVariant {
	v := []h1ScanVariant{
		{"Ref", scanH1LineRef},
		{"SWAR", scanH1LineSWAR},
		{"Dispatch", func(p []byte) (int, bool) { return classifyFirstSpecial(p, firstH1Special(p)) }},
	}
	return append(v, h1ScanArchVariants...)
}

func TestScanH1LineVariants(t *testing.T) {
	long := bytes.Repeat([]byte("a"), 100)
	at := func(prefix int, tail string) string { return string(long[:prefix]) + tail }
	cases := []struct {
		name string
		in   string
		end  int
		bad  bool
	}{
		{"empty", "", -1, false},
		{"no terminator", "abc", -1, false},
		{"trailing CR waits", "abc\r", -1, false},
		{"crlf", "abc\r\n", 3, false},
		{"empty line", "\r\n", 0, false},
		{"tab allowed", "a\tb\r\n", 3, false},
		{"obs-text allowed", "a\x80\xff\r\n", 3, false},
		{"bare LF", "ab\ncd\r\n", 2, true},
		{"lone CR", "ab\rcd\r\n", 2, true},
		{"NUL", "a\x00\r\n", 1, true},
		{"DEL", "a\x7f\r\n", 1, true},
		{"unit separator", "a\x1f\r\n", 1, true},
		{"space is fine", "a b\r\n", 3, false},
		{"bytes after terminator ignored", "abc\r\n\x00", 3, false},
		{"crlf at 31", at(31, "\r\n"), 31, false},
		{"cr at 31 lf at 32", at(31, "\r\n") + string(long), 31, false},
		{"crlf at 32", at(32, "\r\n"), 32, false},
		{"crlf at 63", at(63, "\r\n"), 63, false},
		{"crlf at 95", at(95, "\r\n") + string(long), 95, false},
		{"bad at 33 in long line", at(33, "\x01") + string(long) + "\r\n", 33, true},
		{"tab then bad", at(40, "\t\t\x02") + string(long), 42, true},
		{"many tabs then crlf", at(5, strings.Repeat("\t", 35)) + "\r\n", 40, false},
		{"lone CR at end of 40 bytes", at(39, "\r"), -1, false},
		{"lone CR at 39 then x", at(39, "\rx"), 39, true},
		{"no special 33 bytes", at(33, ""), -1, false},
		{"no special 100 bytes", string(long), -1, false},
		{"del at 99", at(99, "\x7f"), 99, true},
		{"bad only in overlap tail", at(70, "\x05"), 70, true},
	}
	for _, v := range h1ScanVariants() {
		for _, c := range cases {
			end, bad := v.scan([]byte(c.in))
			if end != c.end || bad != c.bad {
				t.Errorf("%s/%s: got (%d, %v), want (%d, %v)", v.name, c.name, end, bad, c.end, c.bad)
			}
		}
	}
}

func TestScanH1LineVariantsAgreeOnEveryByte(t *testing.T) {
	for n := 1; n <= 80; n++ {
		for pos := 0; pos < n; pos++ {
			for c := 0; c < 256; c++ {
				buf := bytes.Repeat([]byte("x"), n)
				buf[pos] = byte(c)
				wantEnd, wantBad := scanH1LineRef(buf)
				for _, v := range h1ScanVariants() {
					if end, bad := v.scan(buf); end != wantEnd || bad != wantBad {
						t.Fatalf("%s: n=%d pos=%d byte=%#02x got (%d, %v), want (%d, %v)", v.name, n, pos, c, end, bad, wantEnd, wantBad)
					}
				}
			}
		}
	}
}

func FuzzScanH1LineDifferential(f *testing.F) {
	for _, s := range []string{"", "GET / HTTP/1.1\r\n", "a\tb\r\n", "\r", "x\n", "\x7f", "\xff\xfe\r\n"} {
		f.Add([]byte(s))
	}
	f.Add(append(bytes.Repeat([]byte("a"), 31), '\r', '\n'))
	f.Add(append(bytes.Repeat([]byte("a"), 7), '\r', '\n'))
	f.Add(append(bytes.Repeat([]byte("\t"), 64), '\r'))
	f.Fuzz(func(t *testing.T, data []byte) {
		wantEnd, wantBad := scanH1LineRef(data)
		for _, v := range h1ScanVariants() {
			if end, bad := v.scan(data); end != wantEnd || bad != wantBad {
				t.Fatalf("%s(%q) = (%d, %v), Ref = (%d, %v)", v.name, data, end, bad, wantEnd, wantBad)
			}
		}
	})
}

func BenchmarkScanH1Line(b *testing.B) {
	for _, n := range []int{16, 64, 512} {
		line := append(bytes.Repeat([]byte("a"), n-2), '\r', '\n')
		for _, v := range h1ScanVariants() {
			if v.name == "Dispatch" {
				continue
			}
			b.Run(v.name+"_"+strconv.Itoa(n), func(b *testing.B) {
				b.SetBytes(int64(n))
				for b.Loop() {
					v.scan(line)
				}
			})
		}
	}
}

type h1HeaderVariant struct {
	name string
	scan func([]byte) (int, int)
}

var h1HeaderArchVariants []h1HeaderVariant

func h1HeaderVariants() []h1HeaderVariant {
	v := []h1HeaderVariant{
		{"Ref", h1HeaderLineRef},
		{"SWAR", h1HeaderLineSWAR},
		{"Scalar", func(p []byte) (int, int) {
			special, nameEnd, _ := h1HeaderLineScalar(p)
			return special, nameEnd
		}},
		{"Scan", func(p []byte) (int, int) {
			special, nameEnd, _ := h1HeaderLineScan(p)
			return special, nameEnd
		}},
	}
	return append(v, h1HeaderArchVariants...)
}

func TestH1HeaderLineVariantsAgreeOnEveryByte(t *testing.T) {
	for n := 1; n <= 80; n++ {
		for pos := 0; pos < n; pos++ {
			for c := 0; c < 256; c++ {
				buf := bytes.Repeat([]byte("x"), n)
				buf[pos] = byte(c)
				wantSpecial, wantName := h1HeaderLineRef(buf)
				for _, v := range h1HeaderVariants() {
					if special, name := v.scan(buf); special != wantSpecial || name != wantName {
						t.Fatalf("%s: n=%d pos=%d byte=%#02x got (%d, %d), want (%d, %d)", v.name, n, pos, c, special, name, wantSpecial, wantName)
					}
				}
			}
		}
	}
}

func TestH1HeaderLineVariantsOnRealLines(t *testing.T) {
	lines := []string{
		"Host: example.com\r\n",
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36\r\n",
		"Accept-Language: en-US,en;q=0.9\r\n",
		"X-Very-Long-Header-Name-That-Spans-More-Than-Thirty-Two-Bytes: v\r\n",
		"X Y: 1\r\n",
		"NoColon\r\n",
		": empty\r\n",
		"Cookie: a=b; c=d\x01\r\n",
		"X-A: a\nb\r\n",
		"X-Tab:\tv\t\r\n",
	}
	for _, l := range lines {
		wantSpecial, wantName := h1HeaderLineRef([]byte(l))
		for _, v := range h1HeaderVariants() {
			if special, name := v.scan([]byte(l)); special != wantSpecial || name != wantName {
				t.Errorf("%s(%q) = (%d, %d), want (%d, %d)", v.name, l, special, name, wantSpecial, wantName)
			}
		}
		special, nameEnd := h1HeaderLineSpecials([]byte(l))
		if special != wantSpecial || nameEnd != wantName {
			t.Errorf("h1HeaderLineSpecials(%q) = (%d, %d), want (%d, %d)", l, special, nameEnd, wantSpecial, wantName)
		}
	}
}

func TestH1TokenTableMatchesRFC9110(t *testing.T) {
	const tchar = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	for c := 0; c < 256; c++ {
		want := strings.IndexByte(tchar, byte(c)) >= 0
		if h1TokenChar[c] != want {
			t.Errorf("h1TokenChar[%#02x] = %v, want %v", c, h1TokenChar[c], want)
		}
		if got := firstNonTokenByte([]byte{byte(c)}) < 0; got != want {
			t.Errorf("firstNonTokenByte(%#02x) treats it as token=%v, want %v", c, got, want)
		}
	}
}

func FuzzH1HeaderLineDifferential(f *testing.F) {
	for _, s := range []string{"Host: a\r\n", "X Y: 1\r\n", "abc", "", "\x00", "a:b\x7f"} {
		f.Add([]byte(s))
	}
	f.Add(append(bytes.Repeat([]byte("N"), 40), ':', ' ', 'v', '\r', '\n'))
	f.Fuzz(func(t *testing.T, data []byte) {
		wantSpecial, wantName := h1HeaderLineRef(data)
		for _, v := range h1HeaderVariants() {
			if special, name := v.scan(data); special != wantSpecial || name != wantName {
				t.Fatalf("%s(%q) = (%d, %d), Ref = (%d, %d)", v.name, data, special, name, wantSpecial, wantName)
			}
		}
	})
}

func BenchmarkH1HeaderLine(b *testing.B) {
	for _, n := range []int{24, 64, 512} {
		line := append([]byte("X-Header-Name: "), bytes.Repeat([]byte("v"), n-17)...)
		line = append(line, '\r', '\n')
		for _, v := range h1HeaderVariants() {
			b.Run(v.name+"_"+strconv.Itoa(n), func(b *testing.B) {
				b.SetBytes(int64(len(line)))
				for b.Loop() {
					v.scan(line)
				}
			})
		}
	}
}

var h1ScanBrowserHead = "GET /dashboard/shop?tab=orders&page=2 HTTP/1.1\r\n" +
	"Host: shop.example.com\r\n" +
	"Connection: keep-alive\r\n" +
	"sec-ch-ua: \"Chromium\";v=\"124\", \"Not-A.Brand\";v=\"99\"\r\n" +
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36\r\n" +
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" +
	"Accept-Encoding: gzip, deflate, br\r\n" +
	"Accept-Language: en-US,en;q=0.9\r\n" +
	"Cookie: session=abc123; theme=dark; _ga=GA1.2.3.4\r\n" +
	"\r\n"

type h1WalkStep struct{ special, nameEnd int }

func walkH1Lines(data []byte, start int, scan func(data []byte, pos int) (int, int)) []h1WalkStep {
	var steps []h1WalkStep
	for pos := start; pos < len(data); {
		special, nameEnd := scan(data, pos)
		steps = append(steps, h1WalkStep{special, nameEnd})
		end, bad := classifyFirstSpecial(data[pos:], special)
		if bad || end <= 0 {
			break
		}
		pos += end + 2
	}
	return steps
}

func refH1Walk(data []byte, start int) []h1WalkStep {
	return walkH1Lines(data, start, func(d []byte, pos int) (int, int) { return h1HeaderLineRef(d[pos:]) })
}

func dispatchH1Walk(data []byte, start int) []h1WalkStep {
	return walkH1Lines(data, start, func(d []byte, pos int) (int, int) { return h1HeaderLineSpecials(d[pos:]) })
}

func equalWalks(a, b []h1WalkStep) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestH1HeaderLineDispatchMatchesReferenceWalk(t *testing.T) {
	base := h1ScanBrowserHead
	var many strings.Builder
	many.WriteString("GET / HTTP/1.1\r\n")
	for i := range 40 {
		fmt.Fprintf(&many, "X-H%02d: value-%d\r\n", i, i)
	}
	many.WriteString("\r\n")
	blocks := []string{
		base,
		many.String(),
		"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-Pad: 0123456789012345678901234567890123456789\r\nY: z\r\n\r\nBODY",
		"GET / HTTP/1.1\r\nHost: a\r\nX: " + strings.Repeat("v", 200) + "\r\n\r\n",
	}
	mutations := []byte{0x00, '\t', '\r', '\n', ':', ' ', 0x7f, 0x80, 'a', '(', 0xff}
	for bi, block := range blocks {
		data := []byte(block)
		start := bytes.Index(data, []byte("\r\n")) + 2
		if want, got := refH1Walk(data, start), dispatchH1Walk(data, start); !equalWalks(want, got) {
			t.Fatalf("block %d: dispatch walk %v, want %v", bi, got, want)
		}
		for cut := start; cut <= len(data); cut++ {
			if want, got := refH1Walk(data[:cut], start), dispatchH1Walk(data[:cut], start); !equalWalks(want, got) {
				t.Fatalf("block %d cut %d: dispatch walk %v, want %v", bi, cut, got, want)
			}
		}
		for i := start; i < len(data); i++ {
			for _, m := range mutations {
				mutated := append([]byte(nil), data...)
				mutated[i] = m
				if want, got := refH1Walk(mutated, start), dispatchH1Walk(mutated, start); !equalWalks(want, got) {
					t.Fatalf("block %d byte %d=%#02x: dispatch walk %v, want %v", bi, i, m, got, want)
				}
			}
		}
	}
}

func FuzzH1HeaderWalkDifferential(f *testing.F) {
	f.Add([]byte(h1ScanBrowserHead))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	f.Add([]byte("Host: a\r\nX Y: 1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if want, got := refH1Walk(data, 0), dispatchH1Walk(data, 0); !equalWalks(want, got) {
			t.Fatalf("dispatch walk %v, want %v for %q", got, want, data)
		}
	})
}

func hostSafeRef(p []byte, special, nameEnd int) bool {
	if special < 0 || nameEnd < 0 || p[nameEnd] != ':' {
		return false
	}
	return ValidateHost(UnsafeString(trimOWS(p[nameEnd+1 : special])))
}

func checkHostSafe(t *testing.T, p []byte) {
	t.Helper()
	special, nameEnd, hostSafe := h1HeaderLineScan(p)
	if hostSafe && !hostSafeRef(p, special, nameEnd) {
		t.Fatalf("%q: hostSafe reported for a value ValidateHost rejects", p)
	}
	if len(p) < h1ScalarScanMax && hostSafeRef(p, special, nameEnd) && !hostSafe {
		if v := p[nameEnd+1 : special]; len(trimOWS(v)) == len(v)-leadingOWS(v) {
			t.Fatalf("%q: scalar scan missed a host-safe value", p)
		}
	}
}

func leadingOWS(v []byte) int {
	n := 0
	for n < len(v) && (v[n] == ' ' || v[n] == '\t') {
		n++
	}
	return n
}

func TestH1HeaderLineHostSafeOnEveryByte(t *testing.T) {
	for _, tmpl := range []string{"Host: ab.c:80\r\n", "host:\t[::1] \r\n", "Host:\r\n", "Host: a%2Fb~\r\n", "X: abcdefghijklmnopqrstuvwxyz\r\n"} {
		for pos := 0; pos < len(tmpl); pos++ {
			buf := []byte(tmpl)
			for c := 0; c < 256; c++ {
				buf[pos] = byte(c)
				checkHostSafe(t, buf)
			}
		}
	}
}

func FuzzH1HeaderLineHostSafe(f *testing.F) {
	f.Add([]byte("Host: a.b:1\r\n"))
	f.Add([]byte("Host: a b\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		checkHostSafe(t, data)
	})
}
