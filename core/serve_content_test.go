//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const serveContentSize = 10000

var serveContentModTime = time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC)

func serveContentPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31%251 + 1)
	}
	return b
}

func writeServeContentFile(t testing.TB, dir string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, "content.bin")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, serveContentModTime, serveContentModTime); err != nil {
		t.Fatal(err)
	}
	return path
}

func expectedETag(fi os.FileInfo) string {
	return `"` + strconv.FormatUint(uint64(fi.ModTime().UnixNano()), 16) + "-" + strconv.FormatUint(uint64(fi.Size()), 16) + `"`
}

func serveContentDo(t testing.TB, path, method string, headers ...string) *Response {
	t.Helper()
	req := &Request{Method: method}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Headers = append(req.Headers, [2]string{headers[i], headers[i+1]})
	}
	resp := &Response{lazyReq: req}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.serveContent(req, f, fi, "application/octet-stream", nil); err != nil {
		t.Fatalf("serveContent: %v", err)
	}
	return resp
}

type serveContentFixture struct {
	path         string
	content      []byte
	etag         string
	lastModified string
}

func newServeContentFixture(t testing.TB) serveContentFixture {
	t.Helper()
	content := serveContentPattern(serveContentSize)
	path := writeServeContentFile(t, t.TempDir(), content)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return serveContentFixture{
		path:         path,
		content:      content,
		etag:         expectedETag(fi),
		lastModified: fi.ModTime().UTC().Format(http.TimeFormat),
	}
}

func TestServeContentPlainGET(t *testing.T) {
	fx := newServeContentFixture(t)
	resp := serveContentDo(t, fx.path, "GET")
	if resp.StatusCode != 200 || !bytes.Equal(resp.GetBody(), fx.content) {
		t.Fatalf("status %d, body %d bytes", resp.StatusCode, len(resp.GetBody()))
	}
	want := map[string]string{"Accept-Ranges": "bytes", "ETag": fx.etag, "Last-Modified": fx.lastModified}
	for name, value := range want {
		if got, _ := respHeader(resp, name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
	if _, has := respHeader(resp, "Content-Range"); has {
		t.Error("200 carries Content-Range")
	}
	if !strings.HasPrefix(fx.etag, `"`) || strings.HasPrefix(fx.etag, "W/") {
		t.Fatalf("ETag %q is not a strong tag", fx.etag)
	}
}

func TestServeContentConditionals(t *testing.T) {
	fx := newServeContentFixture(t)
	opaque := strings.Trim(fx.etag, `"`)
	earlier := serveContentModTime.Add(-time.Second).UTC().Format(http.TimeFormat)
	later := serveContentModTime.Add(time.Hour).UTC().Format(http.TimeFormat)
	cases := []struct {
		name    string
		method  string
		headers []string
		status  int
	}{
		{"inm exact", "GET", []string{"If-None-Match", fx.etag}, 304},
		{"inm list with weak first", "GET", []string{"If-None-Match", `W/"x", ` + fx.etag}, 304},
		{"inm weak form of our tag", "GET", []string{"If-None-Match", `W/"` + opaque + `"`}, 304},
		{"inm star", "GET", []string{"If-None-Match", "*"}, 304},
		{"inm other", "GET", []string{"If-None-Match", `"other"`}, 200},
		{"inm second header line", "GET", []string{"If-None-Match", `"a"`, "If-None-Match", fx.etag}, 304},
		{"inm malformed", "GET", []string{"If-None-Match", opaque}, 200},
		{"inm unterminated", "GET", []string{"If-None-Match", `"` + opaque}, 200},
		{"inm on HEAD", "HEAD", []string{"If-None-Match", fx.etag}, 304},
		{"inm on POST", "POST", []string{"If-None-Match", fx.etag}, 412},
		{"inm star on PUT", "PUT", []string{"If-None-Match", "*"}, 412},
		{"ims equal", "GET", []string{"If-Modified-Since", fx.lastModified}, 304},
		{"ims later", "GET", []string{"If-Modified-Since", later}, 304},
		{"ims earlier", "GET", []string{"If-Modified-Since", earlier}, 200},
		{"ims invalid", "GET", []string{"If-Modified-Since", "yesterday"}, 200},
		{"ims ignored on POST", "POST", []string{"If-Modified-Since", fx.lastModified}, 200},
		{"ims ignored when inm present", "GET", []string{"If-None-Match", `"other"`, "If-Modified-Since", fx.lastModified}, 200},
		{"ims rfc850 form", "GET", []string{"If-Modified-Since", serveContentModTime.Format(time.RFC850)}, 304},
		{"ims asctime form", "GET", []string{"If-Modified-Since", serveContentModTime.Format(time.ANSIC)}, 304},
		{"im match", "GET", []string{"If-Match", fx.etag}, 200},
		{"im list match", "GET", []string{"If-Match", `"a", ` + fx.etag}, 200},
		{"im star", "GET", []string{"If-Match", "*"}, 200},
		{"im mismatch", "GET", []string{"If-Match", `"other"`}, 412},
		{"im weak is never strong", "GET", []string{"If-Match", `W/` + fx.etag}, 412},
		{"im mismatch on PUT", "PUT", []string{"If-Match", `"other"`}, 412},
		{"ius earlier", "GET", []string{"If-Unmodified-Since", earlier}, 412},
		{"ius equal", "GET", []string{"If-Unmodified-Since", fx.lastModified}, 200},
		{"ius invalid", "GET", []string{"If-Unmodified-Since", "nope"}, 200},
		{"ius ignored when im present", "GET", []string{"If-Match", fx.etag, "If-Unmodified-Since", earlier}, 200},
		{"im fails before inm", "GET", []string{"If-Match", `"other"`, "If-None-Match", fx.etag}, 412},
		{"star must stand alone", "GET", []string{"If-None-Match", "*x"}, 200},
	}
	for _, tc := range cases {
		resp := serveContentDo(t, fx.path, tc.method, tc.headers...)
		if resp.StatusCode != tc.status {
			t.Errorf("%s: status %d, want %d", tc.name, resp.StatusCode, tc.status)
			continue
		}
		if tc.status == 304 {
			if len(resp.GetBody()) != 0 || resp.ContentType != "" {
				t.Errorf("%s: 304 carries body %d / content-type %q", tc.name, len(resp.GetBody()), resp.ContentType)
			}
			if got, _ := respHeader(resp, "ETag"); got != fx.etag {
				t.Errorf("%s: 304 ETag %q", tc.name, got)
			}
			if got, _ := respHeader(resp, "Last-Modified"); got != fx.lastModified {
				t.Errorf("%s: 304 Last-Modified %q", tc.name, got)
			}
			if cl := resp.headerContentLength(); cl != -1 {
				t.Errorf("%s: 304 would send Content-Length %d", tc.name, cl)
			}
		}
	}
}

func TestServeContentLastModifiedRoundTrips(t *testing.T) {
	fx := newServeContentFixture(t)
	first := serveContentDo(t, fx.path, "GET")
	lm, _ := respHeader(first, "Last-Modified")
	etag, _ := respHeader(first, "ETag")
	if resp := serveContentDo(t, fx.path, "GET", "If-Modified-Since", lm); resp.StatusCode != 304 {
		t.Fatalf("If-Modified-Since round trip = %d", resp.StatusCode)
	}
	if resp := serveContentDo(t, fx.path, "GET", "If-None-Match", etag); resp.StatusCode != 304 {
		t.Fatalf("If-None-Match round trip = %d", resp.StatusCode)
	}
	if resp := serveContentDo(t, fx.path, "GET", "Range", "bytes=0-9", "If-Range", lm); resp.StatusCode != 206 {
		t.Fatalf("If-Range date round trip = %d", resp.StatusCode)
	}
}

func TestServeContentChangedFileInvalidatesValidators(t *testing.T) {
	fx := newServeContentFixture(t)
	if err := os.Chtimes(fx.path, serveContentModTime.Add(2*time.Second), serveContentModTime.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if resp := serveContentDo(t, fx.path, "GET", "If-None-Match", fx.etag); resp.StatusCode != 200 {
		t.Fatalf("stale ETag = %d, want 200", resp.StatusCode)
	}
	if resp := serveContentDo(t, fx.path, "GET", "If-Modified-Since", fx.lastModified); resp.StatusCode != 200 {
		t.Fatalf("stale date = %d, want 200", resp.StatusCode)
	}
}

func TestServeContentRanges(t *testing.T) {
	fx := newServeContentFixture(t)
	size := int64(len(fx.content))
	sizeText := strconv.FormatInt(size, 10)
	cases := []struct {
		name         string
		method       string
		headers      []string
		status       int
		start, end   int64
		contentRange string
	}{
		{"first 100", "GET", []string{"Range", "bytes=0-99"}, 206, 0, 100, "bytes 0-99/" + sizeText},
		{"middle", "GET", []string{"Range", "bytes=1000-1999"}, 206, 1000, 2000, "bytes 1000-1999/" + sizeText},
		{"single byte", "GET", []string{"Range", "bytes=5-5"}, 206, 5, 6, "bytes 5-5/" + sizeText},
		{"last byte", "GET", []string{"Range", "bytes=9999-"}, 206, 9999, size, "bytes 9999-9999/" + sizeText},
		{"open ended", "GET", []string{"Range", "bytes=9000-"}, 206, 9000, size, "bytes 9000-9999/" + sizeText},
		{"suffix 500", "GET", []string{"Range", "bytes=-500"}, 206, size - 500, size, "bytes 9500-9999/" + sizeText},
		{"suffix beyond size", "GET", []string{"Range", "bytes=-99999"}, 206, 0, size, "bytes 0-9999/" + sizeText},
		{"end clamped", "GET", []string{"Range", "bytes=9990-99999"}, 206, 9990, size, "bytes 9990-9999/" + sizeText},
		{"unit case-insensitive", "GET", []string{"Range", "BYTES=0-0"}, 206, 0, 1, "bytes 0-0/" + sizeText},
		{"surrounding whitespace", "GET", []string{"Range", "bytes= 10-19 "}, 206, 10, 20, "bytes 10-19/" + sizeText},
		{"start at size", "GET", []string{"Range", "bytes=" + sizeText + "-"}, 416, 0, 0, "bytes */" + sizeText},
		{"start past size", "GET", []string{"Range", "bytes=20000-30000"}, 416, 0, 0, "bytes */" + sizeText},
		{"suffix zero", "GET", []string{"Range", "bytes=-0"}, 416, 0, 0, "bytes */" + sizeText},
		{"multi range", "GET", []string{"Range", "bytes=0-1,5-9"}, 200, 0, size, ""},
		{"trailing comma", "GET", []string{"Range", "bytes=0-1,"}, 200, 0, size, ""},
		{"inverted", "GET", []string{"Range", "bytes=5-3"}, 200, 0, size, ""},
		{"unknown unit", "GET", []string{"Range", "items=0-5"}, 200, 0, size, ""},
		{"no equals", "GET", []string{"Range", "bytes0-5"}, 200, 0, size, ""},
		{"no dash", "GET", []string{"Range", "bytes=5"}, 200, 0, size, ""},
		{"bare dash", "GET", []string{"Range", "bytes=-"}, 200, 0, size, ""},
		{"letters", "GET", []string{"Range", "bytes=a-b"}, 200, 0, size, ""},
		{"negative suffix", "GET", []string{"Range", "bytes=--5"}, 200, 0, size, ""},
		{"plus sign", "GET", []string{"Range", "bytes=+1-5"}, 200, 0, size, ""},
		{"space inside", "GET", []string{"Range", "bytes=1 -5"}, 200, 0, size, ""},
		{"overflowing digits", "GET", []string{"Range", "bytes=0-99999999999999999999"}, 200, 0, size, ""},
		{"empty spec", "GET", []string{"Range", "bytes="}, 200, 0, size, ""},
		{"range on POST", "POST", []string{"Range", "bytes=0-99"}, 200, 0, size, ""},
		{"range on HEAD", "HEAD", []string{"Range", "bytes=0-99"}, 200, 0, size, ""},
		{"unsatisfiable on HEAD", "HEAD", []string{"Range", "bytes=20000-"}, 200, 0, size, ""},
		{"if-range etag match", "GET", []string{"Range", "bytes=0-9", "If-Range", fx.etag}, 206, 0, 10, "bytes 0-9/" + sizeText},
		{"if-range etag mismatch", "GET", []string{"Range", "bytes=0-9", "If-Range", `"other"`}, 200, 0, size, ""},
		{"if-range weak etag", "GET", []string{"Range", "bytes=0-9", "If-Range", "W/" + fx.etag}, 200, 0, size, ""},
		{"if-range etag with junk", "GET", []string{"Range", "bytes=0-9", "If-Range", fx.etag + "x"}, 200, 0, size, ""},
		{"if-range exact date", "GET", []string{"Range", "bytes=0-9", "If-Range", fx.lastModified}, 206, 0, 10, "bytes 0-9/" + sizeText},
		{"if-range later date", "GET", []string{"Range", "bytes=0-9", "If-Range", serveContentModTime.Add(time.Hour).UTC().Format(http.TimeFormat)}, 200, 0, size, ""},
		{"if-range garbage", "GET", []string{"Range", "bytes=0-9", "If-Range", "garbage"}, 200, 0, size, ""},
		{"if-range mismatch skips 416", "GET", []string{"Range", "bytes=20000-", "If-Range", `"other"`}, 200, 0, size, ""},
		{"precondition before range", "GET", []string{"Range", "bytes=0-9", "If-None-Match", fx.etag}, 304, 0, 0, ""},
	}
	for _, tc := range cases {
		resp := serveContentDo(t, fx.path, tc.method, tc.headers...)
		if resp.StatusCode != tc.status {
			t.Errorf("%s: status %d, want %d", tc.name, resp.StatusCode, tc.status)
			continue
		}
		gotRange, hasRange := respHeader(resp, "Content-Range")
		if gotRange != tc.contentRange || hasRange != (tc.contentRange != "") {
			t.Errorf("%s: Content-Range %q, want %q", tc.name, gotRange, tc.contentRange)
		}
		switch tc.status {
		case 200, 206:
			want := fx.content[tc.start:tc.end]
			if got := resp.GetBody(); sha256.Sum256(got) != sha256.Sum256(want) {
				t.Errorf("%s: body %d bytes does not match [%d:%d]", tc.name, len(got), tc.start, tc.end)
			}
			if cl := resp.headerContentLength(); tc.method != "HEAD" && cl != len(want) {
				t.Errorf("%s: Content-Length %d, want %d", tc.name, cl, len(want))
			}
		case 416:
			if _, has := respHeader(resp, "ETag"); has {
				t.Errorf("%s: 416 carries an ETag", tc.name)
			}
		}
	}
}

func TestServeContentEmptyFile(t *testing.T) {
	path := writeServeContentFile(t, t.TempDir(), nil)
	if resp := serveContentDo(t, path, "GET"); resp.StatusCode != 200 || len(resp.GetBody()) != 0 {
		t.Fatalf("empty GET = %d", resp.StatusCode)
	}
	for _, spec := range []string{"bytes=0-", "bytes=-1", "bytes=0-0"} {
		resp := serveContentDo(t, path, "GET", "Range", spec)
		if got, _ := respHeader(resp, "Content-Range"); resp.StatusCode != 416 || got != "bytes */0" {
			t.Errorf("%s on empty file = %d %q, want 416 bytes */0", spec, resp.StatusCode, got)
		}
	}
}

func TestServeContentSparseGiB(t *testing.T) {
	const size = 1 << 30
	const start = 1073741000
	path := filepath.Join(t.TempDir(), "sparse.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Skipf("sparse file unsupported: %v", err)
	}
	tail := serveContentPattern(size - start)
	if _, err := f.WriteAt(tail, start); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()

	resp := serveContentDo(t, path, "GET", "Range", "bytes=1073741000-")
	if resp.StatusCode != 206 || len(resp.GetBody()) != 824 {
		t.Fatalf("status %d, %d bytes", resp.StatusCode, len(resp.GetBody()))
	}
	if sha256.Sum256(resp.GetBody()) != sha256.Sum256(tail) {
		t.Fatal("sparse tail bytes differ")
	}
	if got, _ := respHeader(resp, "Content-Range"); got != "bytes 1073741000-1073741823/1073741824" {
		t.Fatalf("Content-Range %q", got)
	}
}

func TestServeContentShrunkFileFailsInsteadOfShortBody(t *testing.T) {
	fx := newServeContentFixture(t)
	f, err := os.Open(fx.path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(fx.path, 100); err != nil {
		t.Fatal(err)
	}
	req := &Request{Method: "GET"}
	resp := &Response{lazyReq: req}
	if err := resp.serveContent(req, f, fi, "", nil); err == nil {
		t.Fatal("serving a file that shrank after stat reported no error")
	}
}

func TestParseByteRangeTable(t *testing.T) {
	cases := []struct {
		header        string
		size          int64
		start, length int64
		outcome       rangeOutcome
	}{
		{"bytes=0-0", 1, 0, 1, rangeSatisfiable},
		{"bytes=0-", 1, 0, 1, rangeSatisfiable},
		{"bytes=-1", 1, 0, 1, rangeSatisfiable},
		{"bytes=1-", 1, 0, 0, rangeUnsatisfiable},
		{"bytes=-1", 0, 0, 0, rangeUnsatisfiable},
		{"bytes=0-999999999999999999", 10, 0, 10, rangeSatisfiable},
		{"bytes=999999999999999999-", 10, 0, 0, rangeUnsatisfiable},
		{"bytes=0-9999999999999999999", 10, 0, 0, rangeIgnored},
		{"Bytes=2-3", 10, 2, 2, rangeSatisfiable},
		{"bytes =2-3", 10, 0, 0, rangeIgnored},
		{"bytes=\t2-3\t", 10, 2, 2, rangeSatisfiable},
		{"bytes=2-3-4", 10, 0, 0, rangeIgnored},
		{"", 10, 0, 0, rangeIgnored},
	}
	for _, tc := range cases {
		start, length, outcome := parseByteRange(tc.header, tc.size)
		if outcome != tc.outcome || (outcome == rangeSatisfiable && (start != tc.start || length != tc.length)) {
			t.Errorf("parseByteRange(%q, %d) = %d,%d,%d want %d,%d,%d", tc.header, tc.size, start, length, outcome, tc.start, tc.length, tc.outcome)
		}
	}
}

func TestETagListContains(t *testing.T) {
	const tag = `"abc-1"`
	cases := []struct {
		list   string
		strong bool
		want   bool
	}{
		{tag, true, true},
		{tag, false, true},
		{`W/` + tag, true, false},
		{`W/` + tag, false, true},
		{`"x",` + tag, true, true},
		{` , ,"x" ,	` + tag + ` ,`, true, true},
		{`*`, true, true},
		{` * `, true, true},
		{`*, "x"`, true, true},
		{`*x`, true, false},
		{`"x"`, true, false},
		{`abc-1`, false, false},
		{`"abc-1`, false, false},
		{`"a b"` + tag, false, false},
		{`"a"` + tag, false, true},
		{"\"\x7f\"," + tag, false, false},
		{"\"\x80\xff\"," + tag, false, true},
		{``, false, false},
		{`W/`, false, false},
	}
	for _, tc := range cases {
		if got := etagListContains(tc.list, tag, tc.strong); got != tc.want {
			t.Errorf("etagListContains(%q, strong=%v) = %v, want %v", tc.list, tc.strong, got, tc.want)
		}
	}
}

func TestHTTPDateCache(t *testing.T) {
	a := httpDate(serveContentModTime.Unix())
	if a != serveContentModTime.UTC().Format(http.TimeFormat) {
		t.Fatalf("httpDate = %q", a)
	}
	b := httpDate(serveContentModTime.Unix() + 1)
	if b == a || b != serveContentModTime.Add(time.Second).UTC().Format(http.TimeFormat) {
		t.Fatalf("httpDate next second = %q", b)
	}
	if again := httpDate(serveContentModTime.Unix() + 1); again != b {
		t.Fatalf("cached httpDate = %q", again)
	}
}

func TestSendFileHonoursRange(t *testing.T) {
	content := serveContentPattern(4096)
	f, err := os.CreateTemp(".", "sendfile-range-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(f.Name())
	t.Cleanup(func() { _ = os.Remove(name) })
	_, _ = f.Write(content)
	_ = f.Close()

	req := &Request{Method: "GET", Headers: [][2]string{{"Range", "bytes=100-199"}}}
	resp := &Response{lazyReq: req}
	if err := resp.SendFile(name, WithAttachment("x.bin")); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 206 || !bytes.Equal(resp.GetBody(), content[100:200]) {
		t.Fatalf("status %d, %d bytes", resp.StatusCode, len(resp.GetBody()))
	}
	if cd, _ := respHeader(resp, "Content-Disposition"); cd != `attachment; filename="x.bin"` {
		t.Fatalf("Content-Disposition %q", cd)
	}
}

func TestStaticHonoursRangeAndConditionals(t *testing.T) {
	dir := t.TempDir()
	content := serveContentPattern(70 << 20)
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<p>i</p>"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := Static("/s", StaticConfig{Root: dir})
	run := func(path string, headers ...string) *Response {
		req := &Request{Method: "GET", Path: path}
		for i := 0; i+1 < len(headers); i += 2 {
			req.Headers = append(req.Headers, [2]string{headers[i], headers[i+1]})
		}
		resp := &Response{lazyReq: req}
		h(req, resp)
		return resp
	}
	resp := run("/s/big.bin", "Range", "bytes=50000000-50000999")
	if resp.StatusCode != 206 || !bytes.Equal(resp.GetBody(), content[50000000:50001000]) {
		t.Fatalf("range over a 70MB static file = %d, %d bytes", resp.StatusCode, len(resp.GetBody()))
	}
	etag, _ := respHeader(resp, "ETag")
	if again := run("/s/big.bin", "If-None-Match", etag); again.StatusCode != 304 {
		t.Fatalf("static If-None-Match = %d", again.StatusCode)
	}
	index := run("/s/")
	if index.StatusCode != 200 || string(index.GetBody()) != "<p>i</p>" || index.ContentType != "text/html; charset=utf-8" {
		t.Fatalf("index = %d %q %q", index.StatusCode, index.GetBody(), index.ContentType)
	}
	if ar, _ := respHeader(index, "Accept-Ranges"); ar != "bytes" {
		t.Fatal("index lacks Accept-Ranges")
	}
	if missing := run("/s/nope.bin"); missing.StatusCode != 404 {
		t.Fatalf("missing = %d", missing.StatusCode)
	}
}

func refParseByteRange(header string, size int64) (int64, int64, rangeOutcome) {
	unit, spec, ok := strings.Cut(header, "=")
	if !ok || strings.ToLower(unit) != "bytes" {
		return 0, 0, rangeIgnored
	}
	spec = strings.Trim(spec, " \t\r\n")
	if spec == "" || strings.Contains(spec, ",") {
		return 0, 0, rangeIgnored
	}
	first, last, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, rangeIgnored
	}
	number := func(s string) (int64, bool) {
		if len(s) == 0 || len(s) > maxRangeIntDigits || strings.Trim(s, "0123456789") != "" {
			return 0, false
		}
		n, err := strconv.ParseInt(s, 10, 64)
		return n, err == nil
	}
	if first == "" {
		n, ok := number(last)
		if !ok {
			return 0, 0, rangeIgnored
		}
		if n == 0 || size == 0 {
			return 0, 0, rangeUnsatisfiable
		}
		n = min(n, size)
		return size - n, n, rangeSatisfiable
	}
	a, ok := number(first)
	if !ok {
		return 0, 0, rangeIgnored
	}
	end := size - 1
	if last != "" {
		b, ok := number(last)
		if !ok || b < a {
			return 0, 0, rangeIgnored
		}
		end = min(end, b)
	}
	if a >= size {
		return 0, 0, rangeUnsatisfiable
	}
	return a, end - a + 1, rangeSatisfiable
}

func FuzzRangeHeader(f *testing.F) {
	for _, seed := range []string{"bytes=0-99", "bytes=-500", "bytes=10000-", "bytes=0-1,5-9", "BYTES= 1-2 ", "bytes=5-3", "items=0-1", "bytes=-0", "bytes=0-99999999999999999999", "bytes=--1", "bytes=1-2-3"} {
		f.Add(seed, int64(serveContentSize))
		f.Add(seed, int64(0))
	}
	f.Fuzz(func(t *testing.T, header string, size int64) {
		if size < 0 {
			size = -size
		}
		if size < 0 {
			return
		}
		start, length, outcome := parseByteRange(header, size)
		refStart, refLength, refOutcome := refParseByteRange(header, size)
		if outcome != refOutcome || start != refStart || length != refLength {
			t.Fatalf("parseByteRange(%q, %d) = %d,%d,%d; reference %d,%d,%d", header, size, start, length, outcome, refStart, refLength, refOutcome)
		}
		if outcome == rangeSatisfiable && (start < 0 || length < 1 || start+length > size) {
			t.Fatalf("parseByteRange(%q, %d) = [%d,+%d) outside the file", header, size, start, length)
		}
		if outcome != rangeSatisfiable && (start != 0 || length != 0) {
			t.Fatalf("parseByteRange(%q, %d) returned %d,%d with outcome %d", header, size, start, length, outcome)
		}
		if outcome == rangeSatisfiable {
			cr := formatContentRange(start, length, size)
			want := "bytes " + strconv.FormatInt(start, 10) + "-" + strconv.FormatInt(start+length-1, 10) + "/" + strconv.FormatInt(size, 10)
			if cr != want {
				t.Fatalf("formatContentRange = %q, want %q", cr, want)
			}
		}
	})
}
