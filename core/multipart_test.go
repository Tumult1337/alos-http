//go:build linux && amd64

package core

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

type multipartFixturePart struct {
	disposition string
	contentType string
	body        string
}

func buildMultipart(boundary string, parts ...multipartFixturePart) []byte {
	var b bytes.Buffer
	for _, p := range parts {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Disposition: " + p.disposition + "\r\n")
		if p.contentType != "" {
			b.WriteString("Content-Type: " + p.contentType + "\r\n")
		}
		b.WriteString("\r\n")
		b.WriteString(p.body)
		b.WriteString("\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes()
}

type multipartParser struct {
	name  string
	parse func(t *testing.T, body []byte, boundary string) (map[string][]string, map[string][]FileHeader, error)
}

func multipartParsers() []multipartParser {
	return []multipartParser{
		{"inmem", func(t *testing.T, body []byte, boundary string) (map[string][]string, map[string][]FileHeader, error) {
			return parseMultipartInMem(body, boundary)
		}},
		{"stdlib-reference", func(t *testing.T, body []byte, boundary string) (map[string][]string, map[string][]FileHeader, error) {
			return parseMultipartStdlibReference(body, boundary)
		}},
	}
}

func TestMultipartFilenameHandling(t *testing.T) {
	cases := []struct {
		disposition, want string
	}{
		{`form-data; name="f"; filename="../../etc/passwd"`, "passwd"},
		{`form-data; name="f"; filename="C:\x\a.txt"`, "a.txt"},
		{`form-data; name="f"; filename="C:\\x\\a.txt"`, "a.txt"},
		{`form-data; name="f"; filename*=UTF-8''%E2%82%AC.txt`, "€.txt"},
		{`form-data; name="f"; filename="fallback.txt"; filename*=utf-8'en'%E2%82%AC.txt`, "€.txt"},
		{`form-data; name="f"; filename*=UTF-8''%E2%82; filename="fallback.txt"`, "fallback.txt"},
		{`form-data; name="f"; filename=".."`, ""},
		{`form-data; name="f"; filename="."`, ""},
		{`form-data; name="f"; filename*=UTF-8''a%01b%7F.txt`, "ab.txt"},
		{`form-data; filename="first.txt"; name="f"`, "first.txt"},
		{`form-data; name="f"; filename="say \"hi\".txt"`, `say "hi".txt`},
	}
	for _, p := range multipartParsers() {
		for _, c := range cases {
			body := buildMultipart("B", multipartFixturePart{disposition: c.disposition, body: "data"})
			_, files, err := p.parse(t, body, "B")
			if err != nil {
				t.Errorf("%s %q: %v", p.name, c.disposition, err)
				continue
			}
			got := files["f"]
			if len(got) != 1 || got[0].Filename != c.want {
				t.Errorf("%s %q: files %+v, want filename %q", p.name, c.disposition, got, c.want)
			}
		}
	}
}

func TestMultipartLongFilenameIsCappedOnRuneBoundary(t *testing.T) {
	long := strings.Repeat("€", 200)
	got := sanitizeUploadFilename(long)
	if len(got) > maxUploadFilenameBytes || !strings.HasPrefix(long, got) || strings.ContainsRune(got, '\uFFFD') {
		t.Fatalf("capped name has %d bytes and is not a clean prefix", len(got))
	}
}

func TestMultipartValuesAndFiles(t *testing.T) {
	body := buildMultipart("XyZ",
		multipartFixturePart{disposition: `form-data; name=field`, body: "plain"},
		multipartFixturePart{disposition: `FORM-DATA; NAME="quoted"`, body: "q"},
		multipartFixturePart{disposition: `form-data; name="up"; filename="a.txt"`, contentType: "text/plain", body: "file-a"},
		multipartFixturePart{disposition: `form-data; name="up"; filename="b.bin"`, body: "file-b"},
		multipartFixturePart{disposition: `form-data; name="multi"`, body: "1"},
		multipartFixturePart{disposition: `form-data; name="multi"`, body: "2"},
		multipartFixturePart{disposition: `form-data`, body: "nameless is skipped"},
	)
	for _, p := range multipartParsers() {
		vals, files, err := p.parse(t, body, "XyZ")
		if err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		if vals["field"][0] != "plain" || vals["quoted"][0] != "q" || len(vals["multi"]) != 2 || vals["multi"][1] != "2" {
			t.Errorf("%s: values %q", p.name, vals)
		}
		if len(vals) != 3 {
			t.Errorf("%s: %d value fields, want 3 (nameless part must be skipped)", p.name, len(vals))
		}
		up := files["up"]
		if len(up) != 2 || string(up[0].Data) != "file-a" || up[0].ContentType != "text/plain" || up[1].ContentType != defaultUploadType || up[1].Size != 6 {
			t.Errorf("%s: files %+v", p.name, up)
		}
		r, err := up[0].Open()
		if err != nil {
			t.Fatalf("%s: Open: %v", p.name, err)
		}
		data, _ := io.ReadAll(r)
		_ = r.Close()
		if string(data) != "file-a" {
			t.Errorf("%s: Open read %q", p.name, data)
		}
	}
}

func TestMultipartDelimiterNeedsPrecedingCRLF(t *testing.T) {
	body := []byte("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx--B y\r\n--B--\r\n")
	for _, p := range multipartParsers() {
		vals, _, err := p.parse(t, body, "B")
		if err != nil || len(vals["a"]) != 1 || vals["a"][0] != "x--B y" {
			t.Errorf("%s: vals %q err %v, want the embedded delimiter kept as content", p.name, vals, err)
		}
	}
}

func TestMultipartBareLFIsNotALineBreak(t *testing.T) {
	body := []byte("\n--B \nContent-Disposition:form-dAtA;nAme=0\n\r\n--B--")
	vals, files, err := parseMultipartInMem(body, "B")
	if err != nil || len(vals) != 0 || len(files) != 0 {
		t.Fatalf("vals %q files %v err %v, want the bare-LF lines treated as preamble", vals, files, err)
	}
	inPart := []byte("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\n--B\ny\r\n--B--\r\n")
	vals, _, err = parseMultipartInMem(inPart, "B")
	if err != nil || len(vals["a"]) != 1 || vals["a"][0] != "x\n--B\ny" {
		t.Fatalf("vals %q err %v, want the LF delimiter kept as content", vals, err)
	}
}

func TestHasBareLF(t *testing.T) {
	for in, want := range map[string]bool{"": false, "a\r\nb": false, "\n": true, "a\nb": true, "\r\n\n": true, "\r\r\n": false} {
		if got := hasBareLF([]byte(in)); got != want {
			t.Errorf("hasBareLF(%q) = %v", in, got)
		}
	}
}

func TestMultipartPreambleAndEpilogue(t *testing.T) {
	body := []byte("preamble text\r\n--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--B--\r\nepilogue")
	for _, p := range multipartParsers() {
		vals, _, err := p.parse(t, body, "B")
		if err != nil || vals["a"][0] != "v" {
			t.Errorf("%s: vals %q err %v", p.name, vals, err)
		}
	}
}

func TestMultipartRejectsMalformedBodies(t *testing.T) {
	bodies := map[string]string{
		"missing close delimiter":   "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv",
		"no delimiter at all":       "just text",
		"header line without colon": "--B\r\nContent-Disposition: form-data; name=\"a\"\r\nbroken\r\n\r\nv\r\n--B--\r\n",
		"not form-data":             "--B\r\nContent-Disposition: attachment; name=\"a\"\r\n\r\nv\r\n--B--\r\n",
		"control byte in header":    "--B\r\nContent-Disposition: form-data; name=\"a\"; filename=\"a\x01b\"\r\n\r\nv\r\n--B--\r\n",
	}
	for name, body := range bodies {
		for _, p := range multipartParsers() {
			if _, _, err := p.parse(t, []byte(body), "B"); err == nil {
				t.Errorf("%s accepted %s", p.name, name)
			}
		}
	}
	oversized := "--B\r\nX-Pad: " + strings.Repeat("p", maxMultipartHeaderBytes) + "\r\n\r\nv\r\n--B--\r\n"
	if _, _, err := parseMultipartInMem([]byte(oversized), "B"); err == nil {
		t.Error("inmem accepted a part header block over the cap")
	}
}

func TestMultipartPartCap(t *testing.T) {
	parts := make([]multipartFixturePart, maxMultipartParts+1)
	for i := range parts {
		parts[i] = multipartFixturePart{disposition: fmt.Sprintf(`form-data; name="p%d"`, i), body: "v"}
	}
	body := buildMultipart("B", parts...)
	for _, p := range multipartParsers() {
		if _, _, err := p.parse(t, body, "B"); !errors.Is(err, errMultipartTooManyParts) {
			t.Errorf("%s: err %v, want errMultipartTooManyParts", p.name, err)
		}
	}
	if _, _, err := parseMultipartInMem(buildMultipart("B", parts[:maxMultipartParts]...), "B"); err != nil {
		t.Errorf("exactly %d parts rejected: %v", maxMultipartParts, err)
	}
}

func TestMultipartBoundaryFromContentType(t *testing.T) {
	cases := map[string]string{
		`multipart/form-data; boundary=abc`:                                            "abc",
		`multipart/form-data; BOUNDARY="a b;c"`:                                        "a b;c",
		`Multipart/Form-Data ; charset=utf-8; boundary=x123`:                           "x123",
		`multipart/mixed; boundary=abc`:                                                "",
		`multipart/form-data`:                                                          "",
		`multipart/form-data; boundary=`:                                               "",
		`multipart/form-data; boundary=` + strings.Repeat("b", maxMultipartBoundary+1): "",
	}
	for ct, want := range cases {
		if got := multipartBoundary(ct); got != want {
			t.Errorf("multipartBoundary(%q) = %q, want %q", ct, got, want)
		}
	}
}

func TestFormValueReadsMultipartFields(t *testing.T) {
	body := buildMultipart("B",
		multipartFixturePart{disposition: `form-data; name="name"`, body: "alos"},
		multipartFixturePart{disposition: `form-data; name="f"; filename="x.txt"`, body: "file"},
	)
	req := &Request{Body: body, Headers: [][2]string{{"Content-Type", "multipart/form-data; boundary=B"}}}
	if got := req.FormValue("name"); got != "alos" {
		t.Fatalf("FormValue = %q before FormFile was called", got)
	}
	if fh, ok := req.FormFile("f"); !ok || string(fh.Data) != "file" {
		t.Fatalf("FormFile = %+v %v", fh, ok)
	}
}
