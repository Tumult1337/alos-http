//go:build linux && amd64

package core

import (
	"errors"
	"reflect"
	"testing"
)

const multipartFieldPart = "Content-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n"

func multipartDifferentialBodies() map[string]string {
	normal := string(buildMultipart("B",
		multipartFixturePart{disposition: `form-data; name="field"`, body: "value"},
		multipartFixturePart{disposition: `form-data; name="upload"; filename="a.bin"`, contentType: "application/octet-stream", body: "data"},
	))
	withContent := func(content string) string {
		return string(buildMultipart("B",
			multipartFixturePart{disposition: `form-data; name="field"`, body: content},
			multipartFixturePart{disposition: `form-data; name="upload"; filename="a.bin"`, body: content},
			multipartFixturePart{disposition: `form-data; name="after"`, body: "kept"},
		))
	}
	return map[string]string{
		"normal":                           normal,
		"preamble_close_prefix":            "--B--x\r\n" + normal,
		"preamble_line_close_prefix":       "ignored\r\n--B--junk\r\n" + normal,
		"preamble_close_prefix_lwsp_junk":  "--B-- \tjunk\r\n" + normal,
		"preamble_open_prefix":             "--Bwrong\r\n" + normal,
		"preamble_open_prefix_lines":       "text\r\n--Bwrong\r\n--B-x\r\n" + normal,
		"preamble_open_lwsp_junk":          "--B \tjunk\r\n" + normal,
		"preamble_close_line":              "--B--\r\n" + normal,
		"preamble_close_eof":               "--B--",
		"preamble_close_lwsp_eof":          "--B-- \t",
		"preamble_open_eof":                "--B",
		"preamble_open_lwsp_eof":           "--B \t",
		"preamble_only":                    "preamble only",
		"preamble_inline_boundary":         "ignored--B\r\n" + multipartFieldPart + "--B--",
		"open_padding":                     "--B \t\r\n" + multipartFieldPart + "--B-- \t\r\n",
		"close_junk":                       "--B\r\n" + multipartFieldPart + "--B--junk\r\n",
		"close_lwsp_junk":                  "--B\r\n" + multipartFieldPart + "--B-- \tjunk\r\n",
		"close_bare_cr":                    "--B\r\n" + multipartFieldPart + "--B--\r",
		"close_eof":                        "--B\r\n" + multipartFieldPart + "--B--",
		"close_lwsp_eof":                   "--B\r\n" + multipartFieldPart + "--B-- \t",
		"close_epilogue":                   "--B\r\n" + multipartFieldPart + "--B--\r\nignored",
		"close_missing":                    "--B\r\n" + multipartFieldPart + "--B",
		"close_single_dash_eof":            "--B\r\n" + multipartFieldPart + "--B-",
		"next_open_lwsp_junk":              "--B\r\n" + multipartFieldPart + "--B \tjunk\r\n" + multipartFieldPart + "--B--\r\n",
		"content_open_prefix":              withContent("first\r\n--Bnot-a-delimiter\r\nlast"),
		"content_single_dash":              withContent("first\r\n--B-junk\r\nlast"),
		"content_binary_suffix":            withContent("first\r\n--B\x00junk\r\nlast"),
		"content_repeated_prefixes":        withContent("first\r\n--Bwrong\r\n--Bmore\r\nlast"),
		"content_leading_prefix":           withContent("--Bx\r\nlast"),
		"content_empty":                    withContent(""),
		"content_close_junk":               withContent("first\r\n--B--junk\r\nlast"),
		"content_open_lwsp_junk":           withContent("first\r\n--B \tjunk\r\nlast"),
		"content_close_lwsp_junk":          withContent("first\r\n--B-- \tjunk\r\nlast"),
		"content_open_cr_junk":             withContent("first\r\n--B\rjunk\r\nlast"),
		"content_open_tab_junk":            withContent("first\r\n--B\tjunk\r\nlast"),
		"content_true_close":               withContent("first\r\n--B--\r\nlast"),
		"empty_part_without_crlf":          "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n--B\r\n" + multipartFieldPart + "--B--\r\n",
		"empty_file_closed_without_crlf":   "--B\r\nContent-Disposition: form-data; filename=\"../../x\"; name=\"f\"\r\n\r\n--B--",
		"empty_part_bad_line_without_crlf": "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n--B--junk\r\n",
	}
}

func TestMultipartMatchesStdlibOnTrickyBoundaries(t *testing.T) {
	for name, body := range multipartDifferentialBodies() {
		t.Run(name, func(t *testing.T) {
			if hasBareLF([]byte(body)) {
				t.Fatalf("fixture contains a bare LF")
			}
			values, files, err := parseMultipartInMem([]byte(body), "B")
			refValues, refFiles, refErr := parseMultipartStdlibReference([]byte(body), "B")
			if (err == nil) != (refErr == nil) {
				t.Fatalf("inmem err=%v values=%q, stdlib err=%v values=%q", err, values, refErr, refValues)
			}
			if err != nil {
				if !errors.Is(err, errMultipartMalformed) {
					t.Fatalf("inmem err=%v, want errMultipartMalformed", err)
				}
				return
			}
			if !reflect.DeepEqual(values, refValues) || !reflect.DeepEqual(files, refFiles) {
				t.Fatalf("inmem values=%q files=%+v, stdlib values=%q files=%+v", values, files, refValues, refFiles)
			}
		})
	}
}
