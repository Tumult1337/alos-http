//go:build linux && amd64

package core

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestMultipartBoundaryPrefixesRemainPartContent(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"opening_prefix", "first\r\n--Bnot-a-delimiter\r\nlast"},
		{"single_dash", "first\r\n--B-junk\r\nlast"},
		{"binary_suffix", "first\r\n--B\x00junk\r\nlast"},
		{"repeated_prefixes", "first\r\n--Bwrong\r\n--Bmore\r\nlast"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := buildMultipart("B",
				multipartFixturePart{disposition: `form-data; name="field"`, body: tc.content},
				multipartFixturePart{disposition: `form-data; name="upload"; filename="a.bin"`, contentType: "application/octet-stream", body: tc.content},
				multipartFixturePart{disposition: `form-data; name="after"`, body: "kept"},
			)
			referenceValues, referenceFiles, referenceErr := parseMultipartStdlibReference(body, "B")
			if referenceErr != nil || !reflect.DeepEqual(referenceValues, map[string][]string{"field": {tc.content}, "after": {"kept"}}) || len(referenceFiles["upload"]) != 1 || !bytes.Equal(referenceFiles["upload"][0].Data, []byte(tc.content)) {
				t.Fatalf("reference fixture: values=%q files=%+v err=%v", referenceValues, referenceFiles, referenceErr)
			}
			values, files, err := parseMultipartInMem(body, "B")
			if err != nil || !reflect.DeepEqual(values, referenceValues) || !reflect.DeepEqual(files, referenceFiles) {
				t.Fatalf("content lost: values=%q files=%+v err=%v; reference values=%q files=%+v", values, files, err, referenceValues, referenceFiles)
			}
			req := &Request{Body: body, Headers: [][2]string{{"Content-Type", "multipart/form-data; boundary=B"}}}
			file, found := req.FormFile("upload")
			if !found || !bytes.Equal(file.Data, []byte(tc.content)) || file.Size != int64(len(tc.content)) || req.FormValue("field") != tc.content || req.FormValue("after") != "kept" {
				t.Fatalf("public request lost content: found=%v file=%+v field=%q after=%q", found, file, req.FormValue("field"), req.FormValue("after"))
			}
		})
	}
}

func TestMultipartContentPrefixesRequireTrueClosingBoundary(t *testing.T) {
	for _, suffix := range []string{"--Bwrong\r\n", "--B--junk\r\n", "--B \tjunk\r\n", "--B-- \tjunk\r\n", "--B"} {
		body := []byte("--B\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n" + suffix)
		if _, _, err := parseMultipartInMem(body, "B"); !errors.Is(err, errMultipartMalformed) {
			t.Errorf("suffix %q: err=%v, want malformed", suffix, err)
		}
		req := &Request{Body: body, Headers: [][2]string{{"Content-Type", "multipart/form-data; boundary=B"}}}
		if value := req.FormValue("field"); value != "" || len(req.formCache) != 0 || len(req.filesCache) != 0 {
			t.Errorf("suffix %q exposed partial value %q", suffix, value)
		}
	}
}

func TestMultipartMalformedContentBoundaryCandidatesAreRejected(t *testing.T) {
	for _, content := range []string{"first\r\n--B--junk\r\nlast", "first\r\n--B \tjunk\r\nlast", "first\r\n--B-- \tjunk\r\nlast", "first\r\n--B\rjunk\r\nlast", "first\r\n--B\njunk\r\nlast", "first\r\n--B\tjunk\r\nlast"} {
		body := buildMultipart("B", multipartFixturePart{disposition: `form-data; name="field"`, body: content})
		if _, _, err := parseMultipartStdlibReference(body, "B"); !errors.Is(err, errMultipartMalformed) {
			t.Fatalf("reference accepted malformed candidate %q: %v", content, err)
		}
		if _, _, err := parseMultipartInMem(body, "B"); !errors.Is(err, errMultipartMalformed) {
			t.Errorf("accepted malformed candidate %q: %v", content, err)
		}
	}
}

func TestMultipartFileBoundaryPrefixBeforeAnyField(t *testing.T) {
	content := "first\r\n--Bnot-a-delimiter\r\nlast"
	body := buildMultipart("B", multipartFixturePart{disposition: `form-data; name="upload"; filename="a.bin"`, body: content})
	_, reference, referenceErr := parseMultipartStdlibReference(body, "B")
	if referenceErr != nil || len(reference["upload"]) != 1 || !bytes.Equal(reference["upload"][0].Data, []byte(content)) {
		t.Fatalf("reference file fixture: %+v %v", reference, referenceErr)
	}
	values, files, err := parseMultipartInMem(body, "B")
	if err != nil || len(values) != 0 || !reflect.DeepEqual(files, reference) {
		t.Fatalf("file content lost: files=%+v err=%v, reference=%+v", files, err, reference)
	}
}
