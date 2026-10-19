//go:build linux && amd64

package core

import (
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestMultipartClosingBoundaryPrefixDoesNotEndPreamble(t *testing.T) {
	for _, prefix := range []string{"--B--x\r\n", "ignored\r\n--B--junk\r\n", "--B-- \tjunk\r\n"} {
		body := append([]byte(prefix), buildMultipart("B", multipartFixturePart{disposition: `form-data; name="0"`, body: ""})...)
		values, _, err := parseMultipartInMem(body, "B")
		reference, _, referenceErr := parseMultipartStdlibReference(body, "B")
		want := map[string][]string{"0": {""}}
		if referenceErr != nil || !reflect.DeepEqual(reference, want) {
			t.Fatalf("reference fixture prefix %q: values=%q err=%v", prefix, reference, referenceErr)
		}
		if err != nil || !reflect.DeepEqual(values, want) {
			t.Errorf("prefix %q: inmem values=%q err=%v; reference values=%q", prefix, values, err, reference)
		}
	}
}

func TestMultipartMalformedClosingBoundaryIsRejected(t *testing.T) {
	for _, ending := range []string{"--B--junk\r\n", "--B-- \tjunk\r\n", "--B--\r", "--B--\n"} {
		body := []byte("--B\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n" + ending)
		if values, _, err := parseMultipartInMem(body, "B"); !errors.Is(err, errMultipartMalformed) {
			t.Errorf("closing line %q accepted with values=%q", ending, values)
		}
	}
}

func TestMultipartBoundaryLineAcceptedForms(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, ending string
		want                 map[string][]string
	}{
		{"normal", "--B\r\n", "--B--\r\n", map[string][]string{"field": {"value"}}},
		{"padding", "--B \t\r\n", "--B-- \t\r\n", map[string][]string{"field": {"value"}}},
		{"final_eof", "--B\r\n", "--B--", map[string][]string{"field": {"value"}}},
		{"epilogue", "--B\r\n", "--B--\r\nignored", map[string][]string{"field": {"value"}}},
		{"opening_junk_preamble", "--Bwrong\r\n--B\r\n", "--B--\r\n", map[string][]string{"field": {"value"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.prefix + "Content-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n" + tc.ending)
			values, _, err := parseMultipartInMem(body, "B")
			reference, _, referenceErr := parseMultipartStdlibReference(body, "B")
			if referenceErr != nil || !reflect.DeepEqual(reference, tc.want) {
				t.Fatalf("invalid reference fixture: %q %v", reference, referenceErr)
			}
			if err != nil || !reflect.DeepEqual(values, tc.want) {
				t.Fatalf("values=%q err=%v, want %q", values, err, tc.want)
			}
		})
	}
}

func TestMultipartRequestKeepsFieldsAndEmptyFilesAfterFalseClose(t *testing.T) {
	body := append([]byte("--B--junk\r\n"), buildMultipart("B",
		multipartFixturePart{disposition: `form-data; name="field"`, body: "kept"},
		multipartFixturePart{disposition: `form-data; name="upload"; filename="empty.txt"`, body: ""},
	)...)
	req := &Request{Body: body, Headers: [][2]string{{"Content-Type", "multipart/form-data; boundary=B"}}}
	if value := req.FormValue("field"); value != "kept" {
		t.Fatalf("FormValue=%q, want kept", value)
	}
	file, found := req.FormFile("upload")
	if !found || file.Filename != "empty.txt" || file.Size != 0 || len(file.Data) != 0 {
		t.Fatalf("empty upload=%+v, found=%v", file, found)
	}
	reader, err := file.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil || len(data) != 0 {
		t.Fatalf("empty upload reader: %d bytes, err=%v", len(data), err)
	}
}

func TestMultipartRequestDiscardsMalformedClosingFields(t *testing.T) {
	body := []byte("--B\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n--B--junk\r\n")
	req := &Request{Body: body, Headers: [][2]string{{"Content-Type", "multipart/form-data; boundary=B"}}}
	if value := req.FormValue("field"); value != "" || len(req.formCache) != 0 || len(req.filesCache) != 0 {
		t.Fatalf("malformed multipart exposed partial form value=%q", value)
	}
}

func TestMultipartBoundaryPreambleRequiresAnchoringAndTermination(t *testing.T) {
	for _, body := range []string{"--B--junk", "--Bwrong\r\n", "preamble only"} {
		if _, _, err := parseMultipartInMem([]byte(body), "B"); !errors.Is(err, errMultipartMalformed) {
			t.Errorf("preamble %q: err=%v, want malformed", body, err)
		}
	}
	for _, prefix := range []string{"--B--\r\n", "ignored--B\r\n"} {
		body := append([]byte(prefix), []byte("Content-Disposition: form-data; name=\"ignored\"\r\n\r\nvalue\r\n--B--")...)
		values, files, err := parseMultipartInMem(body, "B")
		if err != nil || len(values) != 0 || len(files) != 0 {
			t.Errorf("prefix %q: values=%q err=%v, want valid empty multipart", prefix, values, err)
		}
	}
}
