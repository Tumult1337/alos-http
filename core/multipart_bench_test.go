//go:build linux && amd64

package core

import (
	"fmt"
	"strings"
	"testing"
)

const benchMultipartBoundary = "alosBenchBoundary"

type multipartBenchBody struct {
	name string
	body []byte
}

func multipartBenchFormFields() []byte {
	parts := make([]multipartFixturePart, 0, 16)
	for i := 0; len(parts) < 16; i++ {
		parts = append(parts, multipartFixturePart{disposition: fmt.Sprintf(`form-data; name="field%d"`, i), body: strings.Repeat("v", 40)})
	}
	return buildMultipart(benchMultipartBoundary, parts...)
}

func multipartBenchSingleFile(size int) []byte {
	return buildMultipart(benchMultipartBoundary, multipartFixturePart{
		disposition: `form-data; name="upload"; filename="blob.bin"`,
		contentType: "application/octet-stream",
		body:        strings.Repeat("u", size),
	})
}

func multipartBenchManyParts(n, size int) []byte {
	parts := make([]multipartFixturePart, n)
	for i := range parts {
		parts[i] = multipartFixturePart{disposition: fmt.Sprintf(`form-data; name="f%d"; filename="p%d.txt"`, i, i), body: strings.Repeat("m", size)}
	}
	return buildMultipart(benchMultipartBoundary, parts...)
}

func multipartBenchBodies() []multipartBenchBody {
	return []multipartBenchBody{
		{"Form1K", multipartBenchFormFields()},
		{"File64K", multipartBenchSingleFile(64 << 10)},
		{"File8M", multipartBenchSingleFile(8 << 20)},
		{"File64M", multipartBenchSingleFile(64 << 20)},
		{"Parts1000x512", multipartBenchManyParts(1000, 512)},
	}
}

func BenchmarkMultipartParse(b *testing.B) {
	for _, body := range multipartBenchBodies() {
		b.Run(body.name, func(b *testing.B) {
			b.SetBytes(int64(len(body.body)))
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := parseMultipartInMem(body.body, benchMultipartBoundary); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
