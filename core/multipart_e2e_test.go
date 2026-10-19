//go:build linux && amd64

package core

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

func multipartUploadRoutes(r *Router) {
	r.POST("/upload", func(req *Request, resp *Response) {
		fh, ok := req.FormFile("doc")
		if !ok {
			resp.Status(400).String("no file")
			return
		}
		rc, err := fh.Open()
		if err != nil {
			resp.Status(500).String(err.Error())
			return
		}
		data, _ := io.ReadAll(rc)
		_ = rc.Close()
		resp.String(req.FormValue("title") + "|" + fh.Filename + "|" + fh.ContentType + "|" + string(data))
	})
}

func multipartUploadRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("title", "report")
	part, err := w.CreateFormFile("doc", `..\..\secret.txt`)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte(strings.Repeat("A", 70000)))
	_ = w.Close()
	req, err := http.NewRequest("POST", url, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = harnessDomain
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func TestMultipartUploadOverTheWire(t *testing.T) {
	want := "report|secret.txt|application/octet-stream|" + strings.Repeat("A", 70000)
	for _, c := range []struct {
		name string
		tls  bool
		alpn string
	}{{"h1", false, ""}, {"h2", true, "h2"}} {
		t.Run(c.name, func(t *testing.T) {
			ts := newTestServer(t, testServerOptions{TLS: c.tls, Routes: multipartUploadRoutes})
			resp, err := ts.client(t, c.alpn).Do(multipartUploadRequest(t, ts.url("/upload")))
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || string(got) != want {
				t.Fatalf("status %d, body prefix %q", resp.StatusCode, got[:min(len(got), 80)])
			}
		})
	}
}
