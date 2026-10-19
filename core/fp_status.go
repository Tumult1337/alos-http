//go:build linux && amd64

package core

import "net/http"

const unknownStatusText = "Unknown"

func statusText(code int) string {
	if text := http.StatusText(code); text != "" {
		return text
	}
	return unknownStatusText
}
