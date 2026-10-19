//go:build linux && amd64

package core

import "github.com/bytedance/sonic"

func bindJSON(body []byte, v any) error {
	return sonic.Unmarshal(body, v)
}
