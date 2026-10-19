//go:build linux && amd64

package core

import "testing"

func TestWSUnmaskWithoutAVX2(t *testing.T) {
	prev := hasAVX2
	hasAVX2 = false
	t.Cleanup(func() { hasAVX2 = prev })
	TestWSUnmaskMatchesReference(t)
}
