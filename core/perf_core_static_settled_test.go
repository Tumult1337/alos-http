//go:build linux && amd64

package core

import "testing"

func BenchmarkPerfCoreW6StaticSettled(b *testing.B) {
	perfCoreSettleStaticFiles(b)
	root, _ := perfCoreStaticRoot(b)
	b.Run("streamed_sw_64K", func(b *testing.B) {
		rig := newPerfCoreStaticRig(root, true)
		b.SetBytes(perfCoreStaticFileSize)
		b.ReportAllocs()
		for b.Loop() {
			rig.serve()
		}
		if rig.resp.StatusCode != 200 {
			b.Fatalf("status %d", rig.resp.StatusCode)
		}
	})
}
