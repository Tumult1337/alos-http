//go:build linux && amd64

package core

import (
	"errors"
	"testing"
)

func TestAppFixFineTuneNeverRunsPackageManagerByDefault(t *testing.T) {
	if DefaultFineTuneOptions().AutoInstallWrk {
		t.Fatal("DefaultFineTuneOptions enables AutoInstallWrk, so FineTune() runs the system package manager")
	}
	t.Setenv("PATH", t.TempDir())
	_, installed, err := ensureWrkAvailable(DefaultFineTuneOptions().AutoInstallWrk)
	if installed || !errors.Is(err, errWrkNotInstalled) {
		t.Fatalf("missing wrk with default options: installed=%v err=%v, want errWrkNotInstalled", installed, err)
	}
}
