//go:build linux && !janitor_prove_base

// This test needs the cargoBeforeVerify seam; build with the
// janitor_prove_base tag to leave it out when compiling the tests against a
// base that does not have the seam.

package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A profile's .cargo-lock unlinked after the trim has locked it and before
// its final verification (a held flock does not stop an unlink) leaves an
// untagged directory without its proof of being a cargo target: the trim
// fails and removes nothing.
func TestCargoTargetTrimRefusesProfileLockUnlinkedBeforeVerify(t *testing.T) {
	x, target, trim := cargoTargetFixture(t)
	if err := os.Remove(filepath.Join(target, "CACHEDIR.TAG")); err != nil {
		t.Fatal(err)
	}
	backdate(t, target, 2*time.Hour)
	lock := filepath.Join(target, "release", ".cargo-lock")
	cargoBeforeVerify = func(string) {
		if err := os.Remove(lock); err != nil {
			t.Error(err)
		}
	}
	defer func() { cargoBeforeVerify = nil }()
	trims, code := x.cycleTrims(t, trim)
	if code == ExitOK || trims[0].Status != "failed" {
		t.Fatalf("trim went ahead without the profile's .cargo-lock: exit %d %+v", code, trims[0])
	}
	if !exists(t, filepath.Join(target, "release", "deps", "libbig.rlib")) || !exists(t, filepath.Join(target, ".rustc_info.json")) {
		t.Fatal("the trim removed outputs after losing its proof")
	}
}
