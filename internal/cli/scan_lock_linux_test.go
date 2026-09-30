//go:build linux

package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

// runsHeld starts work while the scan lock is held and reports whether it
// finished before the lock was released, then whether it finished after.
func runsHeld(t *testing.T, stateDir string, work func() error) (finishedWhileHeld bool, err error) {
	t.Helper()
	unlock, lockErr := lockScan(context.Background(), stateDir)
	if lockErr != nil {
		t.Fatal(lockErr)
	}
	done := make(chan error, 1)
	go func() { done <- work() }()
	select {
	case err = <-done:
		unlock()
		return true, err
	case <-time.After(700 * time.Millisecond):
	}
	unlock()
	select {
	case err = <-done:
		return false, err
	case <-time.After(60 * time.Second):
		t.Fatal("work did not finish after the scan lock was released")
	}
	return false, nil
}

func scanLockFixture(t *testing.T) (*fixture, string) {
	t.Helper()
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	if err := os.MkdirAll(filepath.Join(root, "project"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n")
	paths, err := config.ResolvePaths(config.MapLookup(f.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	return f, paths.StateDir
}

// A scheduled cycle scans, plans and applies against its own scan. A watcher
// scan recorded in between made apply refuse the plan (#50), so the cycle
// waits for any scan in progress before starting its own.
func TestCycleWaitsForTheScanLock(t *testing.T) {
	f, stateDir := scanLockFixture(t)
	var stderr string
	early, _ := runsHeld(t, stateDir, func() error {
		_, errOut, code := f.run(t, "cycle")
		stderr = errOut
		if code != ExitOK {
			return &usageError{msg: errOut}
		}
		return nil
	})
	if early {
		t.Fatal("cycle ran while another scan held the scan lock")
	}
	if stderr != "" {
		t.Fatalf("cycle failed after the lock was released: %s", stderr)
	}
}

// The watcher waits for a cycle's scan, plan and apply to finish before
// recording its own scan.
func TestWatcherScanWaitsForTheScanLock(t *testing.T) {
	f, stateDir := scanLockFixture(t)
	e := &env{opts: &globalOpts{format: "json"}, stdout: &bytes.Buffer{}, stderr: io.Discard, lookup: config.MapLookup(f.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	early, err := runsHeld(t, stateDir, func() error {
		return reconcileWatch(context.Background(), e, paths, policy, "startup", nil, true, 0)
	})
	if early {
		t.Fatal("watcher scanned while a cycle held the scan lock")
	}
	if err != nil {
		t.Fatalf("watcher scan failed after the lock was released: %v", err)
	}
}
