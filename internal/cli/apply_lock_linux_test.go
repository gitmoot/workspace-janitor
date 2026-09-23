//go:build linux

package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

const lockChildHome = "JANITOR_TEST_LOCK_HOME"

func TestApplyLockRejectsSecondProcess(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: false\n")
	if _, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("scan: %s", stderr)
	}
	paths, err := config.ResolvePaths(config.MapLookup(f.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockApply(paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestApplyLockChild$")
	child.Env = append(os.Environ(), lockChildHome+"="+f.home)
	if output, err := child.CombinedOutput(); err != nil {
		unlock()
		t.Fatalf("second process bypassed lock: %v %s", err, output)
	}
	unlock()
	_, stderr, code := f.run(t, "apply", "--expire", "--confirm", "--dry-run=false")
	if code != ExitError || !strings.Contains(stderr, "deletion is disabled by policy") {
		t.Fatalf("lock did not release for next process: exit=%d %s", code, stderr)
	}
}

func TestApplyLockChild(t *testing.T) {
	home := os.Getenv(lockChildHome)
	if home == "" {
		return
	}
	var stderr bytes.Buffer
	code := Run(context.Background(), Options{Args: []string{"apply", "--expire", "--confirm", "--dry-run=false"},
		Stdout: &bytes.Buffer{}, Stderr: &stderr, Lookup: config.MapLookup(map[string]string{config.EnvHome: home})})
	if code != ExitError || !strings.Contains(stderr.String(), "another janitor apply or restore is active") {
		t.Fatalf("concurrent apply not refused: exit=%d %s", code, stderr.String())
	}
}
