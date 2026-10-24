//go:build linux

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOfficialPruneRunnerBoundsSubprocessGroup(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "uv")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nsleep 10 &\nwait\n"), 0700); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := executeOfficialPrune(context.Background(), []string{binary, "cache"}, 100*time.Millisecond); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("expected deadline, got %v", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("subprocess group outlived its bound")
	}
}
