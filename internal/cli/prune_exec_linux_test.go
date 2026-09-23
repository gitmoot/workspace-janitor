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

func TestOfficialPruneRunnerBoundsAndRecords(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "uv")
	argsFile := filepath.Join(root, "args")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \""+argsFile+"\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := executeOfficialPrune(context.Background(), []string{binary, "cache", "prune", "--offline"}, time.Second); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(args) != "cache\nprune\n--offline\n" {
		t.Fatalf("provider saw wrong argv: %q", args)
	}
	report := pruneReport{Mode: "official_prune", Path: filepath.Join(root, "cache"), Status: "starting", Timestamp: time.Now().UTC()}
	if err := recordOfficialPrune(root, report); err != nil {
		t.Fatal(err)
	}
	report.Status = "completed"
	if err := recordOfficialPrune(root, report); err != nil {
		t.Fatal(err)
	}
	journal, err := os.ReadFile(filepath.Join(root, "official-prunes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(journal), `"status":"starting"`) || !strings.Contains(string(journal), `"status":"completed"`) {
		t.Fatalf("missing durable phases: %s", journal)
	}
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
