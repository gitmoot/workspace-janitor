//go:build linux

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func TestQuarantineDryRunEstimatesUniqueAllocatedBytes(t *testing.T) {
	f := newFixture(t)
	workspace := filepath.Join(f.home, "workspace")
	cache := filepath.Join(workspace, ".cache", "uv")
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(cache, "shared")
	if err := os.WriteFile(file, []byte("cache entry"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, filepath.Join(workspace, "outside")); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, "roots:\n  - path: "+workspace+"\n    max_depth: 2\ncaches:\n  - name: uv\n    path: "+cache+"\n    action: quarantine\n")
	if _, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("scan: %s", stderr)
	}
	stdout, stderr, code := f.run(t, "--format", "json", "plan", "--no-jev")
	var doc planDocument
	if code != ExitOK || json.Unmarshal([]byte(stdout), &doc) != nil {
		t.Fatalf("plan: %s %s", stderr, stdout)
	}
	var chosen core.Action
	for _, candidate := range doc.Data.Plan.Actions {
		if candidate.Path == cache {
			chosen = candidate
			break
		}
	}
	if chosen.Kind != core.ActionQuarantine {
		t.Fatalf("expected cache quarantine, got %+v", chosen)
	}
	if _, stderr, code := f.run(t, "plan", "--plan", doc.Data.Plan.ID, "--approve", chosen.ID); code != ExitOK {
		t.Fatalf("approve: %s", stderr)
	}
	stdout, stderr, code = f.run(t, "--format", "json", "apply", "--quarantine", "--action", chosen.ID)
	var preview struct {
		Data struct {
			Expected *struct {
				Bytes  int64 `json:"bytes"`
				Shared int   `json:"shared_inodes"`
			} `json:"expected_reclaim"`
			Unavailable string `json:"estimate_unavailable"`
		} `json:"data"`
	}
	if code != ExitOK || json.Unmarshal([]byte(stdout), &preview) != nil {
		t.Fatalf("preview: %s %s", stderr, stdout)
	}
	if preview.Data.Expected == nil {
		t.Fatalf("expected known allocated-block estimate, got %q", preview.Data.Unavailable)
	}
	info, err := os.Lstat(cache)
	if err != nil {
		t.Fatal(err)
	}
	want := info.Sys().(*syscall.Stat_t).Blocks * 512
	if preview.Data.Expected.Bytes != want || preview.Data.Expected.Shared != 1 {
		t.Fatalf("preview = %+v, want %d excluding external hardlink", preview.Data.Expected, want)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("dry-run moved source: %v", err)
	}
}
