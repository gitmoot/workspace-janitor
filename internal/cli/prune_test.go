package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func TestApprovedOfficialPrunePreviewsThenRunsInFixture(t *testing.T) {
	f := newFixture(t)
	workspace := filepath.Join(f.home, "workspace")
	cache := filepath.Join(workspace, ".cache", "uv")
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "unused"), []byte("cached"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(workspace, "uv")
	marker := filepath.Join(workspace, "invoked")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \""+marker+"\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	services := filepath.Join(workspace, "services")
	if err := os.Mkdir(services, 0700); err != nil {
		t.Fatal(err)
	}
	proc := filepath.Join(workspace, "proc")
	if err := os.Mkdir(proc, 0700); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, "roots:\n  - path: "+workspace+"\n    max_depth: 2\ncollectors:\n  git: false\n  processes: false\n  services: false\n  proc_root: "+proc+"\n  systemd_dirs:\n    - "+services+"\n  cron_paths: []\n  pm2_dumps: []\n  deep_size: true\ncaches:\n  - name: uv\n    path: "+cache+"\n    action: delete_candidate\n    dedicated: true\n    official_binary: "+binary+"\n")
	if _, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("fixture scan: %d %s", code, stderr)
	}
	var doc planDocument
	stdout, stderr, code := f.run(t, "--format", "json", "plan", "--no-jev")
	if code != ExitOK || json.Unmarshal([]byte(stdout), &doc) != nil {
		t.Fatalf("plan: %d %s %s", code, stderr, stdout)
	}
	var chosen core.Action
	for _, candidate := range doc.Data.Plan.Actions {
		if candidate.Path == cache {
			chosen = candidate
			break
		}
	}
	if chosen.Kind != core.ActionDeleteCandidate {
		t.Fatalf("cache not approved for provider path: %+v", chosen)
	}
	if _, stderr, code := f.run(t, "plan", "--plan", doc.Data.Plan.ID, "--approve", chosen.ID, "--no-jev"); code != ExitOK {
		t.Fatalf("approve: %d %s", code, stderr)
	}
	stdout, stderr, code = f.run(t, "--format", "json", "apply", "--prune", "--action", chosen.ID)
	var preview struct {
		Data pruneReport `json:"data"`
	}
	if code != ExitOK || json.Unmarshal([]byte(stdout), &preview) != nil || preview.Data.Status != "preview" {
		t.Fatalf("prune preview: %d %s %s", code, stderr, stdout)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("dry-run invoked provider: %v", err)
	}
	stdout, stderr, code = f.run(t, "--format", "json", "apply", "--prune", "--action", chosen.ID, "--confirm", "--dry-run=false")
	var completed struct {
		Data pruneReport `json:"data"`
	}
	if code != ExitOK || json.Unmarshal([]byte(stdout), &completed) != nil ||
		!strings.Contains(stderr, "official prune (irreversible)") || !strings.HasPrefix(completed.Data.Status, "completed;") {
		t.Fatalf("prune: %d %s %s", code, stderr, stdout)
	}
	args, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if string(args) != "cache\nprune\n--cache-dir\n"+cache+"\n--offline\n" {
		t.Fatalf("wrong provider argv: %q", args)
	}
	if _, err := os.Stat(filepath.Join(cache, "unused")); err != nil {
		t.Fatalf("test provider unexpectedly deleted source: %v", err)
	}
	journal, err := os.ReadFile(filepath.Join(f.home, ".local", "state", "workspace-janitor", "official-prunes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(journal), `"status":"starting"`) || !strings.Contains(string(journal), `"status":"completed;`) {
		t.Fatalf("missing durable result: %s", journal)
	}
}
