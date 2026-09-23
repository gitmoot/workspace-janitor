//go:build linux

package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// This fixture exercises the public CLI path, not the collectors or action
// engine directly. Every readable location and every mutation stays under its
// temporary home; neither procfs nor host services nor Gitmoot are consulted.
func TestReleaseReadinessFixtureWorkflow(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	canonical := filepath.Join(root, "repos", "app")
	dirty := filepath.Join(root, "dirty")
	active := filepath.Join(root, "active")
	service := filepath.Join(root, "service")
	cache := filepath.Join(root, ".cache")
	artifact := filepath.Join(root, "dist")
	backup := filepath.Join(root, "backups")
	outside := filepath.Join(f.home, "outside-root")
	proc := filepath.Join(f.home, "proc", "4242")
	units := filepath.Join(f.home, "units")
	for _, dir := range []string{canonical, dirty, active, service, cache, artifact, backup, outside, proc, units} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(cache, "payload"):    "recover me",
		filepath.Join(artifact, "bundle"):  "generated",
		filepath.Join(backup, "archive"):   "retain",
		filepath.Join(outside, "sentinel"): "outside root must survive",
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{canonical, dirty} {
		fixtureGitRepo(t, f.home, dir)
	}
	if err := os.WriteFile(filepath.Join(dirty, "tracked"), []byte("uncommitted"), 0600); err != nil {
		t.Fatal(err)
	}
	// A repository may request an executable fsmonitor hook during an
	// otherwise read-only git status. The collector must not run it.
	hookMarker := filepath.Join(f.home, "fsmonitor-ran")
	hook := filepath.Join(f.home, "fsmonitor.sh")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nprintf attack > "+hookMarker+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", dirty, "config", "core.fsmonitor", hook)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + f.home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("configure malicious fixture: %v %s", err, out)
	}
	if err := os.Symlink(active, filepath.Join(proc, "cwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "comm"), []byte("fixture-worker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "cmdline"), []byte("not-to-be-read SECRET_FIXTURE_TOKEN"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(units, "fixture.service"), []byte("[Service]\nWorkingDirectory="+service+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "outside-link")); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, strings.Join([]string{
		"roots:", "  - path: " + root, "    max_depth: 2",
		"canonical_roots:", "  - class: primary_project", "    path: " + filepath.Dir(canonical),
		"collectors:", "  git: true", "  processes: true", "  services: true",
		"  proc_root: " + filepath.Dir(proc), "  systemd_dirs:", "    - " + units,
		"  cron_paths: []", "  pm2_dumps: []",
		"safety:", "  min_free_bytes: 0", "", // fixture disk headroom cannot gate the test
	}, "\n"))

	run := func(args ...string) string {
		t.Helper()
		out, stderr, code := f.run(t, args...)
		if code != ExitOK {
			t.Fatalf("janitor %v: exit=%d stderr=%s stdout=%s", args, code, stderr, out)
		}
		return out
	}
	var scan scanDocument
	if out := run("--format", "json", "scan"); json.Unmarshal([]byte(out), &scan) != nil || !scan.Data.Persisted {
		t.Fatalf("fixture scan failed: %+v %q", scan, out)
	} else if strings.Contains(out, "SECRET_FIXTURE_TOKEN") {
		t.Fatal("process command-line secret escaped into inventory")
	}
	if _, err := os.Lstat(hookMarker); !os.IsNotExist(err) {
		t.Fatalf("Git collector executed repository-supplied fsmonitor: %v", err)
	}
	entry := func(path string) core.Entry {
		t.Helper()
		for _, candidate := range scan.Data.Entries {
			if candidate.Path == path {
				return candidate
			}
		}
		t.Fatalf("scan did not inventory %s", path)
		return core.Entry{}
	}
	protectedBy := func(path string, kind core.ProtectionKind) {
		t.Helper()
		for _, protection := range entry(path).Protections {
			if protection.Kind == kind {
				return
			}
		}
		t.Fatalf("%s not protected by %s: %+v", path, kind, entry(path).Protections)
	}
	for _, path := range []string{canonical, dirty, active, service, cache, artifact, backup, filepath.Join(root, "outside-link")} {
		entry(path)
	}
	protectedBy(dirty, core.ProtectDirtyRepository)
	protectedBy(active, core.ProtectActiveProcess)
	protectedBy(service, core.ProtectServiceReference)
	protectedBy(filepath.Join(root, "outside-link"), core.ProtectSymlinkEscape)

	var planned planDocument
	if out := run("--format", "json", "plan", "--no-jev"); json.Unmarshal([]byte(out), &planned) != nil {
		t.Fatalf("invalid plan: %s", out)
	}
	actionAt := func(path string) core.Action {
		t.Helper()
		for _, action := range planned.Data.Plan.Actions {
			if action.Path == path {
				return action
			}
		}
		t.Fatalf("plan omitted %s", path)
		return core.Action{}
	}
	if candidate := actionAt(cache); candidate.Kind != core.ActionQuarantine {
		t.Fatalf("fixture cache is not a quarantine candidate: %+v", candidate)
	}
	for _, path := range []string{canonical, dirty, active, service, backup, filepath.Join(root, "outside-link")} {
		if action := actionAt(path); action.Kind.Mutating() {
			t.Fatalf("protected or durable path proposed mutation: %+v", action)
		}
	}
	if action := actionAt(artifact); action.Kind != core.ActionQuarantine {
		t.Fatalf("generated artifact not reversible quarantine candidate: %+v", action)
	}
	cacheAction := actionAt(cache)
	run("plan", "--plan", planned.Data.Plan.ID, "--approve", cacheAction.ID, "--no-jev")
	var preview struct {
		Data cleanupReport `json:"data"`
	}
	if out := run("--format", "json", "apply", "--quarantine", "--action", cacheAction.ID); json.Unmarshal([]byte(out), &preview) != nil || !preview.Data.DryRun {
		t.Fatalf("quarantine preview unavailable: %s", out)
	}
	if _, err := os.Lstat(cache); err != nil {
		t.Fatalf("preview mutated cache: %v", err)
	}

	// The approved inode is swapped for a symlink to a directory outside the
	// root. A stale approval cannot be interpreted as authority to move it.
	held := filepath.Join(f.home, "held-cache")
	if err := os.Rename(cache, held); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, cache); err != nil {
		t.Fatal(err)
	}
	_, _, code := f.run(t, "apply", "--quarantine", "--action", cacheAction.ID, "--confirm", "--dry-run=false")
	if code != ExitError {
		t.Fatalf("stale plan moved a swapped symlink: exit=%d", code)
	}
	if content, err := os.ReadFile(filepath.Join(outside, "sentinel")); err != nil || string(content) != "outside root must survive" {
		t.Fatalf("outside content changed: %q %v", content, err)
	}
	if err := os.Remove(cache); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(held, cache); err != nil {
		t.Fatal(err)
	}

	var applied struct {
		Data cleanupReport `json:"data"`
	}
	out, stderr, code := f.run(t, "--format", "json", "apply", "--quarantine", "--action", cacheAction.ID, "--confirm", "--dry-run=false")
	if code != ExitError || json.Unmarshal([]byte(out), &applied) != nil || len(applied.Data.Items) != 1 || len(applied.Data.Errors) == 0 {
		t.Fatalf("stale receipt was reported successful: exit=%d stderr=%s stdout=%s", code, stderr, out)
	}
	if applied.Data.Items[0].State != core.CleanupInvestigate {
		t.Fatalf("stale approval silently resumed after a path swap: %+v", applied.Data.Items[0])
	}
	if _, err := os.Lstat(cache); err != nil {
		t.Fatalf("investigation moved the restored source: %v", err)
	}
	// Explicitly close the investigated receipt with restore before a fresh
	// plan can claim this source. The store forbids two active receipts for it.
	run("restore", "--confirm", applied.Data.ID)
	// An investigated receipt is deliberately not retryable on the same
	// approval. Observe and approve the recovered path again.
	run("scan")
	planned = planDocument{}
	if out := run("--format", "json", "plan", "--no-jev"); json.Unmarshal([]byte(out), &planned) != nil {
		t.Fatalf("invalid recovery plan: %s", out)
	}
	cacheAction = actionAt(cache)
	run("plan", "--plan", planned.Data.Plan.ID, "--approve", cacheAction.ID, "--no-jev")
	applied = struct {
		Data cleanupReport `json:"data"`
	}{}
	if out := run("--format", "json", "apply", "--quarantine", "--action", cacheAction.ID, "--confirm", "--dry-run=false"); json.Unmarshal([]byte(out), &applied) != nil || len(applied.Data.Items) != 1 || applied.Data.Items[0].State != core.CleanupQuarantined {
		t.Fatalf("freshly approved quarantine failed: %s", out)
	}
	if _, err := os.Lstat(cache); !os.IsNotExist(err) {
		t.Fatalf("quarantined cache remains at source: %v", err)
	}
	if _, err := os.Stat(applied.Data.Items[0].Destination); err != nil {
		t.Fatalf("receipt destination missing: %v", err)
	}
	if out := run("--format", "json", "restore", applied.Data.ID); !strings.Contains(out, "\"restore\"") {
		t.Fatalf("restore preview unavailable: %s", out)
	}
	if _, err := os.Lstat(cache); !os.IsNotExist(err) {
		t.Fatalf("restore preview mutated cache: %v", err)
	}
	run("restore", "--confirm", applied.Data.ID)
	if content, err := os.ReadFile(filepath.Join(cache, "payload")); err != nil || string(content) != "recover me" {
		t.Fatalf("restored cache content differs: %q %v", content, err)
	}
	if content, err := os.ReadFile(filepath.Join(outside, "sentinel")); err != nil || string(content) != "outside root must survive" {
		t.Fatalf("outside fixture changed: %q %v", content, err)
	}
}

func fixtureGitRepo(t *testing.T, home, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"-C", dir, "init", "-q"},
		{"-C", dir, "add", "tracked"},
		{"-C", dir, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"},
	} {
		if args[2] == "add" {
			if err := os.WriteFile(filepath.Join(dir, "tracked"), []byte("committed"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("git", args...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture git %v: %v %s", args, err, out)
		}
	}
}
