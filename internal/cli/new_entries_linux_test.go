//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The test reads the published JSON, not the implementation's types.
type newEntriesTestReport struct {
	Status  string `json:"status"`
	ScanID  string `json:"scan_id"`
	Total   int    `json:"total"`
	Entries []newEntriesTestEntry
}

type newEntriesTestEntry struct {
	Path          string     `json:"path"`
	Type          string     `json:"type"`
	CreatedAt     *time.Time `json:"created_at"`
	ApparentBytes *int64     `json:"apparent_bytes"`
	Attributions  []struct {
		Source string `json:"source"`
		Value  string `json:"value"`
	} `json:"attributions"`
}

type newEntriesDocument struct {
	Data struct {
		Inventory struct {
			NewEntries *newEntriesTestReport `json:"new_entries"`
		} `json:"inventory_report"`
	} `json:"data"`
}

func newEntriesStatus(t *testing.T, f *scanFixture) *newEntriesTestReport {
	t.Helper()
	out, stderr, code := f.run(t, "--format", "json", "status")
	if code != ExitOK {
		t.Fatalf("status failed: %s", stderr)
	}
	var doc newEntriesDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Data.Inventory.NewEntries == nil {
		t.Fatalf("status omitted new_entries for a report_new_entries root:\n%s", out)
	}
	return doc.Data.Inventory.NewEntries
}

func newEntryAt(t *testing.T, report *newEntriesTestReport, path string) newEntriesTestEntry {
	t.Helper()
	for _, entry := range report.Entries {
		if entry.Path == path {
			return entry
		}
	}
	t.Fatalf("new entry %s missing: %+v", path, report)
	return newEntriesTestEntry{}
}

func hasNewEntryAttribution(entry newEntriesTestEntry, source, value string) bool {
	for _, attribution := range entry.Attributions {
		if attribution.Source == source && attribution.Value == value {
			return true
		}
	}
	return false
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestNewRootEntriesListOnlyPathsAbsentFromBaseline(t *testing.T) {
	f := newScanFixture(t)
	fresh := filepath.Join(f.root, "fresh")
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    max_depth: 1\n    report_new_entries: true\ncollectors:\n  git: false\n  processes: false\n  services: false\nowners:\n  - path: %s\n    owner: builder\n", f.root, fresh))
	f.scanJSON(t, "--deep-size")
	mustMkdirAll(t, filepath.Join(fresh, "sub"))
	if err := os.WriteFile(filepath.Join(fresh, "sub", "data"), []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	latest := f.scanJSON(t, "--deep-size")
	report := newEntriesStatus(t, f)
	if report.Status != "compared" || report.ScanID != latest.Data.Scan.ID || report.Total != 1 || len(report.Entries) != 1 {
		t.Fatalf("want exactly the one new child against the baseline: %+v", report)
	}
	entry := newEntryAt(t, report, fresh)
	if entry.Type != "dir" || entry.CreatedAt == nil || entry.ApparentBytes == nil {
		t.Fatalf("new entry shape: %+v", entry)
	}
	if !hasNewEntryAttribution(entry, "policy_owner", "builder") {
		t.Fatalf("owners entry not attributed: %+v", entry.Attributions)
	}
}

func TestNewRootEntriesWithoutComparableBaselineListNothing(t *testing.T) {
	f := newScanFixture(t)
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    max_depth: 1\n    report_new_entries: true\ncollectors:\n  git: false\n  processes: false\n  services: false\n", f.root))
	f.scanJSON(t, "--deep-size")
	report := newEntriesStatus(t, f)
	if report.Status != "no_comparable_baseline" || report.Total != 0 || len(report.Entries) != 0 {
		t.Fatalf("a first scan flooded the report with every child: %+v", report)
	}
}

func TestNewRootEntriesNameLinkedWorktreeMainRepository(t *testing.T) {
	f := newScanFixture(t)
	repo := filepath.Join(f.home, "repo")
	mustMkdirAll(t, repo)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "HOME="+f.home, "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s %v", args, out, err)
		}
	}
	git("init", "-q")
	git("commit", "-q", "--allow-empty", "-m", "base")
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    max_depth: 1\n    report_new_entries: true\ncollectors:\n  git: true\n  processes: false\n  services: false\n", f.root))
	f.scanJSON(t, "--deep-size")
	linked := filepath.Join(f.root, "linked")
	git("worktree", "add", "-q", "-b", "linked", linked)
	f.scanJSON(t, "--deep-size")
	entry := newEntryAt(t, newEntriesStatus(t, f), linked)
	if entry.Type != "worktree" || !hasNewEntryAttribution(entry, "linked_worktree", repo) {
		t.Fatalf("linked worktree not attributed to %s: %+v", repo, entry)
	}
}

func TestNewRootEntriesNameLiveProcessSession(t *testing.T) {
	f := newScanFixture(t)
	fresh := filepath.Join(f.root, "fresh")
	proc := filepath.Join(f.home, "proc")
	process := func(pid, cwd string, argv ...string) {
		t.Helper()
		dir := filepath.Join(proc, pid)
		mustMkdirAll(t, dir)
		if err := os.Symlink(cwd, filepath.Join(dir, "cwd")); err != nil {
			t.Fatal(err)
		}
		cmdline := ""
		for _, arg := range argv {
			cmdline += arg + "\x00"
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(argv[0]+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustMkdirAll(t, proc)
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    max_depth: 1\n    report_new_entries: true\ncollectors:\n  git: false\n  processes: true\n  services: false\n  proc_root: %s\n", f.root, proc))
	f.scanJSON(t, "--deep-size")
	mustMkdirAll(t, filepath.Join(fresh, "sub"))
	process("4242", filepath.Join(fresh, "sub"), "omp", "--resume=/home/u/.omp/agent/sessions/-root-fresh/2026-11-15T00-00-00-000Z_x.jsonl")
	process("4343", fresh, "bash")
	process("4444", filepath.Join(f.root, "project"), "omp", "--resume=/home/u/.omp/agent/sessions/-root-project/s.jsonl")
	f.scanJSON(t, "--deep-size")
	entry := newEntryAt(t, newEntriesStatus(t, f), fresh)
	if !hasNewEntryAttribution(entry, "omp_session_process", "-root-fresh") || !hasNewEntryAttribution(entry, "process_cwd", "bash") {
		t.Fatalf("live processes in the new entry not attributed: %+v", entry.Attributions)
	}
	if hasNewEntryAttribution(entry, "omp_session_process", "-root-project") {
		t.Fatalf("a process outside the new entry was attributed: %+v", entry.Attributions)
	}
}
