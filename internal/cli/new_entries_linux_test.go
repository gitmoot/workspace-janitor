//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test reads the published JSON, not the implementation's types.
type newEntriesTestReport struct {
	Status      string   `json:"status"`
	ScanID      string   `json:"scan_id"`
	Total       int      `json:"total"`
	Attribution []string `json:"attribution"`
	Entries     []newEntriesTestEntry
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
	return decodeNewEntries(t, out, stderr, code)
}

func decodeNewEntries(t *testing.T, out, stderr string, code ExitCode) *newEntriesTestReport {
	t.Helper()
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

// fakeProcess adds a process to a fake procfs. Without argv it has no cmdline.
func fakeProcess(t *testing.T, proc, pid, cwd, exe string, argv ...string) {
	t.Helper()
	dir := filepath.Join(proc, pid)
	mustMkdirAll(t, dir)
	for name, target := range map[string]string{"cwd": cwd, "exe": exe} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(filepath.Base(exe)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(argv) == 0 {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// processFixture scans a report_new_entries root before and after fresh is
// created, with processes read from proc. extra is appended to the policy.
func processFixture(t *testing.T, extra string) (f *scanFixture, fresh, proc string) {
	t.Helper()
	f = newScanFixture(t)
	fresh = filepath.Join(f.root, "fresh")
	proc = filepath.Join(f.home, "proc")
	mustMkdirAll(t, proc)
	// Keep the root's listing within the smallest max_dir_entries used here.
	if err := os.Remove(filepath.Join(f.root, "notes.md")); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    max_depth: 1\n    report_new_entries: true\ncollectors:\n  git: false\n  processes: true\n  services: false\n  proc_root: %s\n%s", f.root, proc, extra))
	f.scanJSON(t, "--deep-size")
	mustMkdirAll(t, filepath.Join(fresh, "sub"))
	f.scanJSON(t, "--deep-size")
	return f, fresh, proc
}

func TestNewRootEntriesNameLiveProcessSession(t *testing.T) {
	f, fresh, proc := processFixture(t, "")
	fakeProcess(t, proc, "4242", filepath.Join(fresh, "sub"), "/usr/local/bin/omp", "omp", "--resume=/home/u/.omp/agent/sessions/-root-fresh/2026-11-15T00-00-00-000Z_x.jsonl")
	fakeProcess(t, proc, "4343", fresh, "/usr/bin/bash", "bash")
	fakeProcess(t, proc, "4444", filepath.Join(f.root, "project"), "/usr/local/bin/omp", "omp", "--resume=/home/u/.omp/agent/sessions/-root-project/s.jsonl")
	entry := newEntryAt(t, newEntriesStatus(t, f), fresh)
	if !hasNewEntryAttribution(entry, "omp_session_process", "-root-fresh") || !hasNewEntryAttribution(entry, "process_cwd", "bash") {
		t.Fatalf("live processes in the new entry not attributed: %+v", entry.Attributions)
	}
	if hasNewEntryAttribution(entry, "omp_session_process", "-root-project") {
		t.Fatalf("a process outside the new entry was attributed: %+v", entry.Attributions)
	}
}

func TestNewRootEntriesResumeArgumentOfOtherProgramIsNoSession(t *testing.T) {
	f, fresh, proc := processFixture(t, "")
	fakeProcess(t, proc, "4242", fresh, "/usr/bin/python3", "python3", "train.py", "--resume=/models/x/checkpoint.jsonl")
	entry := newEntryAt(t, newEntriesStatus(t, f), fresh)
	if hasNewEntryAttribution(entry, "omp_session_process", "x") || !hasNewEntryAttribution(entry, "process_cwd", "python3") {
		t.Fatalf("a non-OMP --resume argument was read as an OMP session: %+v", entry.Attributions)
	}
}

func TestNewRootEntriesRequireDeepBaseline(t *testing.T) {
	f := newScanFixture(t)
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    max_depth: 1\n    report_new_entries: true\ncollectors:\n  git: false\n  processes: false\n  services: false\n", f.root))
	f.scanJSON(t)
	mustMkdirAll(t, filepath.Join(f.root, "fresh"))
	f.scanJSON(t)
	report := newEntriesStatus(t, f)
	if report.Status == "compared" || report.Total != 0 || len(report.Entries) != 0 {
		t.Fatalf("metadata-only scans served as the new-entry baseline: %+v", report)
	}
}

func TestNewRootEntriesProcessAttributionHonoursMaxDirEntries(t *testing.T) {
	f, fresh, proc := processFixture(t, "limits:\n  max_dir_entries: 2\n")
	for _, pid := range []string{"4241", "4242", "4243", "4244", "4245"} {
		fakeProcess(t, proc, pid, fresh, "/usr/bin/worker"+pid, "worker"+pid)
	}
	report := newEntriesStatus(t, f)
	processes := 0
	for _, attribution := range newEntryAt(t, report, fresh).Attributions {
		if attribution.Source == "process_cwd" {
			processes++
		}
	}
	if processes > 2 || !strings.Contains(strings.Join(report.Attribution, "\n"), "incomplete") {
		t.Fatalf("process attribution ignored max_dir_entries 2 (%d processes) or hid the bound: %v", processes, report.Attribution)
	}
}

func TestNewRootEntriesProcessAttributionCannotBlockOnFIFO(t *testing.T) {
	for _, fifo := range []string{"cmdline", "comm"} {
		t.Run(fifo, func(t *testing.T) {
			f, fresh, proc := processFixture(t, "limits:\n  command_timeout: 100ms\n")
			fakeProcess(t, proc, "4242", fresh, "/usr/local/bin/omp")
			if fifo == "comm" {
				if err := os.Remove(filepath.Join(proc, "4242", "comm")); err != nil {
					t.Fatal(err)
				}
			}
			if err := syscall.Mkfifo(filepath.Join(proc, "4242", fifo), 0o600); err != nil {
				t.Fatal(err)
			}
			type result struct {
				out, stderr string
				code        ExitCode
			}
			done := make(chan result, 1)
			go func() {
				out, stderr, code := f.run(t, "--format", "json", "status")
				done <- result{out, stderr, code}
			}()
			select {
			case got := <-done:
				report := decodeNewEntries(t, got.out, got.stderr, got.code)
				switch {
				// A command line that cannot be read without blocking is
				// skipped; the process is still attributed.
				case fifo == "cmdline" && !hasNewEntryAttribution(newEntryAt(t, report, fresh), "process_cwd", "omp"):
					t.Fatalf("process with an unreadable command line lost its attribution: %+v", report)
				// A blocked read hits the command timeout and says so.
				case fifo == "comm" && !strings.Contains(strings.Join(report.Attribution, "\n"), "incomplete"):
					t.Fatalf("timed-out process attribution not reported incomplete: %v", report.Attribution)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("status blocked on a FIFO %s", fifo)
			}
		})
	}
}
