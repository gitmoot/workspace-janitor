//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/store"
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
	"golang.org/x/sys/unix"
)

// scratchFixture is an isolated home with one inventory root, a scratch
// directory outside it, a protected archive directory and a fixture procfs.
type scratchFixture struct {
	*fixture
	work, scratch, archive, proc string
	// extra is appended at the top level, limits under limits: and
	// options under the scratch_cleanup entry.
	extra, limits, options string
}

func newScratchFixture(t *testing.T) *scratchFixture {
	t.Helper()
	f := newFixture(t)
	home, err := filepath.EvalSymlinks(f.home)
	if err != nil {
		t.Fatal(err)
	}
	f.home, f.env[config.EnvHome] = home, home
	x := &scratchFixture{fixture: f, work: filepath.Join(home, "work"), scratch: filepath.Join(home, "scratch"),
		archive: filepath.Join(home, "archive"), proc: filepath.Join(home, "proc")}
	for _, dir := range []string{x.work, x.scratch, x.archive, x.proc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	x.write(t)
	// Every fixture entry is created now and its ctime cannot be moved
	// back, so idle ages are measured on a clock two days ahead.
	x.shift(t, 48*time.Hour)
	return x
}

func (x *scratchFixture) shift(t *testing.T, by time.Duration) {
	t.Helper()
	previous := scratchNow
	scratchNow = func() time.Time { return time.Now().UTC().Add(by) }
	t.Cleanup(func() { scratchNow = previous })
}

func (x *scratchFixture) write(t *testing.T) {
	t.Helper()
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
    max_depth: 1
protect:
  paths: [%s]
  name_patterns: ["*token*", "notes.private"]
collectors:
  proc_root: %s
  systemd_dirs: []
  cron_paths: []
  pm2_dumps: []
prevention:
  min_free_bytes: 0
  min_free_percent: 0
limits:
  command_timeout: 30s
%sscratch_cleanup:
  - path: %s
    idle: 24h
    every: 48h
    skip: ["keep-me-*", "tmux-*"]
    regenerable: ["go-build*", "bunx-*"]
    archive:
      directory: %s
%s%s`, x.work, x.archive, x.proc, x.limits, x.scratch, x.archive, x.options, x.extra))
}

func (x *scratchFixture) entry(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	path := filepath.Join(x.scratch, name)
	if files == nil {
		if err := os.WriteFile(path, []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	for file, data := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(path, file)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, file), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func (x *scratchFixture) cleanup(t *testing.T, act bool) (scratchRunReport, string, ExitCode) {
	t.Helper()
	args := []string{"--format", "json", "scratch"}
	if act {
		args = append(args, "--dry-run=false", "--confirm")
	}
	out, stderr, code := x.run(t, args...)
	var doc struct {
		Data scratchReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Data.Runs) != 1 {
		t.Fatalf("%v: exit=%d %v\nstdout=%s\nstderr=%s", args, code, err, out, stderr)
	}
	return doc.Data.Runs[0], stderr, code
}

func (x *scratchFixture) mustCleanup(t *testing.T, act bool) scratchRunReport {
	t.Helper()
	report, stderr, code := x.cleanup(t, act)
	if code != ExitOK {
		t.Fatalf("scratch: exit=%d %s %+v", code, stderr, report)
	}
	return report
}

func scratchStatus(t *testing.T, report scratchRunReport, entry string) scratchItem {
	t.Helper()
	for _, item := range report.Items {
		if item.Entry == entry {
			return item
		}
	}
	t.Fatalf("%s missing from the scratch report: %+v", entry, report.Items)
	return scratchItem{}
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func (x *scratchFixture) deletions(t *testing.T, runID string) []store.ScratchDeletion {
	t.Helper()
	db, err := store.OpenExisting(context.Background(), x.paths(t).DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var out []store.ScratchDeletion
	if err := db.Read(context.Background(), func(tx *store.Tx) error {
		var err error
		out, err = tx.ScratchDeletions(context.Background(), runID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (x *scratchFixture) paths(t *testing.T) config.Paths {
	t.Helper()
	paths, err := config.ResolvePaths(config.MapLookup(x.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

// Skip globs are never touched, regenerable globs are deleted without an
// archive, everything else idle is archived and verified before deletion,
// and the preview changes nothing.
func TestScratchHonorsSkipAndRegenerableFromPolicy(t *testing.T) {
	x := newScratchFixture(t)
	skipped := x.entry(t, "keep-me-1", map[string]string{"a": "keep\n"})
	regen := x.entry(t, "go-build123", map[string]string{"b/c.a": "object\n"})
	plain := x.entry(t, "plain", map[string]string{"report.txt": "payload\n", "nested/data.bin": "data\n"})
	file := x.entry(t, "loose.log", nil)

	preview := x.mustCleanup(t, false)
	for name, want := range map[string]string{"keep-me-1": scratchSkipped, "go-build123": scratchWouldDelete, "plain": scratchWouldArchive, "loose.log": scratchWouldArchive} {
		if got := scratchStatus(t, preview, name); got.Status != want {
			t.Errorf("preview %s = %+v, want %s", name, got, want)
		}
	}
	for _, path := range []string{skipped, regen, plain, file} {
		if !exists(t, path) {
			t.Fatalf("preview removed %s", path)
		}
	}
	if entries, _ := os.ReadDir(x.archive); len(entries) != 0 {
		t.Fatalf("preview wrote %d archive files", len(entries))
	}

	report := x.mustCleanup(t, true)
	if report.Status != "completed" || report.Archive == nil || report.Archived != 2 || report.Deleted != 1 {
		t.Fatalf("run = %+v", report)
	}
	if !exists(t, skipped) || exists(t, regen) || exists(t, plain) || exists(t, file) {
		t.Fatalf("after the run: skip kept=%v regenerable kept=%v plain kept=%v file kept=%v", exists(t, skipped), exists(t, regen), exists(t, plain), exists(t, file))
	}
	archived := append([]string(nil), report.Archive.Entries...)
	sort.Strings(archived)
	if strings.Join(archived, ",") != "loose.log,plain" {
		t.Fatalf("archive entries = %v, want only the non-regenerable entries", report.Archive.Entries)
	}
	dispositions := map[string]string{}
	for _, deletion := range x.deletions(t, report.RunID) {
		dispositions[deletion.Entry] = deletion.Disposition
	}
	if dispositions["go-build123"] != store.ScratchRegenerable || dispositions["plain"] != store.ScratchArchived || dispositions["loose.log"] != store.ScratchArchived || len(dispositions) != 3 {
		t.Fatalf("deletion receipts = %v", dispositions)
	}
}

// A sensitive name anywhere inside an entry (file or directory, built-in or
// from protect.name_patterns, in any letter case) keeps the whole entry
// local: neither archived nor deleted, even when it is regenerable. So do
// fifos, at the top or inside.
func TestScratchSensitiveNamesAndFifosKeepEntriesLocal(t *testing.T) {
	x := newScratchFixture(t)
	builtin := x.entry(t, "deploy", map[string]string{"deep/certs/server.pem": "-----BEGIN-----\n"})
	policyDir := x.entry(t, "stash", map[string]string{"MyTOKEN-cache/value": "abc\n"})
	policyFile := x.entry(t, "bunx-123", map[string]string{"sub/notes.private": "x\n"})
	fifoInside := x.entry(t, "pipes", map[string]string{"readme": "x\n"})
	if err := unix.Mkfifo(filepath.Join(fifoInside, "ctl"), 0o600); err != nil {
		t.Fatal(err)
	}
	fifoTop := filepath.Join(x.scratch, "fifo")
	if err := unix.Mkfifo(fifoTop, 0o600); err != nil {
		t.Fatal(err)
	}
	plain := x.entry(t, "plain", map[string]string{"a": "a\n"})

	report := x.mustCleanup(t, true)
	for path, reason := range map[string]string{builtin: "sensitive", policyDir: "sensitive", policyFile: "sensitive", fifoInside: "unsupported", fifoTop: ""} {
		item := scratchStatus(t, report, filepath.Base(path))
		if item.Status != scratchKept || !strings.Contains(item.Reason, reason) || !exists(t, path) {
			t.Errorf("%s = %+v (exists=%v), want kept for %q", path, item, exists(t, path), reason)
		}
	}
	if exists(t, plain) || report.Archive == nil || strings.Join(report.Archive.Entries, ",") != "plain" {
		t.Fatalf("only plain should be archived and removed: %+v", report.Archive)
	}
}

// An entry a process uses (here as its working directory) is kept; one
// changed within idle is kept.
func TestScratchKeepsInUseAndRecentlyChangedEntries(t *testing.T) {
	x := newScratchFixture(t)
	live := x.entry(t, "live", map[string]string{"a": "a\n"})
	pid := filepath.Join(x.proc, "424242")
	if err := os.MkdirAll(pid, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(live, "a"), filepath.Join(pid, "cwd")); err != nil {
		t.Fatal(err)
	}
	report := x.mustCleanup(t, true)
	if item := scratchStatus(t, report, "live"); item.Status != scratchKept || !strings.Contains(item.Reason, "in use") || !exists(t, live) {
		t.Fatalf("in-use entry = %+v", item)
	}

	// On the real clock every fixture entry changed moments ago.
	x.shift(t, 0)
	recent := x.entry(t, "recent", map[string]string{"a": "a\n"})
	report = x.mustCleanup(t, true)
	if item := scratchStatus(t, report, "recent"); item.Status != scratchKept || !strings.Contains(item.Reason, "changed") || !exists(t, recent) {
		t.Fatalf("recently changed entry = %+v", item)
	}
}

// A published archive that fails the read-back before deletion deletes
// nothing at all, regenerable entries included, and records no deletion.
func TestScratchArchiveMismatchDeletesNothing(t *testing.T) {
	x := newScratchFixture(t)
	plain := x.entry(t, "plain", map[string]string{"a": strings.Repeat("payload\n", 64)})
	regen := x.entry(t, "go-build9", map[string]string{"o": "obj\n"})
	previous := createScratchArchive
	t.Cleanup(func() { createScratchArchive = previous })
	createScratchArchive = func(dir *workspacearchive.ScratchDir, ctx context.Context, dest config.WorkspaceArchiveCategoryDestination, runID string, entries []workspacearchive.ScratchEntry, preflight func() error) (workspacearchive.ScratchManifest, *workspacearchive.Binding, error) {
		m, binding, err := previous(dir, ctx, dest, runID, entries, preflight)
		if err == nil {
			tarPath := filepath.Join(dest.Directory, m.TarFile)
			data, readErr := os.ReadFile(tarPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			// Damage file content past the first tar header.
			data[1024] ^= 0xff
			if writeErr := os.WriteFile(tarPath, data, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
		}
		return m, binding, err
	}
	report, stderr, code := x.cleanup(t, true)
	if code == ExitOK || report.Status != "failed" || !strings.Contains(stderr, "verification") {
		t.Fatalf("damaged archive: exit=%d %s %+v", code, stderr, report)
	}
	if !exists(t, plain) || !exists(t, regen) {
		t.Fatalf("a damaged archive deleted entries: plain=%v regenerable=%v", exists(t, plain), exists(t, regen))
	}
	if report.Archived != 0 || report.Deleted != 0 {
		t.Fatalf("report claims deletions: %+v", report)
	}
}

// An entry that changes after it was archived is kept, and the change is
// not lost; untouched entries of the same run are still removed.
func TestScratchEntryChangedAfterArchiveIsKept(t *testing.T) {
	x := newScratchFixture(t)
	changed := x.entry(t, "changed", map[string]string{"a": "before\n"})
	other := x.entry(t, "other", map[string]string{"b": "b\n"})
	previous := createScratchArchive
	t.Cleanup(func() { createScratchArchive = previous })
	createScratchArchive = func(dir *workspacearchive.ScratchDir, ctx context.Context, dest config.WorkspaceArchiveCategoryDestination, runID string, entries []workspacearchive.ScratchEntry, preflight func() error) (workspacearchive.ScratchManifest, *workspacearchive.Binding, error) {
		m, binding, err := previous(dir, ctx, dest, runID, entries, preflight)
		if writeErr := os.WriteFile(filepath.Join(changed, "a"), []byte("after the archive\n"), 0o644); writeErr != nil {
			t.Fatal(writeErr)
		}
		return m, binding, err
	}
	report := x.mustCleanup(t, true)
	if item := scratchStatus(t, report, "changed"); item.Status != scratchKept || !strings.Contains(item.Reason, "changed") {
		t.Fatalf("changed entry = %+v", item)
	}
	if data, err := os.ReadFile(filepath.Join(changed, "a")); err != nil || string(data) != "after the archive\n" {
		t.Fatalf("changed entry lost its change: %q %v", data, err)
	}
	if exists(t, other) {
		t.Fatal("the unchanged entry of the same run was not removed")
	}
}

// The cycle runs a scratch directory only when it is due: never run, or its
// last run started at least `every` ago.
func TestScratchCycleHonorsEvery(t *testing.T) {
	x := newScratchFixture(t)
	first := x.entry(t, "first", map[string]string{"a": "a\n"})
	cycle := func() []scratchRunReport {
		t.Helper()
		out, stderr, code := x.run(t, "cycle")
		if code != ExitOK {
			t.Fatalf("cycle: exit=%d %s %s", code, stderr, out)
		}
		var report struct {
			ScratchCleanup []scratchRunReport `json:"scratch_cleanup"`
		}
		if err := json.Unmarshal([]byte(out), &report); err != nil || len(report.ScratchCleanup) != 1 {
			t.Fatalf("cycle output: %v\n%s", err, out)
		}
		return report.ScratchCleanup
	}
	if runs := cycle(); runs[0].Status != "completed" || exists(t, first) {
		t.Fatalf("first cycle = %+v (first exists=%v)", runs[0], exists(t, first))
	}
	second := x.entry(t, "second", map[string]string{"a": "a\n"})
	if runs := cycle(); runs[0].Status != "not_due" || runs[0].NextDue == nil || !exists(t, second) {
		t.Fatalf("cycle within every = %+v (second exists=%v)", runs[0], exists(t, second))
	}
	x.shift(t, 48*time.Hour+49*time.Hour)
	if runs := cycle(); runs[0].Status != "completed" || exists(t, second) {
		t.Fatalf("cycle after every = %+v (second exists=%v)", runs[0], exists(t, second))
	}
}

// Without scratch_cleanup nothing changes: the command refuses, the cycle
// reports no scratch step and the directory is untouched.
func TestScratchDefaultPolicyDoesNothing(t *testing.T) {
	x := newScratchFixture(t)
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    max_depth: 1\ncollectors:\n  proc_root: %s\n  systemd_dirs: []\n  cron_paths: []\n  pm2_dumps: []\nprevention:\n  min_free_bytes: 0\n  min_free_percent: 0\n", x.work, x.proc))
	old := x.entry(t, "old", map[string]string{"a": "a\n"})
	if out, stderr, code := x.run(t, "scratch", "--dry-run=false", "--confirm"); code == ExitOK || !strings.Contains(stderr, "no scratch_cleanup") {
		t.Fatalf("scratch without policy: exit=%d %s %s", code, out, stderr)
	}
	out, stderr, code := x.run(t, "cycle")
	if code != ExitOK || strings.Contains(out, "scratch_cleanup") {
		t.Fatalf("cycle without scratch policy: exit=%d %s %s", code, out, stderr)
	}
	if !exists(t, old) {
		t.Fatal("default policy removed a scratch entry")
	}
}

// An archived entry restores byte for byte (directory with a symlink, and a
// single file) to its original path or elsewhere, never over an existing
// path.
func TestScratchRestoreRoundTrip(t *testing.T) {
	x := newScratchFixture(t)
	dir := x.entry(t, "project", map[string]string{"notes.txt": "hello\n", "deep/data.bin": strings.Repeat("z", 5000)})
	if err := os.Symlink("deep/data.bin", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	file := x.entry(t, "single.log", nil)
	report := x.mustCleanup(t, true)
	if exists(t, dir) || exists(t, file) || report.Archive == nil {
		t.Fatalf("entries not archived and removed: %+v", report)
	}
	restore := func(args ...string) (string, ExitCode) {
		out, stderr, code := x.run(t, append([]string{"--format", "json", "scratch", "restore", report.RunID}, args...)...)
		return out + stderr, code
	}
	if out, code := restore("project"); code != ExitOK || exists(t, dir) || !strings.Contains(out, `"verified"`) {
		t.Fatalf("restore preview: exit=%d %s", code, out)
	}
	if out, code := restore("project", "--dry-run=false", "--confirm"); code != ExitOK {
		t.Fatalf("restore: exit=%d %s", code, out)
	}
	for name, want := range map[string]string{"notes.txt": "hello\n", "deep/data.bin": strings.Repeat("z", 5000)} {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(data) != want {
			t.Fatalf("restored %s = %d bytes, %v", name, len(data), err)
		}
	}
	if target, err := os.Readlink(filepath.Join(dir, "link")); err != nil || target != "deep/data.bin" {
		t.Fatalf("restored symlink = %q %v", target, err)
	}
	if out, code := restore("project", "--dry-run=false", "--confirm"); code == ExitOK || !strings.Contains(out, "must not exist") {
		t.Fatalf("restore over an existing path: exit=%d %s", code, out)
	}
	elsewhere := filepath.Join(x.home, "restored.log")
	if out, code := restore("single.log", "--restore-to", elsewhere, "--dry-run=false", "--confirm"); code != ExitOK {
		t.Fatalf("file restore: exit=%d %s", code, out)
	}
	if data, err := os.ReadFile(elsewhere); err != nil || string(data) != "single.log\n" {
		t.Fatalf("restored file = %q %v", data, err)
	}
	if out, code := restore("never-archived", "--dry-run=false", "--confirm"); code == ExitOK {
		t.Fatalf("restore of an unarchived entry: %s", out)
	}
}

// A scratch directory has its own listing bound: one larger than
// limits.max_dir_entries (which bounds inventory scans) is still cleaned,
// and one larger than scratch max_entries is refused as a whole, with
// nothing deleted, instead of cleaning a partial listing.
func TestScratchMaxEntriesBoundsTheListing(t *testing.T) {
	x := newScratchFixture(t)
	x.limits, x.options = "  max_dir_entries: 3\n", "    max_entries: 10\n"
	x.write(t)
	var paths []string
	for i := range 6 {
		paths = append(paths, x.entry(t, fmt.Sprintf("entry-%d", i), map[string]string{"a": fmt.Sprintf("%d\n", i)}))
	}
	report := x.mustCleanup(t, true)
	if report.Archived != 6 || report.Archive == nil || len(report.Archive.Entries) != 6 {
		t.Fatalf("6 entries above limits.max_dir_entries 3 but within max_entries 10: %+v", report)
	}
	for _, path := range paths {
		if exists(t, path) {
			t.Fatalf("%s was not cleaned", path)
		}
	}

	for i := range 6 {
		paths[i] = x.entry(t, fmt.Sprintf("again-%d", i), map[string]string{"a": "again\n"})
	}
	x.options = "    max_entries: 4\n"
	x.write(t)
	refused, stderr, code := x.cleanup(t, true)
	if code == ExitOK || refused.Status != "failed" || !strings.Contains(refused.Error, "4-entry bound") || !strings.Contains(stderr, "nothing is touched") {
		t.Fatalf("6 entries above max_entries 4: exit=%d %s %+v", code, stderr, refused)
	}
	for _, path := range paths {
		if !exists(t, path) {
			t.Fatalf("a refused listing deleted %s", path)
		}
	}
	if refused.Archived != 0 || refused.Deleted != 0 || refused.Archive != nil {
		t.Fatalf("a refused listing reports work: %+v", refused)
	}
}
