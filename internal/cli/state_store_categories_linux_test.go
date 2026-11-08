//go:build linux

package cli

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// stateStoreFixture is the category fixture's isolated home with an OMP
// sessions store and a Gitmoot job-log directory (inside a Gitmoot home with
// an empty ledger) as the only category roots.
type stateStoreFixture struct {
	*categoryFixture
	sessions, gitmoot, jobs string
}

func newStateStoreFixture(t *testing.T) *stateStoreFixture {
	t.Helper()
	x := &stateStoreFixture{categoryFixture: newCategoryFixture(t)}
	x.sessions = filepath.Join(x.home, ".omp", "agent", "sessions")
	x.gitmoot = filepath.Join(x.home, ".gitmoot")
	x.jobs = filepath.Join(x.gitmoot, "logs", "jobs")
	for _, dir := range []string{x.sessions, x.jobs} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(x.gitmoot, "gitmoot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		`CREATE TABLE jobs(id TEXT, state TEXT, payload TEXT, updated_at TEXT, dispatched_by TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE tasks(id TEXT, state TEXT, worktree_path TEXT, disposal_escalation_role TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE cleanup_obligations(owner_job_id TEXT, expected_path TEXT, resource_kind TEXT, state TEXT, created_at TEXT, updated_at TEXT)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	x.writeStores(t, "")
	return x
}

func (x *stateStoreFixture) writeStores(t *testing.T, extra string) {
	t.Helper()
	category := func(name, kind, root string) string {
		return fmt.Sprintf("  - name: %s\n    kind: %s\n    roots: [%s]\n    idle: 1d\n    local_retention: none\n    archive:\n      directory: %s\n", name, kind, root, x.archive)
	}
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
    max_depth: 2
  - path: %s
    max_depth: 1
protect:
  paths: [%s]
collectors:
  git: true
  processes: true
  services: true
  proc_root: %s
  systemd_dirs: [%s]
  cron_paths: []
  pm2_dumps: []
retention:
  default: none
  delete_enabled: true
prevention:
  min_free_bytes: 0
  min_free_percent: 0
limits:
  command_timeout: 30s
gitmoot:
  home: %s
  database: %s
%sworkspace_archive_categories:
%s%s`, x.sessions, x.jobs, x.archive, x.proc, x.services, x.gitmoot, filepath.Join(x.gitmoot, "gitmoot.db"), extra,
		category("sessions", "omp_sessions", x.sessions), category("job-logs", "gitmoot_job_logs", x.jobs)))
}

// session creates an OMP session: <project>/<stem> with a few artifact files
// and its <stem>.jsonl transcript, everything modified age ago.
func (x *stateStoreFixture) session(t *testing.T, project, stem string, age time.Duration) string {
	t.Helper()
	dir := filepath.Join(x.sessions, project, stem)
	for name, data := range map[string]string{"0.bash.log": "ls\n", "sub/1.read.log": strings.Repeat("read\n", 64)} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(dir+".jsonl", []byte(`{"type":"session","id":"`+stem+`"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	backdate(t, dir, age)
	backdate(t, dir+".jsonl", age)
	backdate(t, filepath.Dir(dir), age)
	return dir
}

// process adds a fake procfs process with the given command line and
// environment and, optionally, one open descriptor.
func (x *stateStoreFixture) process(t *testing.T, pid string, argv, environ []string, open string) {
	t.Helper()
	dir := filepath.Join(x.proc, pid)
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, values := range map[string][]string{"cmdline": argv, "environ": environ} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(values, "\x00")+"\x00"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if open != "" {
		if err := os.Symlink(open, filepath.Join(dir, "fd", "3")); err != nil {
			t.Fatal(err)
		}
	}
}

// snapshot maps every regular file below each path (or the file itself) to
// its content, keyed relative to path's parent.
func snapshot(t *testing.T, paths ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range paths {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || !entry.Type().IsRegular() {
				return err
			}
			data, err := os.ReadFile(path)
			rel, _ := filepath.Rel(filepath.Dir(root), path)
			out[rel] = string(data)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func sameSnapshot(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d files, want %d: %v", what, len(got), len(want), got)
	}
	for name, data := range want {
		if got[name] != data {
			t.Fatalf("%s: %s differs or is missing", what, name)
		}
	}
}

// quarantineUnit approves and applies the proposed quarantine of path and
// returns its receipt.
func (x *stateStoreFixture) quarantineUnit(t *testing.T, path string) core.CleanupItem {
	t.Helper()
	plan, action := x.action(t, path)
	if action.Kind != core.ActionQuarantine {
		t.Fatalf("archived unit %s not proposed for quarantine: %+v", path, action)
	}
	x.data(t, "plan", "--plan", plan.ID, "--approve", action.ID, "--no-jev")
	x.data(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm")
	db, err := store.OpenExisting(context.Background(), x.paths(t).DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var found core.CleanupItem
	err = db.Read(context.Background(), func(tx *store.Tx) error {
		items, err := tx.CleanupItems(context.Background(), "")
		for _, item := range items {
			if item.Source == path {
				found = item
			}
		}
		return err
	})
	if err != nil || found.CleanupID == "" {
		t.Fatalf("quarantine receipt for %s absent: %v", path, err)
	}
	return found
}

func absentPaths(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still exists: %v", path, err)
		}
	}
}

const (
	sessionA = "2026-09-07T15-00-22-554Z_01a07c62-759a-7452-a1c8-f3ebf00ff14f"
	sessionB = "2026-09-08T09-33-12-295Z_01a0805d-48e7-72f4-aa58-baf66d2a22d7"
	sessionC = "2026-10-02T03-43-28-327Z_01a0fab5-b847-707a-a93d-15bbf99364eb"
)

// A session whose id is in some process's environment, or whose transcript
// path is on some command line, is in use even with no descriptor open: it
// stays local, while an unreferenced idle session is archived as one unit.
func TestOMPSessionNamedByAProcessStaysLocal(t *testing.T) {
	x := newStateStoreFixture(t)
	byEnviron := x.session(t, "-proj", sessionA, categoryIdleAge)
	byCmdline := x.session(t, "-proj", sessionB, categoryIdleAge)
	idle := x.session(t, "-other", sessionC, categoryIdleAge)
	x.process(t, "4242", []string{"/usr/bin/bun", "omp"}, []string{"HOME=/root", "PI_SESSION_ID=01a07c62-759a-7452-a1c8-f3ebf00ff14f"}, "")
	x.process(t, "4343", []string{"/usr/bin/omp", "--resume", byCmdline + ".jsonl"}, []string{"HOME=/root"}, "")
	before := snapshot(t, byEnviron, byEnviron+".jsonl", byCmdline, byCmdline+".jsonl")

	report := x.categories(t, false)
	for path, label := range map[string]string{byEnviron: "pid 4242 environ", byCmdline: "pid 4343 cmdline"} {
		item := categoryItem(t, report, path)
		if item.Status != categoryRefused || !strings.Contains(strings.Join(item.Reasons, ";"), label) {
			t.Errorf("%s: want refused for %q, got %+v", filepath.Base(path), label, item)
		}
	}
	sameSnapshot(t, "in-use sessions", snapshot(t, byEnviron, byEnviron+".jsonl", byCmdline, byCmdline+".jsonl"), before)
	item := categoryItem(t, report, idle)
	if item.Status != categoryArchived || item.Companion != idle+".jsonl" {
		t.Fatalf("unreferenced idle session not archived with its transcript: %+v", item)
	}
	for _, listed := range report.Items {
		if strings.HasSuffix(listed.Path, ".jsonl") {
			t.Fatalf("a transcript beside its session was reported as its own unit: %+v", listed)
		}
	}
}

// One write to the transcript keeps the whole session local, even though the
// session directory itself has been idle for weeks.
func TestOMPSessionRecentlyWrittenTranscriptKeepsTheUnit(t *testing.T) {
	x := newStateStoreFixture(t)
	session := x.session(t, "-proj", sessionA, categoryIdleAge)
	if err := os.WriteFile(session+".jsonl", []byte("{\"type\":\"message\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	item := categoryItem(t, x.categories(t, false), session)
	if item.Status != categoryRefused || !strings.Contains(strings.Join(item.Reasons, ";"), "requires 1d idle") {
		t.Fatalf("session with a fresh transcript was not kept for idle: %+v", item)
	}
	if entries, err := os.ReadDir(x.archive); err != nil || len(entries) != 0 {
		t.Fatalf("a busy session was copied off-host: %v %v", entries, err)
	}
}

// The session directory and its transcript are archived in one unit, move
// into quarantine together, come back together with `janitor restore`, and,
// after expiry, are restored together from the archive.
func TestOMPSessionArchivesQuarantinesAndRestoresWithItsTranscript(t *testing.T) {
	setup := func(t *testing.T) (*stateStoreFixture, string, map[string]string) {
		x := newStateStoreFixture(t)
		session := x.session(t, "-proj", sessionA, categoryIdleAge)
		want := snapshot(t, session, session+".jsonl")
		item := categoryItem(t, x.categories(t, false), session)
		if item.Status != categoryArchived || item.Companion != session+".jsonl" {
			t.Fatalf("session not archived with its transcript: %+v", item)
		}
		// The transcript is never a unit by itself while its directory exists.
		if _, action := x.action(t, session+".jsonl"); action.Kind != core.ActionKeep {
			t.Fatalf("transcript of an archived session planned on its own: %+v", action)
		}
		return x, session, want
	}
	t.Run("quarantine and janitor restore", func(t *testing.T) {
		x, session, want := setup(t)
		receipt := x.quarantineUnit(t, session)
		absentPaths(t, session, session+".jsonl")
		moved := snapshot(t, receipt.Destination, receipt.Destination+".jsonl")
		renamed := map[string]string{}
		for name, data := range moved {
			renamed[strings.Replace(name, "item", sessionA, 1)] = data
		}
		sameSnapshot(t, "quarantined unit", renamed, want)
		x.data(t, "restore", "--confirm", receipt.CleanupID)
		sameSnapshot(t, "restored unit", snapshot(t, session, session+".jsonl"), want)
		absentPaths(t, receipt.Destination, receipt.Destination+".jsonl")
	})
	t.Run("expiry and archive restore", func(t *testing.T) {
		x, session, want := setup(t)
		receipt := x.quarantineUnit(t, session)
		if _, _, code := x.run(t, "apply", "--expire", "--cleanup", receipt.CleanupID, "--dry-run=false", "--confirm"); code != ExitOK {
			t.Fatalf("expiry of an archived session failed: exit %d", code)
		}
		absentPaths(t, receipt.Destination, receipt.Destination+".jsonl", session, session+".jsonl")
		restored := x.data(t, "archive", "--restore-category-item", session, "--restore-to", session, "--dry-run=false", "--confirm")
		var status string
		field(t, restored, "status", &status)
		if status != "restored" {
			t.Fatalf("restore status = %q", status)
		}
		sameSnapshot(t, "restored unit", snapshot(t, session, session+".jsonl"), want)
	})
}

// Job logs are plain files directly in the jobs directory. An idle one is
// archived and then planned for quarantine despite lying in Gitmoot's
// protected home; a fresh or open one, a subdirectory, and an unarchived
// log stay local.
func TestGitmootJobLogsArchiveOnlyIdleUnusedFiles(t *testing.T) {
	x := newStateStoreFixture(t)
	write := func(name string, age time.Duration) string {
		path := filepath.Join(x.jobs, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("job output for "+name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		backdate(t, path, age)
		return path
	}
	idle := write("coordinator.log", categoryIdleAge)
	expired := write("child-of-root.log", categoryIdleAge)
	fresh := write("b-healthy.log", time.Hour)
	open := write("a-blocked.log", categoryIdleAge)
	nested := filepath.Join(x.jobs, "nested")
	write("nested/child.log", categoryIdleAge)
	backdate(t, nested, categoryIdleAge)
	x.process(t, "4444", []string{"/usr/bin/tail", "-f"}, []string{"HOME=/root"}, open)

	report := x.categories(t, false)
	for _, path := range []string{idle, expired} {
		if item := categoryItem(t, report, path); item.Status != categoryArchived {
			t.Fatalf("idle job log not archived: %+v", item)
		}
	}
	for path, why := range map[string]string{fresh: "requires 1d idle", open: "pid 4444 fd 3", nested: "only regular files"} {
		item := categoryItem(t, report, path)
		if item.Status != categoryRefused || !strings.Contains(strings.Join(item.Reasons, ";"), why) {
			t.Errorf("%s: want refused for %q, got %+v", filepath.Base(path), why, item)
		}
	}
	if _, action := x.action(t, fresh); action.Kind != core.ActionKeep {
		t.Fatalf("an unarchived job log left Gitmoot's home protection: %+v", action)
	}
	receipt := x.quarantineUnit(t, idle)
	absentPaths(t, idle)
	x.data(t, "restore", "--confirm", receipt.CleanupID)
	if data, err := os.ReadFile(idle); err != nil || string(data) != "job output for coordinator.log\n" {
		t.Fatalf("job log not restored: %q %v", data, err)
	}
	// Expiry re-checks the original pathname inside Gitmoot's home; only the
	// archived log's carve-out lets it delete the quarantined copy.
	receipt = x.quarantineUnit(t, expired)
	if _, _, code := x.run(t, "apply", "--expire", "--cleanup", receipt.CleanupID, "--dry-run=false", "--confirm"); code != ExitOK {
		t.Fatalf("expiry of an archived job log failed: exit %d", code)
	}
	absentPaths(t, expired, receipt.Destination)
}

// A job log that Gitmoot's ledger names is still Gitmoot's: the job-log
// exemption from Gitmoot's home never covers a ledger reference, so it is
// neither archived nor planned for removal.
func TestGitmootJobLogNamedByTheLedgerStaysLocal(t *testing.T) {
	x := newStateStoreFixture(t)
	path := filepath.Join(x.jobs, "coordinator.log")
	if err := os.WriteFile(path, []byte("job output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backdate(t, path, categoryIdleAge)
	db, err := sql.Open("sqlite", filepath.Join(x.gitmoot, "gitmoot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO jobs VALUES ('job-1', 'running', ?, '2026-01-01 00:00:00', 'coordinator')`, `{"worktree_path":"`+path+`"}`); err != nil {
		t.Fatal(err)
	}
	item := categoryItem(t, x.categories(t, false), path)
	if item.Status != categoryRefused || !strings.Contains(strings.Join(item.Reasons, ";"), "Gitmoot references") {
		t.Fatalf("ledger-referenced job log not kept: %+v", item)
	}
	if entries, err := os.ReadDir(x.archive); err != nil || len(entries) != 0 {
		t.Fatalf("a ledger-referenced job log was copied off-host: %v %v", entries, err)
	}
}
