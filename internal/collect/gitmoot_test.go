package collect

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func gitmootSignal(entry core.Entry) string {
	for _, evidence := range entry.Evidence {
		if evidence.Signal == "unknown:gitmoot" || len(evidence.Signal) >= 8 && evidence.Signal[:8] == "gitmoot:" {
			return evidence.Signal
		}
	}
	return ""
}

func TestGitmootObservationProvenanceAndProtection(t *testing.T) {
	base := t.TempDir()
	home := mustMkdir(t, filepath.Join(base, ".gitmoot"))
	dbPath := filepath.Join(home, "gitmoot.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, schema := range []string{
		`CREATE TABLE jobs(id TEXT PRIMARY KEY, state TEXT NOT NULL, payload TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE tasks(id TEXT PRIMARY KEY, state TEXT NOT NULL, worktree_path TEXT NOT NULL)`,
		`CREATE TABLE cleanup_obligations(owner_job_id TEXT, expected_path TEXT, resource_kind TEXT, state TEXT, created_at TEXT, updated_at TEXT)`,
	} {
		if _, err := db.Exec(schema); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct{ name, state, obligation, want string }{
		{"final", "succeeded", "pending", "gitmoot:final_reclaimable"},
		{"failed", "failed", "retryable", "gitmoot:final_reclaimable"},
		{"cancelled", "cancelled", "pending", "gitmoot:final_reclaimable"},
		{"queued", "queued", "removed", "gitmoot:pinned"},
		{"running", "running", "pending", "gitmoot:pinned"},
		{"blocked", "blocked", "removed", "gitmoot:pinned"},
		{"receipt_removed", "succeeded", "removed", "unknown:gitmoot"},
		{"no_receipt", "succeeded", "", "unknown:gitmoot"},
		{"unproven_clone", "", "", "unknown:gitmoot"},
		{"mismatched_owner", "succeeded", "pending", "unknown:gitmoot"},
		{"path_mismatch", "succeeded", "pending", "unknown:gitmoot"},
		{"invalid_payload", "succeeded", "pending", "unknown:gitmoot"},
		{"too_young", "succeeded", "pending", "unknown:gitmoot"},
		{"task_active", "succeeded", "pending", "gitmoot:pinned"},
		{"task_terminal", "succeeded", "pending", "unknown:gitmoot"},
	}
	for _, tc := range cases {
		path := mustMkdir(t, filepath.Join(home, tc.name))
		if tc.state != "" {
			stamp := "2026-03-01 00:00:00"
			if tc.name == "too_young" {
				stamp = "2026-04-05 05:07:08"
			}
			recorded := path
			if tc.name == "path_mismatch" {
				recorded += "-other"
			}
			payload := `{"worktree_path":"` + recorded + `"}`
			if tc.name == "invalid_payload" {
				payload = "{"
			}
			if _, err := db.Exec(`INSERT INTO jobs(id,state,payload,updated_at) VALUES(?,?,?,?)`, tc.name, tc.state, payload, stamp); err != nil {
				t.Fatal(err)
			}
		}
		if tc.obligation != "" {
			owner := tc.name
			if tc.name == "mismatched_owner" {
				owner = "another-job"
			}
			if _, err := db.Exec(`INSERT INTO cleanup_obligations(owner_job_id,expected_path,resource_kind,state,created_at,updated_at) VALUES(?,?,?,?,?,?)`, owner, path, "delegation_worktree", tc.obligation, "2026-03-01 00:00:00", "2026-03-01 00:00:00"); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, state := range []struct{ name, state string }{{"task_active", "review"}, {"task_terminal", "merged"}} {
		if _, err := db.Exec(`INSERT INTO tasks(id,state,worktree_path) VALUES(?,?,?)`, state.name, state.state, filepath.Join(home, state.name)); err != nil {
			t.Fatal(err)
		}
	}
	// An exact DB reference outside the managed tree is observed, but is never
	// classified as reclaimable and never broadens protection to its parent.
	external := mustMkdir(t, filepath.Join(base, "external"))
	if _, err := db.Exec(`INSERT INTO jobs(id,state,payload,updated_at) VALUES(?,?,?,?)`, "external", "succeeded", `{"worktree_path":"`+external+`"}`, "2026-03-01 00:00:00"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO cleanup_obligations(owner_job_id,expected_path,resource_kind,state,created_at,updated_at) VALUES(?,?,?,?,?,?)`, "external", external, "delegation_worktree", "pending", "2026-03-01 00:00:00", "2026-03-01 00:00:00"); err != nil {
		t.Fatal(err)
	}
	opts := fixtureOptions(base)
	opts.Roots[0].MaxDepth = 2
	opts.GitmootHome, opts.GitmootDatabase = home, dbPath
	result := run(t, opts)
	for _, tc := range cases {
		entry := entryFor(t, result, filepath.Join(home, tc.name))
		if signal := gitmootSignal(entry); signal != tc.want {
			t.Errorf("%s signal = %q, want %q", tc.name, signal, tc.want)
		}
		if !entry.Protected() || !hasProtection(entry, core.ProtectOwningJob) {
			t.Errorf("%s generic mutation was not refused", tc.name)
		}
	}
	if signal := gitmootSignal(entryFor(t, result, external)); signal != "unknown:gitmoot" {
		t.Errorf("external signal = %q", signal)
	}
	if report := reportFor(t, result, CollectorGitmoot); report.Status != core.CollectorRan {
		t.Errorf("report = %+v", report)
	}
}

func TestGitmootFailClosedDatabaseAndPathIdentity(t *testing.T) {
	base := t.TempDir()
	home := mustMkdir(t, filepath.Join(base, ".gitmoot"))
	path := mustMkdir(t, filepath.Join(home, "worktree"))
	opts := fixtureOptions(home)
	opts.GitmootHome = home
	opts.GitmootDatabase = filepath.Join(base, "missing.db")
	for _, dbPath := range []string{opts.GitmootDatabase, filepath.Join(base, "invalid.db"), filepath.Join(base, "schema.db")} {
		if filepath.Base(dbPath) == "invalid.db" {
			if err := os.WriteFile(dbPath, []byte("not sqlite"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if filepath.Base(dbPath) == "schema.db" {
			empty, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := empty.Exec(`CREATE TABLE jobs(id TEXT)`); err != nil {
				t.Fatal(err)
			}
			if err := empty.Close(); err != nil {
				t.Fatal(err)
			}
		}
		opts.GitmootDatabase = dbPath
		result := run(t, opts)
		entry := entryFor(t, result, path)
		if gitmootSignal(entry) != "unknown:gitmoot" || !entry.Protected() {
			t.Fatalf("DB %s did not fail closed: %+v", dbPath, entry)
		}
		if reportFor(t, result, CollectorGitmoot).Status != core.CollectorPartial {
			t.Fatal("missing or invalid DB should report partial")
		}
	}
	// A symlink inside the protected home must not inherit a proof for its
	// lexical path when its filesystem identity escapes the home.
	outside := mustMkdir(t, filepath.Join(base, "outside"))
	link := mustSymlink(t, outside, filepath.Join(home, "escape"))
	opts.GitmootDatabase = filepath.Join(base, "valid.db")
	db, err := sql.Open("sqlite", opts.GitmootDatabase)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE jobs(id TEXT, state TEXT, payload TEXT, updated_at TEXT)`,
		`CREATE TABLE tasks(id TEXT, state TEXT, worktree_path TEXT)`,
		`CREATE TABLE cleanup_obligations(owner_job_id TEXT, expected_path TEXT, resource_kind TEXT, state TEXT, created_at TEXT, updated_at TEXT)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO jobs VALUES(?,?,?,?)`, "escape", "succeeded", `{"worktree_path":"`+link+`"}`, "2026-03-01 00:00:00"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO cleanup_obligations VALUES(?,?,?,?,?,?)`, "escape", link, "delegation_worktree", "pending", "2026-03-01 00:00:00", "2026-03-01 00:00:00"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	result := run(t, opts)
	if signal := gitmootSignal(entryFor(t, result, link)); signal != "unknown:gitmoot" {
		t.Errorf("symlink escape signal = %q", signal)
	}
	if signal := gitmootSignal(entryFor(t, result, path)); signal != "unknown:gitmoot" {
		t.Errorf("unproven path signal = %q", signal)
	}
}

func TestGitmootAbsentHomeLeavesOtherScansUnchanged(t *testing.T) {
	root := mustMkdir(t, filepath.Join(t.TempDir(), "root"))
	mustMkdir(t, filepath.Join(root, "ordinary"))
	opts := fixtureOptions(root)
	result, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := gitmootSignal(entryFor(t, result, filepath.Join(root, "ordinary"))); got != "" {
		t.Fatalf("unexpected Gitmoot evidence %q", got)
	}
	if reportFor(t, result, CollectorGitmoot).Status != core.CollectorSkipped {
		t.Fatal("expected skipped collector")
	}
}

func TestGitmootTimeoutProtectsManagedEntry(t *testing.T) {
	base := t.TempDir()
	home := mustMkdir(t, filepath.Join(base, ".gitmoot"))
	managed := mustMkdir(t, filepath.Join(home, "worktree"))
	opts := fixtureOptions(base)
	opts.Roots[0].MaxDepth = 2
	opts.GitmootHome, opts.GitmootDatabase = home, filepath.Join(home, "gitmoot.db")
	opts.Limits.CommandTimeout = time.Nanosecond
	result := run(t, opts)
	entry := entryFor(t, result, managed)
	if signal := gitmootSignal(entry); signal != "unknown:gitmoot" || !entry.Protected() {
		t.Fatalf("timed-out ledger did not protect managed path: %q %+v", signal, entry.Protections)
	}
	report := reportFor(t, result, CollectorGitmoot)
	if report.Status != core.CollectorPartial || report.Unknowns == 0 ||
		!strings.Contains(report.Detail, "command timeout") {
		t.Fatalf("timed-out ledger reported certainty: %+v", report)
	}
}
