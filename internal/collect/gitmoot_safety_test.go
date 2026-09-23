package collect_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/safety"
)

func TestFinalGitmootObservationCannotAuthorizeGenericMutation(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, ".gitmoot")
	worktree := filepath.Join(home, "worktree")
	if err := os.MkdirAll(worktree, 0o700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(root, "gitmoot.db")
	db, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE jobs(id TEXT, state TEXT, payload TEXT, updated_at TEXT)`,
		`CREATE TABLE tasks(state TEXT, worktree_path TEXT)`,
		`CREATE TABLE cleanup_obligations(owner_job_id TEXT, expected_path TEXT, resource_kind TEXT, state TEXT, created_at TEXT, updated_at TEXT)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO jobs VALUES(?,?,?,?)`, "owner", "succeeded", `{"worktree_path":"`+worktree+`"}`, "2026-03-01 00:00:00"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO cleanup_obligations VALUES(?,?,?,?,?,?)`, "owner", worktree, "delegation_worktree", "pending", "2026-03-01 00:00:00", "2026-03-01 00:00:00"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	result, err := collect.Run(context.Background(), collect.Options{
		Roots: []collect.RootSpec{{Path: home, MaxDepth: 1}},
		Limits: collect.Limits{GitTimeout: time.Second, CommandTimeout: time.Second,
			MaxEntries: 100, MaxDirEntries: 100, DeepSizeMaxEntries: 100, DeepSizeMaxDepth: 2},
		Now: func() time.Time { return now }, GitmootHome: home, GitmootDatabase: database,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.Entries {
		if entry.Path != worktree {
			continue
		}
		var final bool
		for _, evidence := range entry.Evidence {
			final = final || evidence.Signal == "gitmoot:final_reclaimable"
		}
		if !final {
			t.Fatalf("expected final Gitmoot observation: %+v", entry.Evidence)
		}
		verdict := safety.Evaluate(safety.Input{Entry: entry, Now: now})
		if verdict.Allows(core.ActionQuarantine) || verdict.Allows(core.ActionDeleteCandidate) {
			t.Fatalf("generic mutation allowed on Gitmoot worktree: %+v", verdict)
		}
		return
	}
	t.Fatal("managed worktree was not inventoried")
}
