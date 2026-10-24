//go:build linux

package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

type exportBinding struct {
	Manifest string `json:"manifest"`
	SHA      string `json:"manifest_sha256"`
}
type exportFixture struct {
	*fixture
	source, container, archive, proc, services string
	completed, modified                        time.Time
	content                                    []byte
	binding                                    exportBinding
}

func newExportFixture(t *testing.T) *exportFixture {
	t.Helper()
	f := newFixture(t)
	x := &exportFixture{fixture: f, container: filepath.Join(f.home, "completed-exports"), archive: filepath.Join(f.home, "retained-archives"), proc: filepath.Join(f.home, "proc"), services: filepath.Join(f.home, "services"), completed: time.Now().Add(-31 * 24 * time.Hour).UTC(), content: []byte(strings.Repeat("verified evidence export\n", 4096))}
	x.modified = x.completed.Add(-time.Hour)
	x.source = filepath.Join(x.container, "completed.json")
	for _, path := range []string{x.container, x.archive, x.proc, x.services} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(x.source, x.content, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(x.source, x.modified, x.modified); err != nil {
		t.Fatal(err)
	}
	x.policy(t, true)
	x.ok(t, "scan")
	return x
}
func (x *exportFixture) policy(t *testing.T, expiry bool) string {
	t.Helper()
	binding := ""
	if x.binding.Manifest != "" {
		binding = fmt.Sprintf("      manifest: %s\n      manifest_sha256: %s\n", x.binding.Manifest, x.binding.SHA)
	}
	return x.writePolicy(t, fmt.Sprintf(`roots:
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
evidence_exports:
  - name: completed-report
    class: completed_report
    path: %s
    owner: fixture-owner
    approval: fixture-owner-decision
    completed_at: %s
    credential_free: true
    source_container: %s
    source_lifetime: completed-job-fixture
    local_retention: 30d
    local_expiry_enabled: %t
    max_bytes: 1048576
    archive:
      directory: %s
      owner: fixture-archive-owner
      approval: fixture-archive-approval
      lifetime: independently-retained-fixture
      retention: permanent
      delete_enabled: false
%s`, x.container, x.archive, x.proc, x.services, x.source, x.completed.Format(time.RFC3339Nano), x.container, expiry, x.archive, binding))
}
func (x *exportFixture) ok(t *testing.T, args ...string) string {
	t.Helper()
	out, stderr, code := x.run(t, append([]string{"--format", "json"}, args...)...)
	if code != ExitOK {
		t.Fatalf("%v: exit=%d stderr=%s stdout=%s", args, code, stderr, out)
	}
	return out
}
func (x *exportFixture) archiveNow(t *testing.T) {
	t.Helper()
	out := x.ok(t, "archive", "--rule", "completed-report", "--dry-run=false", "--confirm")
	var doc struct {
		Data struct {
			Binding exportBinding `json:"binding"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	x.binding = doc.Data.Binding
	if x.binding.Manifest == "" || len(x.binding.SHA) != 64 {
		t.Fatalf("archive did not publish a pinned restore receipt: %s", out)
	}
	x.policy(t, true)
}
func (x *exportFixture) action(t *testing.T) (core.Plan, core.Action) {
	t.Helper()
	x.ok(t, "scan")
	var doc struct {
		Data struct {
			Plan core.Plan `json:"plan"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(x.ok(t, "plan", "--no-jev")), &doc); err != nil {
		t.Fatal(err)
	}
	for _, action := range doc.Data.Plan.Actions {
		if action.Path == x.source {
			return doc.Data.Plan, action
		}
	}
	t.Fatal("exact export missing from plan")
	return core.Plan{}, core.Action{}
}
func (x *exportFixture) approve(t *testing.T) core.Action {
	t.Helper()
	plan, action := x.action(t)
	if action.Kind != core.ActionQuarantine {
		t.Fatalf("verified completed export not eligible: %+v", action)
	}
	x.ok(t, "plan", "--plan", plan.ID, "--approve", action.ID, "--no-jev")
	return action
}
func (x *exportFixture) receipt(t *testing.T) core.CleanupItem {
	t.Helper()
	paths, err := config.ResolvePaths(config.MapLookup(x.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenExisting(context.Background(), paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var found core.CleanupItem
	err = db.Read(context.Background(), func(tx *store.Tx) error {
		items, err := tx.PendingCleanupItems(context.Background())
		for _, item := range items {
			if item.Source == x.source {
				found = item
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if found.CleanupID == "" {
		t.Fatal("quarantine receipt absent")
	}
	return found
}
func (x *exportFixture) preserved(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, x.content) {
		t.Fatalf("retained export changed or vanished: %v", err)
	}
}

func TestExportArchiveCorruptionBlocksExpiryAndRestoresExactMetadata(t *testing.T) {
	x := newExportFixture(t)
	x.archiveNow(t)
	x.preserved(t, x.source)
	action := x.approve(t)
	x.ok(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm")
	receipt := x.receipt(t)
	payload := filepath.Join(filepath.Dir(x.binding.Manifest), "content.gz")
	original, err := os.ReadFile(payload)
	if err != nil {
		t.Fatal(err)
	}
	damaged := append([]byte(nil), original...)
	// Change a gzip header timestamp, not the decompressed bytes or byte count.
	// Only the pinned archive checksum detects this same-length corruption.
	damaged[4] ^= 1
	if err = os.WriteFile(payload, damaged, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := x.run(t, "apply", "--expire", "--cleanup", receipt.CleanupID, "--dry-run=false", "--confirm"); code == ExitOK {
		t.Fatal("corrupt archive authorized destruction of the retained source")
	}
	x.preserved(t, receipt.Destination)
	if err = os.WriteFile(payload, original, 0600); err != nil {
		t.Fatal(err)
	}
	x.ok(t, "apply", "--expire", "--cleanup", receipt.CleanupID, "--dry-run=false", "--confirm")
	if _, err = os.Lstat(receipt.Destination); !os.IsNotExist(err) {
		t.Fatalf("approved local expiry did not remove the quarantined export: %v", err)
	}
	restored := filepath.Join(x.home, "restored-export.json")
	x.ok(t, "archive", "--rule", "completed-report", "--restore-to", restored, "--dry-run=false", "--confirm")
	x.preserved(t, restored)
	info, err := os.Stat(restored)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 || !info.ModTime().Equal(x.modified) {
		t.Fatalf("restored metadata differs: mode=%o mtime=%s", info.Mode().Perm(), info.ModTime())
	}
	if _, _, code := x.run(t, "archive", "--rule", "completed-report", "--restore-to", restored, "--dry-run=false", "--confirm"); code == ExitOK {
		t.Fatal("restore overwrote an existing file")
	}
	x.preserved(t, restored)
	after, err := os.ReadFile(payload)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("local expiry or restore changed the permanent archive")
	}
}

func TestExportArchiveMissingAfterApprovalPreservesOriginal(t *testing.T) {
	x := newExportFixture(t)
	x.archiveNow(t)
	action := x.approve(t)
	payload := filepath.Join(filepath.Dir(x.binding.Manifest), "content.gz")
	if err := os.Rename(payload, payload+".offline"); err != nil {
		t.Fatal(err)
	}
	if _, _, code := x.run(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm"); code == ExitOK {
		t.Fatal("missing archive authorized a source move")
	}
	x.preserved(t, x.source)
}

func TestExportArchiveRevalidatesSourceContentBeforeMove(t *testing.T) {
	x := newExportFixture(t)
	x.archiveNow(t)
	action := x.approve(t)
	replacement := append([]byte(nil), x.content...)
	replacement[0] ^= 1
	if err := os.WriteFile(x.source, replacement, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(x.source, x.modified, x.modified); err != nil {
		t.Fatal(err)
	}
	if _, _, code := x.run(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm"); code == ExitOK {
		t.Fatal("same-metadata replacement bypassed archive content verification")
	}
	data, err := os.ReadFile(x.source)
	if err != nil || !bytes.Equal(data, replacement) {
		t.Fatal("unarchived replacement was lost")
	}
}

func TestExportArchiveRetentionUsesVerifiedCompletionAndExplicitAuthority(t *testing.T) {
	for _, state := range []string{"young-completion", "no-archive", "expiry-disabled", "existing-protection"} {
		t.Run(state, func(t *testing.T) {
			x := newExportFixture(t)
			if state == "young-completion" {
				x.completed = time.Now().Add(-29 * 24 * time.Hour).UTC()
				x.policy(t, true)
			}
			if state != "no-archive" {
				x.archiveNow(t)
			}
			switch state {
			case "expiry-disabled":
				x.policy(t, false)
			case "existing-protection":
				path := x.policy(t, true)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data = []byte(strings.Replace(string(data), "paths: ["+x.archive+"]", "paths: ["+x.archive+", "+x.source+"]", 1))
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, action := x.action(t)
			if action.Kind != core.ActionKeep {
				t.Fatalf("retained export received a destructive action: %+v", action)
			}
			x.preserved(t, x.source)
		})
	}
}

func TestExportArchivePreservesOpenDescriptorsAndQueuedUsers(t *testing.T) {
	for _, state := range []string{"open-descriptor", "queued-job"} {
		t.Run(state, func(t *testing.T) {
			x := newExportFixture(t)
			x.archiveNow(t)
			if state == "open-descriptor" {
				pid := filepath.Join(x.proc, "987654321")
				if err := os.MkdirAll(filepath.Join(pid, "fd"), 0700); err != nil {
					t.Fatal(err)
				}
				elsewhere := filepath.Join(x.home, "unrelated")
				if err := os.Mkdir(elsewhere, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(pid, "comm"), []byte("reader\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(elsewhere, filepath.Join(pid, "cwd")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(x.source, filepath.Join(pid, "fd", "3")); err != nil {
					t.Fatal(err)
				}
			} else {
				home := filepath.Join(x.home, ".gitmoot")
				if err := os.Mkdir(home, 0700); err != nil {
					t.Fatal(err)
				}
				db, err := sql.Open("sqlite", filepath.Join(home, "gitmoot.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				for _, statement := range []string{`CREATE TABLE jobs(id TEXT,state TEXT,payload TEXT,updated_at TEXT)`, `CREATE TABLE tasks(state TEXT,worktree_path TEXT)`, `CREATE TABLE cleanup_obligations(owner_job_id TEXT,expected_path TEXT,resource_kind TEXT,state TEXT,created_at TEXT,updated_at TEXT)`, `INSERT INTO jobs VALUES('consumer','queued','{}','2026-01-01 00:00:00')`} {
					if _, err = db.Exec(statement); err != nil {
						t.Fatal(err)
					}
				}
			}
			_, action := x.action(t)
			if action.Kind != core.ActionKeep {
				t.Fatalf("live or queued user lost its export: %+v", action)
			}
			x.preserved(t, x.source)
		})
	}
}

func TestExportArchiveRejectsRawDatabaseAndSymlinkSources(t *testing.T) {
	for _, state := range []string{"database", "symlink"} {
		t.Run(state, func(t *testing.T) {
			x := newExportFixture(t)
			if state == "database" {
				x.content = []byte("SQLite format 3\x00protected raw database")
				if err := os.WriteFile(x.source, x.content, 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(x.source, x.modified, x.modified); err != nil {
					t.Fatal(err)
				}
			} else {
				target := filepath.Join(x.home, "private-original")
				if err := os.Rename(x.source, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, x.source); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, code := x.run(t, "archive", "--rule", "completed-report", "--dry-run=false", "--confirm"); code == ExitOK {
				t.Fatal("raw or indirect source was archived")
			}
			x.preserved(t, x.source)
		})
	}
}

func TestExportArchiveRefusesChangesAfterVerifiedCompletion(t *testing.T) {
	x := newExportFixture(t)
	if err := os.Chtimes(x.source, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, code := x.run(t, "archive", "--rule", "completed-report", "--dry-run=false", "--confirm"); code == ExitOK {
		t.Fatal("a changed export reused an obsolete completion declaration")
	}
	x.preserved(t, x.source)
}

func TestExportArchiveProtectsContainerFromBroaderCleanupRule(t *testing.T) {
	x := newExportFixture(t)
	path := x.policy(t, true)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(data), "  - path: "+x.container+"\n    max_depth: 1", "  - path: "+x.home+"\n    max_depth: 2", 1)
	text += "\ncaches:\n  - name: broad-parent\n    path: " + x.container + "\n    action: quarantine\n    retention: none\n"
	if err = os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	planned, _ := x.action(t)
	found := false
	for _, action := range planned.Actions {
		if action.Path == x.container {
			found = true
			if action.Kind != core.ActionKeep {
				t.Fatalf("broader rule may remove an unarchived export: %+v", action)
			}
		}
	}
	if !found {
		t.Fatal("parent cleanup rule was not exercised")
	}
	x.preserved(t, x.source)
}

func TestExportArchiveChangedDestinationBlocksExpiryButAllowsRecovery(t *testing.T) {
	x := newExportFixture(t)
	x.archiveNow(t)
	action := x.approve(t)
	old := x.archive + ".old"
	if err := os.Rename(x.archive, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(x.archive, 0700); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Base(filepath.Dir(x.binding.Manifest))
	if err := os.Rename(filepath.Join(old, bundle), filepath.Join(x.archive, bundle)); err != nil {
		t.Fatal(err)
	}
	if _, _, code := x.run(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm"); code == ExitOK {
		t.Fatal("changed archive container inherited local deletion authority")
	}
	x.preserved(t, x.source)
	restored := filepath.Join(x.home, "recovered-from-replaced-container")
	x.ok(t, "archive", "--rule", "completed-report", "--restore-to", restored, "--dry-run=false", "--confirm")
	x.preserved(t, restored)
}

func TestExportArchiveRejectsUnsafeLifetimeAndArchiveExpiryPolicy(t *testing.T) {
	for _, state := range []string{"same-lifetime", "archive-expiry", "short-local-retention", "unprotected-archive"} {
		t.Run(state, func(t *testing.T) {
			x := newExportFixture(t)
			path := x.policy(t, true)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			switch state {
			case "same-lifetime":
				text = strings.Replace(text, "lifetime: independently-retained-fixture", "lifetime: completed-job-fixture", 1)
			case "archive-expiry":
				text = strings.Replace(text, "      delete_enabled: false", "      delete_enabled: true", 1)
			case "short-local-retention":
				text = strings.Replace(text, "local_retention: 30d", "local_retention: 7d", 1)
			case "unprotected-archive":
				text = strings.Replace(text, "  paths: ["+x.archive+"]", "  paths: []", 1)
			}
			if err = os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, code := x.run(t, "archive", "--rule", "completed-report", "--dry-run=false", "--confirm"); code == ExitOK {
				t.Fatal("unsafe retention/lifetime policy permitted archival")
			}
			x.preserved(t, x.source)
		})
	}
}

func TestExportArchiveRuleRemovalCannotExpireQuarantinedSoleCopy(t *testing.T) {
	x := newExportFixture(t)
	x.archiveNow(t)
	action := x.approve(t)
	x.ok(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm")
	receipt := x.receipt(t)
	path := x.policy(t, true)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	retained, _, ok := strings.Cut(string(data), "evidence_exports:\n")
	if !ok {
		t.Fatal("fixture export rule missing")
	}
	if err = os.WriteFile(path, []byte(retained+"evidence_exports: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(x.archive, x.archive+".unavailable"); err != nil {
		t.Fatal(err)
	}
	if _, _, code := x.run(t, "apply", "--expire", "--cleanup", receipt.CleanupID, "--dry-run=false", "--confirm"); code == ExitOK {
		t.Fatal("removing the rule erased the quarantined export's archive requirement")
	}
	x.preserved(t, receipt.Destination)
}
