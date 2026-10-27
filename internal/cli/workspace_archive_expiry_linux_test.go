//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
)

// workspaceExpiryFixture drives the whole released-workspace lifecycle
// through the CLI: archive, pin, scan, plan, approve, quarantine, expire and
// restore, against an isolated home and an empty procfs stand-in.
type workspaceExpiryFixture struct {
	*workspaceArchiveFixture
	services  string
	manifest  string
	sha       string
	expiry    bool
	retention string
	extra     string
	files     map[string][]byte
}

func newWorkspaceExpiryFixture(t *testing.T) *workspaceExpiryFixture {
	t.Helper()
	x := &workspaceExpiryFixture{workspaceArchiveFixture: newWorkspaceArchiveFixture(t), retention: "30d", files: map[string][]byte{}}
	x.services = filepath.Join(x.home, "services")
	if err := os.MkdirAll(x.services, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"README.md", "sub/data.txt"} {
		data, err := os.ReadFile(filepath.Join(x.source, name))
		if err != nil {
			t.Fatal(err)
		}
		x.files[name] = data
	}
	x.write(t)
	return x
}

func (x *workspaceExpiryFixture) write(t *testing.T) {
	t.Helper()
	pin := ""
	if x.manifest != "" {
		pin = fmt.Sprintf("      manifest: %s\n      manifest_sha256: %s\n", x.manifest, x.sha)
	}
	x.writePolicy(t, fmt.Sprintf(`roots:
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
workspace_archives:
  - name: released
    path: %s
    owner: seat-a
    release: release-msg-1
    local_retention: %s
    local_expiry_enabled: %t
    archive:
      directory: %s
%s%s`, x.work, x.archive, x.proc, x.services, x.source, x.retention, x.expiry, x.archive, pin, x.extra))
}

// archiveAndPin creates and pins the archive, then backdates its manifest by age
// (re-pinning the new hash) so retention can be exercised without waiting.
func (x *workspaceExpiryFixture) archiveAndPin(t *testing.T, age time.Duration, expiry bool) {
	t.Helper()
	x.expiry, x.manifest, x.sha = false, "", ""
	x.write(t)
	created := x.data(t, "archive", "--workspace", "released", "--dry-run=false", "--confirm")
	var binding struct {
		Manifest string `json:"manifest"`
		SHA      string `json:"manifest_sha256"`
	}
	field(t, created, "binding", &binding)
	data, err := os.ReadFile(binding.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if age > 0 {
		var m workspacearchive.Manifest
		if err = json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		m.CreatedAt, m.VerifiedAt = m.CreatedAt.Add(-age), m.VerifiedAt.Add(-age)
		if data, err = json.Marshal(m); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(binding.Manifest, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256(data)
	x.manifest, x.sha, x.expiry = binding.Manifest, hex.EncodeToString(sum[:]), expiry
	x.write(t)
}

func (x *workspaceExpiryFixture) action(t *testing.T) (core.Plan, core.Action) {
	t.Helper()
	x.data(t, "scan")
	var plan core.Plan
	field(t, x.data(t, "plan", "--no-jev"), "plan", &plan)
	for _, action := range plan.Actions {
		if action.Path == x.source {
			return plan, action
		}
	}
	t.Fatalf("released workspace missing from plan: %+v", plan.Actions)
	return core.Plan{}, core.Action{}
}

func (x *workspaceExpiryFixture) requireKeep(t *testing.T, why string) {
	t.Helper()
	if _, action := x.action(t); action.Kind != core.ActionKeep {
		t.Fatalf("%s: released workspace proposed for %s: %+v", why, action.Kind, action)
	}
	x.preserved(t, x.source)
}

// quarantine approves the proposed quarantine and moves the workspace.
func (x *workspaceExpiryFixture) quarantine(t *testing.T) core.CleanupItem {
	t.Helper()
	plan, action := x.action(t)
	if action.Kind != core.ActionQuarantine {
		t.Fatalf("archived released workspace past retention not proposed for quarantine: %+v", action)
	}
	x.data(t, "plan", "--plan", plan.ID, "--approve", action.ID, "--no-jev")
	x.data(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm")
	if _, err := os.Lstat(x.source); !os.IsNotExist(err) {
		t.Fatalf("quarantine left the source in place: %v", err)
	}
	return x.receipt(t)
}

func (x *workspaceExpiryFixture) receipt(t *testing.T) core.CleanupItem {
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

func (x *workspaceExpiryFixture) expire(t *testing.T, receipt core.CleanupItem) ExitCode {
	t.Helper()
	_, _, code := x.run(t, "apply", "--expire", "--cleanup", receipt.CleanupID, "--dry-run=false", "--confirm")
	return code
}

// preserved requires the archived files at root, byte for byte.
func (x *workspaceExpiryFixture) preserved(t *testing.T, root string) {
	t.Helper()
	for name, want := range x.files {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s/%s changed or vanished: %v", root, name, err)
		}
	}
}

func (x *workspaceExpiryFixture) corruptTar(t *testing.T) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(x.archive, "released.tar"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = file.WriteAt([]byte("X"), 1024+20); err != nil {
		t.Fatal(err)
	}
}

const pastRetention = 31 * 24 * time.Hour

// (a) The full lifecycle: a pinned archive that exactly matches the released
// workspace, past its local retention, lets the ordinary engine quarantine and
// expire the local copy, and the archive restores it at its original path.
func TestWorkspaceArchiveExpiryQuarantinesExpiresAndRestoresFromArchive(t *testing.T) {
	x := newWorkspaceExpiryFixture(t)
	x.archiveAndPin(t, pastRetention, true)
	receipt := x.quarantine(t)
	x.preserved(t, receipt.Destination)
	if receipt.Quarantined == nil || receipt.Quarantined.WorkspaceArchive == nil || receipt.Quarantined.WorkspaceArchive.ManifestSHA256 != x.sha {
		t.Fatalf("quarantine snapshot lacks the archive binding: %+v", receipt.Quarantined)
	}
	if code := x.expire(t, receipt); code != ExitOK {
		t.Fatalf("expiry of a verified archived workspace failed: exit %d", code)
	}
	if _, err := os.Lstat(receipt.Destination); !os.IsNotExist(err) {
		t.Fatalf("expiry did not remove the quarantined copy: %v", err)
	}
	if _, err := os.Lstat(x.source); !os.IsNotExist(err) {
		t.Fatalf("expiry recreated the original path: %v", err)
	}
	restored := x.data(t, "archive", "--workspace", "released", "--restore-to", x.source, "--dry-run=false", "--confirm")
	var status string
	field(t, restored, "status", &status)
	if status != "restored" {
		t.Fatalf("restore status = %q", status)
	}
	x.preserved(t, x.source)
}

// (b) Local changes made after archiving would be lost, so they hold the
// workspace; changes inside the quarantined copy refuse expiry and restore
// still returns them.
func TestWorkspaceArchiveExpiryRefusesLocalChanges(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, root string){
		"added": func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "sub", "new.txt"), []byte("unarchived\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"changed": func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("edited after archiving\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"removed": func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "sub", "data.txt")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name+" before quarantine", func(t *testing.T) {
			x := newWorkspaceExpiryFixture(t)
			x.archiveAndPin(t, pastRetention, true)
			change(t, x.source)
			if _, action := x.action(t); action.Kind != core.ActionKeep {
				t.Fatalf("a locally changed workspace was proposed for %s", action.Kind)
			}
		})
		t.Run(name+" after quarantine", func(t *testing.T) {
			x := newWorkspaceExpiryFixture(t)
			x.archiveAndPin(t, pastRetention, true)
			receipt := x.quarantine(t)
			change(t, receipt.Destination)
			if code := x.expire(t, receipt); code == ExitOK {
				t.Fatal("expiry deleted a quarantined copy that no longer matches its archive")
			}
			if _, err := os.Lstat(receipt.Destination); err != nil {
				t.Fatalf("refused expiry lost the quarantined copy: %v", err)
			}
			x.data(t, "restore", "--confirm", receipt.CleanupID)
			info, err := os.Stat(x.source)
			if err != nil || !info.IsDir() {
				t.Fatalf("restore did not return the changed workspace: %v", err)
			}
		})
	}
}

// (c) An unavailable, corrupted or re-pinned archive keeps the workspace.
func TestWorkspaceArchiveExpiryRequiresIntactPinnedArchive(t *testing.T) {
	t.Run("missing tar", func(t *testing.T) {
		x := newWorkspaceExpiryFixture(t)
		x.archiveAndPin(t, pastRetention, true)
		tar := filepath.Join(x.archive, "released.tar")
		if err := os.Rename(tar, tar+".offline"); err != nil {
			t.Fatal(err)
		}
		x.requireKeep(t, "missing archive")
	})
	t.Run("wrong manifest pin", func(t *testing.T) {
		x := newWorkspaceExpiryFixture(t)
		x.archiveAndPin(t, pastRetention, true)
		x.sha = fmt.Sprintf("%064x", 0)
		x.write(t)
		x.requireKeep(t, "re-pinned manifest")
	})
	t.Run("unpinned manifest", func(t *testing.T) {
		x := newWorkspaceExpiryFixture(t)
		x.archiveAndPin(t, pastRetention, false)
		x.manifest, x.sha = "", ""
		x.write(t)
		x.requireKeep(t, "unpinned manifest")
		x.expiry = true
		x.write(t)
		if _, _, code := x.run(t, "scan"); code == ExitOK {
			t.Fatal("local expiry without a pinned manifest was accepted")
		}
	})
	t.Run("corrupted before quarantine", func(t *testing.T) {
		x := newWorkspaceExpiryFixture(t)
		x.archiveAndPin(t, pastRetention, true)
		x.corruptTar(t)
		// The inventory scan compares metadata only; the mutation-time
		// recollection re-reads the archive and refuses the move.
		plan, action := x.action(t)
		if action.Kind != core.ActionQuarantine {
			t.Fatalf("metadata scan unexpectedly refused before the move: %+v", action)
		}
		x.data(t, "plan", "--plan", plan.ID, "--approve", action.ID, "--no-jev")
		if _, _, code := x.run(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm"); code == ExitOK {
			t.Fatal("corrupted archive authorized moving the released workspace")
		}
		x.preserved(t, x.source)
	})
	t.Run("corrupted after quarantine", func(t *testing.T) {
		x := newWorkspaceExpiryFixture(t)
		x.archiveAndPin(t, pastRetention, true)
		receipt := x.quarantine(t)
		x.corruptTar(t)
		if code := x.expire(t, receipt); code == ExitOK {
			t.Fatal("corrupted archive authorized deleting the quarantined copy")
		}
		x.preserved(t, receipt.Destination)
		x.data(t, "restore", "--confirm", receipt.CleanupID)
		x.preserved(t, x.source)
	})
}

// (d) Expiry is opt-in and waits for the local retention from archive creation.
func TestWorkspaceArchiveExpiryKeepsUntilEnabledAndRetentionElapsed(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, x *workspaceExpiryFixture){
		"expiry disabled": func(t *testing.T, x *workspaceExpiryFixture) { x.archiveAndPin(t, pastRetention, false) },
		"retention unmet": func(t *testing.T, x *workspaceExpiryFixture) { x.archiveAndPin(t, 0, true) },
		"90d retention": func(t *testing.T, x *workspaceExpiryFixture) {
			x.retention = "90d"
			x.archiveAndPin(t, pastRetention, true)
		},
		"permanent kept": func(t *testing.T, x *workspaceExpiryFixture) {
			x.retention = "permanent"
			x.archiveAndPin(t, pastRetention, false)
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := newWorkspaceExpiryFixture(t)
			setup(t, x)
			x.requireKeep(t, name)
		})
	}
}

// (e) KEEP records, live processes and external dependents still win.
func TestWorkspaceArchiveExpiryYieldsToKeepLiveUseAndDependents(t *testing.T) {
	t.Run("live process", func(t *testing.T) {
		x := newWorkspaceExpiryFixture(t)
		x.archiveAndPin(t, pastRetention, true)
		pid := filepath.Join(x.proc, "987654321")
		if err := os.MkdirAll(pid, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pid, "comm"), []byte("editor\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(x.source, "sub"), filepath.Join(pid, "cwd")); err != nil {
			t.Fatal(err)
		}
		x.requireKeep(t, "live process")
	})
	t.Run("external dependent", func(t *testing.T) {
		x := newWorkspaceExpiryFixture(t)
		x.archiveAndPin(t, pastRetention, true)
		if err := os.Symlink(filepath.Join(x.source, "sub"), filepath.Join(x.work, "uses-released")); err != nil {
			t.Fatal(err)
		}
		x.requireKeep(t, "external dependent")
	})
	t.Run("rule withdrawn after quarantine", func(t *testing.T) {
		x := newWorkspaceExpiryFixture(t)
		x.archiveAndPin(t, pastRetention, true)
		receipt := x.quarantine(t)
		path := filepath.Join(x.home, ".config", config.AppName, "policy.yaml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		retained, _, ok := strings.Cut(string(data), "workspace_archives:\n")
		if !ok {
			t.Fatal("fixture workspace archive rule missing")
		}
		if err = os.WriteFile(path, []byte(retained+"workspace_archives: []\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := x.expire(t, receipt); code == ExitOK {
			t.Fatal("withdrawing the rule erased the quarantined workspace's archive requirement")
		}
		x.preserved(t, receipt.Destination)
	})
	t.Run("keep record after quarantine", func(t *testing.T) {
		x := newWorkspaceExpiryFixture(t)
		x.archiveAndPin(t, pastRetention, true)
		receipt := x.quarantine(t)
		x.extra = fmt.Sprintf("workspace_archive_keep:\n  - path: %s\n    owner: seat-b\n    reference: keep-msg-7\n", x.source)
		x.write(t)
		if code := x.expire(t, receipt); code == ExitOK {
			t.Fatal("expiry ignored an unresolved KEEP/release conflict")
		}
		x.preserved(t, receipt.Destination)
	})
}
