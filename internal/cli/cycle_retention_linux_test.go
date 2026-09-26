//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

func TestScheduledExpiryRechecksOriginalReferences(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	cache := filepath.Join(root, "cache")
	proc := filepath.Join(f.home, "empty-proc")
	units := filepath.Join(f.home, "systemd")
	for _, path := range []string{cache, proc, units} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cache, "payload"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: true\n  proc_root: "+proc+"\n  systemd_dirs:\n    - "+units+"\n  cron_paths: []\n  pm2_dumps: []\ncaches:\n  - name: fixture-cache\n    path: "+cache+"\n    action: quarantine\n    retention: none\nretention:\n  delete_enabled: true\nprevention:\n  auto_expire: true\n  min_free_percent: 0\n")
	if _, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("scan: %s", stderr)
	}
	out, stderr, code := f.run(t, "--format", "json", "plan", "--no-jev")
	var doc struct {
		Data struct {
			Plan core.Plan `json:"plan"`
		} `json:"data"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &doc) != nil {
		t.Fatalf("plan: %d %s %s", code, stderr, out)
	}
	var chosen core.Action
	for _, candidate := range doc.Data.Plan.Actions {
		if candidate.Path == cache {
			chosen = candidate
			break
		}
	}
	if chosen.Kind != core.ActionQuarantine {
		t.Fatalf("cache action: %+v", chosen)
	}
	if _, stderr, code := f.run(t, "plan", "--plan", doc.Data.Plan.ID, "--approve", chosen.ID, "--no-jev"); code != ExitOK {
		t.Fatalf("approve: %s", stderr)
	}
	if _, stderr, code := f.run(t, "apply", "--quarantine", "--action", chosen.ID, "--confirm", "--dry-run=false"); code != ExitOK {
		t.Fatalf("quarantine: %s", stderr)
	}
	paths, err := config.ResolvePaths(config.MapLookup(f.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	var receipt core.CleanupItem
	if err := db.Read(ctx, func(tx *store.Tx) error {
		items, err := tx.PendingCleanupItems(ctx)
		if err == nil && len(items) != 1 {
			t.Fatalf("expected one receipt, got %d", len(items))
		}
		if err == nil {
			receipt = items[0]
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	unit := filepath.Join(units, "active.service")
	if err := os.WriteFile(unit, []byte("[Service]\nWorkingDirectory="+cache+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := f.run(t, "cycle"); code == ExitOK {
		t.Fatal("scheduled expiry bypassed a newly protected original path")
	}
	if _, err := os.Stat(receipt.Destination); err != nil {
		t.Fatalf("protected receipt was deleted: %v", err)
	}
	if err := os.Remove(unit); err != nil {
		t.Fatal(err)
	}
	out, stderr, code = f.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("expiry did not recover after reference removal: %s", stderr)
	}
	var cycle cycleReport
	if err := json.Unmarshal([]byte(out), &cycle); err != nil || cycle.Expiry != "checked" || cycle.ExpiryReport == "" {
		t.Fatalf("scheduled expiry lost its single structured outcome: %+v %v %q", cycle, err, out)
	}
	if _, err := os.Lstat(receipt.Destination); !os.IsNotExist(err) {
		t.Fatalf("expired receipt remains: %v", err)
	}
}

// With auto_quarantine and auto_expire, the daily cycle frees space on its
// own: a regenerable cache with no restore window is moved and deleted in
// one run, while a referenced cache and an unclassified directory stay.
func TestScheduledCycleQuarantinesAndExpiresWithoutOperator(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	cache := filepath.Join(root, "build-cache")
	inUse := filepath.Join(root, "service-cache")
	mystery := filepath.Join(root, "mystery")
	proc := filepath.Join(f.home, "empty-proc")
	units := filepath.Join(f.home, "systemd")
	for _, path := range []string{cache, inUse, mystery, proc, units} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{cache, inUse, mystery} {
		if err := os.WriteFile(filepath.Join(dir, "payload"), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(units, "live.service"), []byte("[Service]\nWorkingDirectory="+inUse+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: true\n  proc_root: "+proc+"\n  systemd_dirs:\n    - "+units+"\n  cron_paths: []\n  pm2_dumps: []\n"+
		"caches:\n  - name: build\n    path: "+cache+"\n    action: quarantine\n    retention: none\n  - name: service\n    path: "+inUse+"\n    action: quarantine\n    retention: none\n"+
		"retention:\n  delete_enabled: true\nprevention:\n  auto_quarantine: true\n  auto_expire: true\n  min_free_percent: 0\n")

	out, stderr, code := f.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("cycle: %d %s %s", code, stderr, out)
	}
	var cycle cycleReport
	if err := json.Unmarshal([]byte(out), &cycle); err != nil || cycle.Quarantine != "applied" || cycle.Expiry != "checked" {
		t.Fatalf("cycle report = %+v %v %q", cycle, err, out)
	}
	if _, err := os.Lstat(cache); !os.IsNotExist(err) {
		t.Fatalf("regenerable cache was not removed: %v", err)
	}
	for _, kept := range []string{inUse, mystery} {
		if raw, err := os.ReadFile(filepath.Join(kept, "payload")); err != nil || string(raw) != "fixture" {
			t.Fatalf("%s was touched: %q %v", kept, raw, err)
		}
	}
	paths, err := config.ResolvePaths(config.MapLookup(f.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(paths.QuarantineDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, batch := range entries {
		items, _ := filepath.Glob(filepath.Join(paths.QuarantineDir, batch.Name(), "*", "item"))
		if len(items) != 0 {
			t.Fatalf("deleted cache left quarantined objects: %v", items)
		}
	}

	// Without the opt-in the cycle stays read-only.
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: false\n"+
		"caches:\n  - name: build\n    path: "+cache+"\n    action: quarantine\n    retention: none\n"+
		"retention:\n  delete_enabled: true\nprevention:\n  auto_expire: true\n  min_free_percent: 0\n")
	out, stderr, code = f.run(t, "cycle")
	if code != ExitOK || json.Unmarshal([]byte(out), &cycle) != nil || cycle.Quarantine != "disabled" {
		t.Fatalf("cycle without auto_quarantine: %d %s %s", code, stderr, out)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("cycle without auto_quarantine moved the cache: %v", err)
	}
}
