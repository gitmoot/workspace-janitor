//go:build linux

package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recoveryFixture struct {
	*fixture
	root, cache, payload, proc, services, binary string
}

func newRecoveryFixture(t *testing.T) recoveryFixture {
	t.Helper()
	f := newFixture(t)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	r := recoveryFixture{fixture: f, root: filepath.Join(f.home, "workspace"), proc: filepath.Join(f.home, "proc"), services: filepath.Join(f.home, "services"), binary: goBinary}
	r.cache = filepath.Join(r.root, ".cache", "go-build")
	r.payload = filepath.Join(r.cache, "00", strings.Repeat("0", 64)+"-d")
	for _, path := range []string{r.proc, r.services, filepath.Dir(r.payload)} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// A valid Go-cache object pathname; the official cleaner removes obsolete
	// objects without needing a cold compiler build in each test.
	r.repopulate(t)
	return r
}

func (r recoveryFixture) repopulate(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(r.payload), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.payload, []byte(strings.Repeat("artifact", 2048)), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := filepath.Walk(r.cache, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, old, old)
	}); err != nil {
		t.Fatal(err)
	}
}

func (r recoveryFixture) policy(t *testing.T, budget int64) {
	t.Helper()
	r.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
    max_depth: 2
collectors:
  git: true
  processes: true
  services: true
  proc_root: %s
  systemd_dirs: [%s]
  cron_paths: []
  pm2_dumps: []
caches:
  - name: retired-build
    path: %s
    action: delete_candidate
    max_bytes: 1
    dedicated: true
    official_binary: %s
    recovery:
      owner: fixture-owner
      approval: fixture-retired-build-approval
      rebuild_cost: rebuild retired compiler outputs
      max_prune_bytes: 1048576
      min_idle: 1h
prevention:
  min_free_bytes: 0
  min_free_percent: 0
  targets:
    - path: %s
      target_free_bytes: 9000000000000000000
      reserve_free_bytes: 0
      recovery_margin_bytes: 1
  recovery:
    enabled: true
    max_stores: 1
    max_bytes: %d
    interval: 24h
    time_budget: 30s
`, r.root, r.proc, r.services, r.cache, r.binary, r.root, budget))
}

// Decode the public JSON shape rather than new Go types so old-head proof
// exercises behavior instead of failing to compile against absent APIs.
type recoveryCycleResult struct {
	Recovery struct {
		Stopped   string `json:"stopped"`
		Attempted int    `json:"attempted_stores"`
		Charged   uint64 `json:"budget_charged_bytes"`
		Actions   []struct {
			Error       string `json:"error"`
			RebuildCost string `json:"rebuild_cost"`
			Prune       struct {
				Status string `json:"status"`
				Before *int64 `json:"store_before_bytes"`
				After  *int64 `json:"store_after_bytes"`
			} `json:"prune"`
		} `json:"actions"`
		Skipped []struct {
			Reason string `json:"reason"`
		} `json:"skipped"`
	} `json:"recovery"`
	Capacity struct {
		Volumes []struct {
			State string `json:"state"`
			Hold  bool   `json:"admission_hold"`
		} `json:"volumes"`
	} `json:"capacity"`
}

func (r recoveryFixture) cycle(t *testing.T, wantSuccess bool) recoveryCycleResult {
	t.Helper()
	stdout, stderr, code := r.run(t, "cycle")
	if (code == ExitOK) != wantSuccess {
		t.Fatalf("cycle code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	var result recoveryCycleResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode cycle: %v: %s %s", err, stdout, stderr)
	}
	return result
}

func TestCapacityRecoveryPrunesOnlyApprovedStoreAndHonorsCooldown(t *testing.T) {
	r := newRecoveryFixture(t)
	protected := filepath.Join(r.root, "source-result")
	if err := os.WriteFile(protected, []byte("irreplaceable"), 0600); err != nil {
		t.Fatal(err)
	}
	r.policy(t, 1048576)
	result := r.cycle(t, true)
	if result.Recovery.Attempted != 1 || len(result.Recovery.Actions) != 1 {
		t.Fatalf("no bounded action: %+v", result)
	}
	action := result.Recovery.Actions[0]
	if action.Prune.Before == nil || action.Prune.After == nil || *action.Prune.After >= *action.Prune.Before || action.RebuildCost == "" {
		t.Fatalf("missing measured reclaim/cost: %+v", action)
	}
	if _, err := os.Stat(r.payload); !os.IsNotExist(err) {
		t.Fatalf("official Go cleaner retained object: %v", err)
	}
	if data, err := os.ReadFile(protected); err != nil || string(data) != "irreplaceable" {
		t.Fatalf("protected source changed: %q %v", data, err)
	}
	if len(result.Capacity.Volumes) != 1 || result.Capacity.Volumes[0].State != "no_safe_reclaim" || !result.Capacity.Volumes[0].Hold {
		t.Fatalf("shortfall released admission: %+v", result)
	}
	r.repopulate(t)
	repeat := r.cycle(t, true)
	if repeat.Recovery.Attempted != 0 {
		t.Fatalf("cooldown allowed erase/rebuild loop: %+v", repeat)
	}
	if _, err := os.Stat(r.payload); err != nil {
		t.Fatalf("rebuilt artifact removed: %v", err)
	}
	found := false
	for _, skip := range repeat.Recovery.Skipped {
		found = found || strings.Contains(skip.Reason, "cooldown")
	}
	if !found {
		t.Fatalf("cooldown not reported: %+v", repeat)
	}
}

func TestCapacityRecoveryRefusesWholeStoreOverBudget(t *testing.T) {
	r := newRecoveryFixture(t)
	r.policy(t, 1)
	result := r.cycle(t, true)
	if result.Recovery.Attempted != 0 || result.Recovery.Charged != 0 {
		t.Fatalf("over-budget store ran: %+v", result)
	}
	if _, err := os.Stat(r.payload); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, skip := range result.Recovery.Skipped {
		found = found || strings.Contains(skip.Reason, "budget")
	}
	if !found {
		t.Fatalf("no budget refusal: %+v", result)
	}
}

func TestCapacityRecoveryPreservesActiveStore(t *testing.T) {
	r := newRecoveryFixture(t)
	pid := filepath.Join(r.proc, "1234")
	if err := os.Mkdir(pid, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid, "cmdline"), []byte("compiler\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(r.cache, filepath.Join(pid, "cwd")); err != nil {
		t.Fatal(err)
	}
	r.policy(t, 1048576)
	result := r.cycle(t, true)
	if result.Recovery.Attempted != 0 {
		t.Fatalf("active store pruned: %+v", result)
	}
	if _, err := os.Stat(r.payload); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, skip := range result.Recovery.Skipped {
		found = found || strings.Contains(skip.Reason, "process")
	}
	if !found {
		t.Fatalf("active process not reported: %+v", result)
	}
}

func TestCapacityRecoveryPreservesBusyProviderOutsideCache(t *testing.T) {
	r := newRecoveryFixture(t)
	pid := filepath.Join(r.proc, "1234")
	if err := os.Mkdir(pid, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid, "comm"), []byte("compile\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(r.home, filepath.Join(pid, "cwd")); err != nil {
		t.Fatal(err)
	}
	r.policy(t, 1048576)
	result := r.cycle(t, true)
	if result.Recovery.Attempted != 0 {
		t.Fatalf("busy provider cache pruned: %+v", result)
	}
	if _, err := os.Stat(r.payload); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityRecoveryPreservesQueuedAndUnknownProducerUse(t *testing.T) {
	for _, state := range []string{"queued-job", "queued-task", "unavailable-ledger"} {
		t.Run(state, func(t *testing.T) {
			r := newRecoveryFixture(t)
			home := filepath.Join(r.home, ".gitmoot")
			if err := os.Mkdir(home, 0700); err != nil {
				t.Fatal(err)
			}
			database := filepath.Join(home, "gitmoot.db")
			if state != "unavailable-ledger" {
				db, err := sql.Open("sqlite", database)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				for _, statement := range []string{
					`CREATE TABLE jobs(id TEXT, state TEXT, payload TEXT, updated_at TEXT)`,
					`CREATE TABLE tasks(state TEXT, worktree_path TEXT)`,
					`CREATE TABLE cleanup_obligations(owner_job_id TEXT, expected_path TEXT, resource_kind TEXT, state TEXT, created_at TEXT, updated_at TEXT)`,
				} {
					if _, err := db.Exec(statement); err != nil {
						t.Fatal(err)
					}
				}
				statement := `INSERT INTO jobs VALUES('consumer','queued','{}','2026-01-01 00:00:00')`
				if state == "queued-task" {
					statement = `INSERT INTO tasks VALUES('pending','')`
				}
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			r.policy(t, 1048576)
			policy := filepath.Join(r.home, ".config", "workspace-janitor", "policy.yaml")
			file, err := os.OpenFile(policy, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := fmt.Fprintf(file, "\ngitmoot:\n  home: %s\n  database: %s\n", home, database)
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatalf("policy: %v %v", writeErr, closeErr)
			}
			result := r.cycle(t, true)
			if result.Recovery.Attempted != 0 {
				t.Fatalf("queued/unknown producer cache pruned: %+v", result)
			}
			if _, err := os.Stat(r.payload); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, skip := range result.Recovery.Skipped {
				found = found || strings.Contains(strings.ToLower(skip.Reason), "gitmoot") || strings.Contains(skip.Reason, "producer")
			}
			if !found {
				t.Fatalf("producer hold not explained: %+v", result)
			}
		})
	}
}

func TestCapacityRecoveryRecordsPartialProviderFailureWithoutRetry(t *testing.T) {
	r := newRecoveryFixture(t)
	r.binary = filepath.Join(r.home, "go")
	// A failing external process is the error boundary, not a mock success.
	if err := os.WriteFile(r.binary, []byte("#!/bin/sh\nrm -f '"+r.payload+"'\nexit 23\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r.policy(t, 1048576)
	result := r.cycle(t, false)
	if result.Recovery.Stopped != "provider_or_measurement_failure" || result.Recovery.Attempted != 1 || len(result.Recovery.Actions) != 1 || result.Recovery.Actions[0].Error == "" {
		t.Fatalf("failure missing: %+v", result)
	}
	if _, err := os.Stat(r.payload); !os.IsNotExist(err) {
		t.Fatalf("partial action not exercised: %v", err)
	}
	r.repopulate(t)
	repeat := r.cycle(t, true)
	if repeat.Recovery.Attempted != 0 {
		t.Fatalf("failed provider retried without owner approval: %+v", repeat)
	}
	if _, err := os.Stat(r.payload); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, skip := range repeat.Recovery.Skipped {
		found = found || strings.Contains(skip.Reason, "new approval")
	}
	if !found {
		t.Fatalf("uncertain failure not latched: %+v", repeat)
	}
}

func TestCapacityRecoveryStopsAtSatisfiedTarget(t *testing.T) {
	r := newRecoveryFixture(t)
	r.policy(t, 1048576)
	path := filepath.Join(r.home, ".config", "workspace-janitor", "policy.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "9000000000000000000", "1", 1))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	result := r.cycle(t, true)
	if result.Recovery.Stopped != "target_recovered" || result.Recovery.Attempted != 0 {
		t.Fatalf("satisfied target allowed unnecessary pruning: %+v", result)
	}
	if _, err := os.Stat(r.payload); err != nil {
		t.Fatal(err)
	}
}
